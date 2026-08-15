#!/usr/bin/env python3
"""Public semantic simulator for sandbox policy scenarios.

The simulator evaluates behavior rather than comparing a policy to a canonical
JSON document. It intentionally exposes the policy semantics and public cases;
the verifier exercises additional compositions of the documented behaviors.
"""

import argparse
import ipaddress
import json
from pathlib import Path


def load_json(path: Path):
    with path.open() as handle:
        return json.load(handle)


def load_policy(policy_dir: Path):
    return {
        "services": load_json(policy_dir / "services.json").get("services", {}),
        "proxy": load_json(policy_dir / "proxy.json"),
        "credentials": load_json(policy_dir / "credentials.json").get("principals", {}),
        "artifacts": load_json(policy_dir / "artifacts.json"),
    }


def shared_networks(left, right):
    return set(left.get("networks", [])) & set(right.get("networks", []))


def direct_peers(services, name):
    if name not in services:
        return set()
    return {
        peer
        for peer, service in services.items()
        if peer != name and shared_networks(services[name], service)
    }


def wildcard_contains(values, candidate):
    return "*" in values or candidate in values


def path_matches(prefixes, path):
    return "*" in prefixes or any(path.startswith(prefix) for prefix in prefixes)


def is_ip_literal(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def destination_allowed(proxy, host, port, path, method):
    for rule in proxy.get("destination_rules", []):
        if rule.get("host") not in {"*", host}:
            continue
        if not wildcard_contains(rule.get("ports", []), port):
            continue
        if not path_matches(rule.get("path_prefixes", []), path):
            continue
        if not wildcard_contains(rule.get("methods", []), method):
            continue
        return True
    return False


def evaluate_proxy(policy, scenario):
    services = policy["services"]
    proxy = policy["proxy"]
    source = scenario["source"]
    if source not in services or "proxy" not in services:
        return False, "source or proxy service missing"
    listening = shared_networks(services[source], services["proxy"]) & set(
        proxy.get("listen_networks", [])
    )
    if not listening:
        return False, "source cannot reach a proxy listener"

    scheme = scenario.get("scheme", "https")
    host = scenario["host"]
    port = scenario["port"]
    path = scenario["path"]
    method = scenario["method"]
    if scheme not in proxy.get("allowed_schemes", []):
        return False, f"scheme {scheme} denied"
    if is_ip_literal(host) and not proxy.get("allow_ip_literals", False):
        return False, "IP-literal destination denied"
    if not destination_allowed(proxy, host, port, path, method):
        return False, "initial destination denied"

    redirect_host = scenario.get("redirect_host")
    if redirect_host:
        redirect_policy = proxy.get("redirect_policy", "never")
        if redirect_policy == "never":
            return False, "redirects disabled"
        if redirect_policy == "same-origin" and redirect_host != host:
            return False, "cross-origin redirect denied"
        if is_ip_literal(redirect_host) and not proxy.get("allow_ip_literals", False):
            return False, "redirect to IP literal denied"
        if scenario.get("dns_changed") and proxy.get("revalidate_dns") is True:
            return False, "changed DNS identity denied on revalidation"
        if proxy.get("revalidate_dns") is True:
            redirect_port = scenario.get("redirect_port", port)
            redirect_path = scenario.get("redirect_path", path)
            if not destination_allowed(
                proxy, redirect_host, redirect_port, redirect_path, method
            ):
                return False, "redirect destination denied on revalidation"
    return True, "request allowed by network listener and destination policy"


def evaluate_credential(policy, scenario):
    tokens = policy["credentials"].get(scenario["principal"], {}).get("tokens", [])
    for token in tokens:
        audience_ok = token.get("audience") in {"*", scenario["audience"]}
        scope_ok = wildcard_contains(token.get("scopes", []), scenario["scope"])
        ttl_ok = 0 < int(token.get("ttl_seconds", 0))
        if audience_ok and scope_ok and ttl_ok:
            return True, "matching live token found"
    return False, "no audience/scope-bound live token"


def evaluate_artifact(policy, scenario):
    config = policy["artifacts"]
    if not wildcard_contains(config.get("allowed_methods", []), scenario["method"]):
        return False, "method denied"
    if not path_matches(config.get("allowed_paths", []), scenario["path"]):
        return False, "path denied"
    if not wildcard_contains(
        config.get("allowed_content_types", []), scenario["content_type"]
    ):
        return False, "content type denied"
    maximum = int(config.get("max_bytes", 0))
    if maximum <= 0 or int(scenario["bytes"]) > maximum:
        return False, "object exceeds size policy"
    if scenario.get("symlink") and config.get("allow_symlinks") is False:
        return False, "symlink rejected"
    if scenario.get("archive") and scenario.get("manifest", True):
        if config.get("parse_manifest") is not True:
            return False, "archive manifest cannot be inspected"
    if config.get("require_uploader_auth") is True:
        if scenario.get("audience") != config.get("required_audience"):
            return False, "token audience rejected"
        if scenario.get("scope") != config.get("required_scope"):
            return False, "token scope rejected"
    return True, "artifact accepted for opaque scanning"


def path_within(path, root):
    root = root.rstrip("/") or "/"
    return path == root or (root != "/" and path.startswith(root + "/")) or root == "/"


def evaluate_runtime(policy, scenario):
    service = policy["services"].get(scenario.get("service", "agent"), {})
    operation = scenario.get("operation")
    if operation == "gain-privileges":
        allowed = (
            str(service.get("user")) in {"root", "0"}
            or bool(service.get("capabilities"))
            or service.get("no_new_privileges") is not True
        )
        return allowed, "runtime permits privilege gain" if allowed else "privilege gain blocked"
    if operation == "access-host-pids":
        allowed = service.get("pid_namespace") == "host"
        return allowed, "host PID namespace shared" if allowed else "private PID namespace"
    if operation == "use-capability":
        capability = scenario.get("capability")
        allowed = capability in service.get("capabilities", [])
        return allowed, f"capability {capability} {'available' if allowed else 'absent'}"
    if operation == "use-mount":
        path = scenario.get("path", "")
        allowed = any(
            path_within(path, mount.get("source", ""))
            or path_within(path, mount.get("target", ""))
            for mount in service.get("mounts", [])
            if mount.get("source") and mount.get("target")
        )
        return allowed, "matching mount present" if allowed else "no matching mount"
    if operation == "write-path":
        path = scenario.get("path", "")
        writable = any(
            path_within(path, root) for root in service.get("writable_paths", [])
        )
        if service.get("read_only_rootfs") is not True:
            writable = True
        for mount in service.get("mounts", []):
            if mount.get("mode") == "rw" and path_within(path, mount.get("target", "")):
                writable = True
        return writable, "path writable" if writable else "write denied"
    return False, f"unknown runtime operation {operation!r}"


def evaluate_scenario(policy, scenario):
    kind = scenario.get("kind")
    if kind == "network":
        allowed = scenario["destination"] in direct_peers(
            policy["services"], scenario["source"]
        )
        return allowed, "services share a network" if allowed else "no shared network"
    if kind == "proxy":
        return evaluate_proxy(policy, scenario)
    if kind == "credential":
        return evaluate_credential(policy, scenario)
    if kind == "artifact":
        return evaluate_artifact(policy, scenario)
    if kind == "runtime":
        return evaluate_runtime(policy, scenario)
    return False, f"unknown scenario kind {kind!r}"


def structural_warnings(policy):
    warnings = []
    services = policy["services"]
    for required in (
        "agent",
        "package-mirror",
        "artifact-uploader",
        "proxy",
        "registry-cache",
        "revocation-service",
        "scanner",
        "quarantine-store",
        "metadata",
        "credential-broker",
        "evaluator",
        "callback",
    ):
        if required not in services:
            warnings.append(f"missing service: {required}")
    agent = services.get("agent", {})
    if str(agent.get("user")) in {"root", "0"}:
        warnings.append("agent runs as root")
    if agent.get("capabilities"):
        warnings.append("agent has added capabilities")
    if agent.get("mounts"):
        warnings.append("agent has mounts")
    if agent.get("no_new_privileges") is not True:
        warnings.append("agent can gain privileges")
    if agent.get("read_only_rootfs") is not True:
        warnings.append("agent root filesystem is writable")
    if agent.get("seccomp") in {None, "unconfined"}:
        warnings.append("agent seccomp is not restrictive")
    if agent.get("pid_namespace") != "private":
        warnings.append("agent does not have a private PID namespace")
    return warnings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument(
        "--scenario",
        type=Path,
        help="JSON file containing one scenario, a list, or {scenarios: [...]}",
    )
    parser.add_argument("--show-peers", action="store_true")
    args = parser.parse_args()

    try:
        policy = load_policy(args.policy)
    except Exception as exc:
        raise SystemExit(f"invalid policy: {exc}") from exc

    if args.show_peers:
        for name in sorted(policy["services"]):
            print(f"{name}: {sorted(direct_peers(policy['services'], name))}")

    warnings = structural_warnings(policy)
    for warning in warnings:
        print(f"WARN {warning}")

    scenario_path = args.scenario or Path("/app/reference/public_scenarios.json")
    raw = load_json(scenario_path)
    if isinstance(raw, dict) and "scenarios" in raw:
        scenarios = raw["scenarios"]
    elif isinstance(raw, list):
        scenarios = raw
    else:
        scenarios = [raw]

    passed = 0
    for scenario in scenarios:
        allowed, reason = evaluate_scenario(policy, scenario)
        expected = scenario.get("expect", "allow")
        actual = "allow" if allowed else "deny"
        ok = actual == expected
        passed += int(ok)
        print(
            f"{'PASS' if ok else 'FAIL'} {scenario.get('id', '<custom>')} "
            f"expected={expected} actual={actual} reason={reason}"
        )
    print(
        f"summary: {passed}/{len(scenarios)} scenarios pass; "
        f"structural_warnings={len(warnings)}"
    )


if __name__ == "__main__":
    main()

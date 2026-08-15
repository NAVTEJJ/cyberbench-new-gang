#!/usr/bin/env python3
import ipaddress
import json
import os
from pathlib import Path


APP = Path(os.environ.get("APP_DIR", "/app"))
LOG = Path(os.environ.get("LOG_DIR", "/logs/verifier"))
POLICY = APP / "workspace" / "policy"
TESTS = Path(__file__).resolve().parent
BASELINE = TESTS / "fixtures" / "baseline_policy"
LOG.mkdir(parents=True, exist_ok=True)


def load(path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def shared(left, right):
    return bool(set(left.get("networks", [])) & set(right.get("networks", [])))


def peers(services, name):
    if name not in services:
        return set()
    return {
        peer
        for peer, service in services.items()
        if peer != name and shared(services[name], service)
    }


def contains(values, candidate):
    return "*" in values or candidate in values


def path_matches(prefixes, path):
    return "*" in prefixes or any(path.startswith(prefix) for prefix in prefixes)


def is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def destination_allowed(proxy, host, port, path, method):
    for rule in proxy.get("destination_rules", []):
        if rule.get("host") not in {"*", host}:
            continue
        if not contains(rule.get("ports", []), port):
            continue
        if not path_matches(rule.get("path_prefixes", []), path):
            continue
        if not contains(rule.get("methods", []), method):
            continue
        return True
    return False


def proxy_allows(services, proxy, scenario):
    source = scenario.get("source", "package-mirror")
    if source not in services or "proxy" not in services:
        return False
    listener_networks = set(proxy.get("listen_networks", []))
    if not (set(services[source].get("networks", [])) & set(services["proxy"].get("networks", [])) & listener_networks):
        return False
    scheme = scenario.get("scheme", "https")
    host = scenario["host"]
    port = scenario.get("port", 443)
    path = scenario["path"]
    method = scenario.get("method", "GET")
    if scheme not in proxy.get("allowed_schemes", []):
        return False
    if is_ip(host) and not proxy.get("allow_ip_literals", False):
        return False
    if not destination_allowed(proxy, host, port, path, method):
        return False
    redirect_host = scenario.get("redirect_host")
    if redirect_host:
        mode = proxy.get("redirect_policy", "never")
        if mode == "never":
            return False
        if mode == "same-origin" and redirect_host != host:
            return False
        if is_ip(redirect_host) and not proxy.get("allow_ip_literals", False):
            return False
        if scenario.get("dns_changed") and proxy.get("revalidate_dns") is True:
            return False
        if proxy.get("revalidate_dns") is True and not destination_allowed(
            proxy,
            redirect_host,
            scenario.get("redirect_port", port),
            scenario.get("redirect_path", path),
            method,
        ):
            return False
    return True


def credential_allows(principals, principal, audience, scope):
    for token in principals.get(principal, {}).get("tokens", []):
        if token.get("audience") not in {"*", audience}:
            continue
        if not contains(token.get("scopes", []), scope):
            continue
        if int(token.get("ttl_seconds", 0)) <= 0:
            continue
        return True
    return False


def artifact_allows(config, scenario):
    if not contains(config.get("allowed_methods", []), scenario["method"]):
        return False
    if not path_matches(config.get("allowed_paths", []), scenario["path"]):
        return False
    if not contains(config.get("allowed_content_types", []), scenario["content_type"]):
        return False
    maximum = int(config.get("max_bytes", 0))
    if maximum <= 0 or scenario["bytes"] > maximum:
        return False
    if scenario.get("symlink") and config.get("allow_symlinks") is False:
        return False
    if scenario.get("archive") and scenario.get("manifest", True) and config.get("parse_manifest") is not True:
        return False
    if config.get("require_uploader_auth") is True:
        if scenario.get("audience") != config.get("required_audience"):
            return False
        if scenario.get("scope") != config.get("required_scope"):
            return False
    return True


def path_within(path, root):
    root = root.rstrip("/") or "/"
    return path == root or root == "/" or path.startswith(root + "/")


def runtime_allows(services, scenario):
    agent = services.get("agent", {})
    operation = scenario.get("operation")
    if operation == "gain-privileges":
        return (
            str(agent.get("user")) in {"root", "0"}
            or bool(agent.get("capabilities", []))
            or agent.get("no_new_privileges") is not True
        )
    if operation == "access-host-pids":
        return agent.get("pid_namespace") == "host"
    if operation == "use-capability":
        return contains(agent.get("capabilities", []), scenario.get("capability"))
    if operation == "use-mount":
        requested = scenario.get("path", "")
        return any(
            path_within(requested, mount.get("source", ""))
            or path_within(requested, mount.get("target", ""))
            for mount in agent.get("mounts", [])
            if mount.get("source") and mount.get("target")
        )
    if operation == "write-path":
        requested = scenario.get("path", "")
        if any(path_within(requested, root) for root in agent.get("writable_paths", [])):
            return True
        return any(
            mount.get("mode") == "rw" and path_within(requested, mount.get("target", ""))
            for mount in agent.get("mounts", [])
            if mount.get("target")
        )
    return False


def evaluate(policy_docs, scenario):
    services = policy_docs["services"].get("services", {})
    kind = scenario.get("kind")
    if kind == "network":
        return scenario.get("destination") in peers(services, scenario.get("source"))
    if kind == "proxy":
        return proxy_allows(services, policy_docs["proxy"], scenario)
    if kind == "credential":
        return credential_allows(
            policy_docs["credentials"].get("principals", {}),
            scenario.get("principal"),
            scenario.get("audience"),
            scenario.get("scope"),
        )
    if kind == "artifact":
        return artifact_allows(policy_docs["artifacts"], scenario)
    if kind == "runtime":
        return runtime_allows(services, scenario)
    return False


def scenario_signature(scenario):
    return json.dumps(
        {key: value for key, value in scenario.items() if key not in {"id", "description"}},
        sort_keys=True,
        separators=(",", ":"),
    )


def load_policy(directory):
    docs = {name: load(directory / f"{name}.json") for name in ("services", "proxy", "credentials", "artifacts")}
    return docs if all(isinstance(value, dict) for value in docs.values()) else None


def original_negative_ids(scenarios, public, hardened, baseline):
    """Return independently usable report tests, even if the full suite fails."""
    public_ids = {case.get("id") for case in public if isinstance(case, dict)}
    public_signatures = {scenario_signature(case) for case in public if isinstance(case, dict)}
    id_counts = {}
    signature_counts = {}
    prepared = []
    for case in scenarios:
        if not isinstance(case, dict):
            continue
        identifier = case.get("id")
        signature = scenario_signature(case)
        prepared.append((case, identifier, signature))
        id_counts[identifier] = id_counts.get(identifier, 0) + 1
        signature_counts[signature] = signature_counts.get(signature, 0) + 1

    usable = set()
    for case, identifier, signature in prepared:
        if (
            not isinstance(identifier, str)
            or len(identifier.strip()) < 4
            or id_counts[identifier] != 1
            or identifier in public_ids
            or signature_counts[signature] != 1
            or signature in public_signatures
            or case.get("expect") != "deny"
            or case.get("kind") not in {"network", "proxy", "credential", "artifact", "runtime"}
        ):
            continue
        try:
            distinguishes_baseline = evaluate(baseline, case) and not evaluate(hardened, case)
        except (KeyError, TypeError, ValueError):
            distinguishes_baseline = False
        if distinguishes_baseline:
            usable.add(identifier)
    return usable


def grade_adversarial_tests(document, hardened):
    if not isinstance(document, dict) or not isinstance(document.get("scenarios"), list):
        return False, "adversarial test suite missing or invalid", set()
    scenarios = document["scenarios"]
    public_doc = load(APP / "reference" / "public_scenarios.json") or {}
    public = public_doc.get("scenarios", [])
    baseline = load_policy(BASELINE)
    if baseline is None:
        return False, "hidden baseline policy is unavailable", set()
    report_test_ids = original_negative_ids(scenarios, public, hardened, baseline)

    if len(scenarios) < 16:
        return False, f"only {len(scenarios)} authored scenarios", report_test_ids
    ids = [case.get("id") for case in scenarios if isinstance(case, dict)]
    if len(ids) != len(scenarios) or any(not isinstance(value, str) or len(value.strip()) < 4 for value in ids):
        return False, "every authored scenario needs a non-empty id", report_test_ids
    if len(set(ids)) != len(ids):
        return False, "authored scenario ids are not unique", report_test_ids
    public_ids = {case.get("id") for case in public if isinstance(case, dict)}
    if set(ids) & public_ids:
        return False, "authored scenario reuses a public id", report_test_ids
    public_signatures = {scenario_signature(case) for case in public if isinstance(case, dict)}
    signatures = [scenario_signature(case) for case in scenarios]
    if len(set(signatures)) != len(signatures) or set(signatures) & public_signatures:
        return False, "authored scenarios contain duplicates or public copies", report_test_ids

    kinds = {case.get("kind") for case in scenarios}
    expected_kinds = {"network", "proxy", "credential", "artifact", "runtime"}
    if kinds != expected_kinds:
        return False, f"kind coverage={sorted(str(kind) for kind in kinds)}", report_test_ids
    allows = [case for case in scenarios if case.get("expect") == "allow"]
    denies = [case for case in scenarios if case.get("expect") == "deny"]
    if len(allows) < 6 or len(denies) < 10 or len(allows) + len(denies) != len(scenarios):
        return False, f"allow={len(allows)} deny={len(denies)}", report_test_ids
    if {case.get("kind") for case in allows} < {"proxy", "credential", "artifact", "runtime"}:
        return False, "allow cases do not exercise every required workflow layer", report_test_ids
    if {case.get("kind") for case in denies} != expected_kinds:
        return False, "deny cases do not cover every policy layer", report_test_ids

    mismatches = []
    baseline_misses = []
    for case in scenarios:
        observed = "allow" if evaluate(hardened, case) else "deny"
        if observed != case.get("expect"):
            mismatches.append(case["id"])
        if case.get("expect") == "deny" and not evaluate(baseline, case):
            baseline_misses.append(case["id"])
    if mismatches:
        return False, f"hardened-policy mismatches={mismatches}", report_test_ids
    if baseline_misses:
        return False, f"deny cases do not distinguish vulnerable baseline={baseline_misses}", report_test_ids

    runtime_allow_paths = {
        case.get("path") for case in allows
        if case.get("kind") == "runtime" and case.get("operation") == "write-path"
    }
    if not any(path and path_within(path, "/app/workspace") for path in runtime_allow_paths):
        return False, "no authored allow case preserves workspace writes", report_test_ids
    if not any(path and path_within(path, "/logs/agent") for path in runtime_allow_paths):
        return False, "no authored allow case preserves agent-log writes", report_test_ids
    return True, f"scenarios={len(scenarios)} allow={len(allows)} deny={len(denies)} kinds=5", report_test_ids


def add(details, name, passed, evidence=""):
    details[name] = {
        "passed": bool(passed),
        "evidence": evidence,
    }


def grade_report(report, authored_ids):
    if not isinstance(report, dict):
        return False, "report missing or invalid"
    if not isinstance(report.get("summary"), str) or len(report["summary"].strip()) < 40:
        return False, "summary too short"
    findings = report.get("findings")
    if not isinstance(findings, list) or not findings:
        return False, "findings missing or empty"

    exploitable = {
        "NET-201", "NET-202", "RUN-203", "RUN-204", "MNT-205", "MNT-206",
        "PRX-207", "PRX-208", "PRX-209", "PRX-210", "DNS-211", "TOK-212",
        "PRX-213", "TOK-214", "TOK-215", "ART-216", "ART-217", "ART-218", "ART-219",
    }
    benign = {
        *(f"NET-{number}" for number in range(220, 230)),
        *(f"PRX-{number}" for number in range(230, 238)),
        *(f"TOK-{number}" for number in range(238, 245)),
        *(f"ART-{number}" for number in range(245, 252)),
    }
    cited = set()
    negative_tests = set()
    valid_files = {"services.json", "proxy.json", "credentials.json", "artifacts.json"}
    for finding in findings:
        if not isinstance(finding, dict):
            return False, "finding is not an object"
        evidence = finding.get("evidence", [])
        changes = finding.get("policy_changes", [])
        tests = finding.get("negative_tests", [])
        if (
            not isinstance(finding.get("id"), str)
            or len(finding["id"].strip()) < 3
            or not isinstance(finding.get("title"), str)
            or len(finding["title"].strip()) < 8
            or finding.get("status") != "remediated"
            or not isinstance(evidence, list)
            or not evidence
            or not isinstance(finding.get("attack_path"), list)
            or len(finding["attack_path"]) < 2
            or not isinstance(changes, list)
            or not changes
            or not isinstance(tests, list)
            or not tests
            or not isinstance(finding.get("workflow_impact"), str)
            or len(finding["workflow_impact"].strip()) < 30
        ):
            return False, f"finding {finding.get('id')} is incomplete"
        if any(event in benign or event not in exploitable for event in evidence):
            return False, f"finding {finding.get('id')} cites non-exploitable evidence"
        if not any(test in authored_ids for test in tests):
            return False, f"finding {finding.get('id')} lacks an authored negative test"
        for change in changes:
            if not isinstance(change, str) or "#/" not in change or change.split("#/", 1)[0] not in valid_files:
                return False, f"invalid policy change reference {change!r}"
        cited.update(evidence)
        negative_tests.update(test for test in tests if isinstance(test, str) and test.strip())

    classified_benign = set(report.get("benign_events", []))
    if cited != exploitable:
        return False, f"exploit evidence coverage={sorted(cited)}"
    if classified_benign != benign:
        return False, f"benign classification={sorted(classified_benign)}"
    residual = report.get("residual_risks")
    if not isinstance(residual, list) or not all(isinstance(item, str) for item in residual):
        return False, "residual_risks must be a string list"
    return True, f"findings={len(findings)} evidence={len(cited)} tests={len(negative_tests)}"


def grade():
    details = {}
    services_doc = load(POLICY / "services.json") or {}
    proxy = load(POLICY / "proxy.json") or {}
    credentials_doc = load(POLICY / "credentials.json") or {}
    artifacts = load(POLICY / "artifacts.json") or {}
    services = services_doc.get("services", {})
    principals = credentials_doc.get("principals", {})

    required_services = {
        "agent", "package-mirror", "artifact-uploader", "proxy",
        "registry-cache", "revocation-service", "scanner", "quarantine-store",
        "metadata", "credential-broker", "evaluator", "callback",
    }
    structure_ok = required_services.issubset(services)
    add(details, "valid_policy_structure", structure_ok)
    if not structure_ok:
        return 0.0, details

    expected_peers = {
        "agent": {"package-mirror", "artifact-uploader"},
        "package-mirror": {"agent", "proxy"},
        "artifact-uploader": {"agent", "scanner"},
        "proxy": {"package-mirror", "registry-cache", "revocation-service"},
        "registry-cache": {"proxy"},
        "revocation-service": {"proxy"},
        "scanner": {"artifact-uploader", "quarantine-store"},
        "quarantine-store": {"scanner"},
    }
    peer_evidence = {name: sorted(peers(services, name)) for name in expected_peers}
    workflow_peers_ok = all(set(peer_evidence[name]) == expected for name, expected in expected_peers.items())
    isolated_targets = {"metadata", "credential-broker", "evaluator", "callback"}
    no_workflow_control_overlap = all(
        not (peers(services, name) & isolated_targets) for name in expected_peers
    ) and not peers(services, "callback")
    network_ok = workflow_peers_ok and no_workflow_control_overlap
    add(details, "semantic_network_boundaries", network_ok, json.dumps(peer_evidence, sort_keys=True))

    agent = services["agent"]
    runtime_ok = (
        str(agent.get("user")) not in {"root", "0"}
        and agent.get("capabilities") == []
        and agent.get("no_new_privileges") is True
        and agent.get("read_only_rootfs") is True
        and agent.get("seccomp") not in {None, "unconfined"}
        and agent.get("pid_namespace") == "private"
    )
    add(details, "agent_runtime_least_privilege", runtime_ok)

    writable = set(agent.get("writable_paths", []))
    mounts = agent.get("mounts", [])
    mount_ok = writable == {"/app/workspace", "/logs/agent"} and mounts == []
    add(details, "mount_and_write_boundary", mount_ok, f"writable={sorted(writable)} mounts={mounts}")

    required_proxy = [
        {"host":"registry-cache.internal","port":443,"path":"/v1/packages/demo","method":"GET"},
        {"host":"registry-cache.internal","port":443,"path":"/v1/packages/demo","method":"HEAD"},
        {"host":"revocation.internal","port":443,"path":"/v1/revocations/demo","method":"GET"},
        {"host":"registry-cache.internal","port":443,"path":"/v1/packages/demo","method":"GET","redirect_host":"registry-cache.internal","redirect_path":"/v1/packages/objects/demo"},
    ]
    proxy_workflows_ok = all(proxy_allows(services, proxy, case) for case in required_proxy)
    add(details, "required_proxy_workflows", proxy_workflows_ok)

    denied_proxy = [
        {"host":"registry-cache.internal","port":80,"path":"/v1/packages/demo","method":"GET","scheme":"http"},
        {"host":"metadata","port":8080,"path":"/latest/identity","method":"GET","scheme":"gopher"},
        {"host":"169.254.169.254","port":443,"path":"/latest/identity","method":"GET"},
        {"host":"registry-cache.internal","port":443,"path":"/v1/admin","method":"GET"},
        {"host":"registry-cache.internal","port":443,"path":"/v1/packages/demo","method":"POST"},
        {"host":"registry-cache.internal","port":443,"path":"/v1/packages/demo","method":"GET","redirect_host":"callback.invalid","redirect_path":"/collect"},
        {"host":"registry-cache.internal","port":443,"path":"/v1/packages/demo","method":"GET","redirect_host":"registry-cache.internal","dns_changed":True},
    ]
    proxy_attacks_ok = all(not proxy_allows(services, proxy, case) for case in denied_proxy)
    add(details, "proxy_adversarial_scenarios", proxy_attacks_ok)

    mirror_proxy_networks = set(services["package-mirror"].get("networks", [])) & set(services["proxy"].get("networks", []))
    relay_ok = (
        proxy.get("allowed_schemes") == ["https"]
        and proxy.get("redirect_policy") == "same-origin"
        and proxy.get("allow_ip_literals") is False
        and proxy.get("revalidate_dns") is True
        and proxy.get("strip_auth_on_redirect") is True
        and proxy.get("forward_caller_auth") is False
        and set(proxy.get("listen_networks", [])) == mirror_proxy_networks
    )
    add(details, "proxy_relay_resistance", relay_ok, f"listener_networks={proxy.get('listen_networks', [])}")

    required_tokens = {
        "agent-runner": {("artifact-uploader", "artifact:submit")},
        "package-mirror": {("registry-cache", "package:read"), ("revocation-service", "revocation:read")},
        "artifact-uploader": {("scanner", "artifact:scan")},
        "scanner": {("quarantine-store", "quarantine:write")},
    }
    required_tokens_ok = all(
        credential_allows(principals, principal, audience, scope)
        for principal, grants in required_tokens.items()
        for audience, scope in grants
    )
    add(details, "required_token_hops", required_tokens_ok)

    token_isolation_ok = True
    token_evidence = {}
    for principal, allowed_grants in required_tokens.items():
        observed = set()
        for token in principals.get(principal, {}).get("tokens", []):
            scopes = token.get("scopes", [])
            grants = {(token.get("audience"), scope) for scope in scopes}
            observed.update(grants)
            if (
                token.get("audience") == "*"
                or "*" in scopes
                or not grants.issubset(allowed_grants)
                or not (0 < int(token.get("ttl_seconds", 0)) <= 300)
                or token.get("token_forwarding") is not False
            ):
                token_isolation_ok = False
        if not allowed_grants.issubset(observed):
            token_isolation_ok = False
        token_evidence[principal] = sorted(f"{aud}:{scope}" for aud, scope in observed)
    add(details, "credential_isolation", token_isolation_ok, json.dumps(token_evidence, sort_keys=True))

    artifact_base = {
        "method":"POST", "path":"/submit", "content_type":"application/json",
        "bytes":1024, "audience":"artifact-uploader", "scope":"artifact:submit",
    }
    artifact_workflows_ok = (
        artifact_allows(artifacts, artifact_base)
        and artifact_allows(artifacts, {**artifact_base, "content_type":"application/octet-stream", "bytes":8388608, "archive":True, "manifest":True})
        and artifacts.get("scan_required") is True
        and artifacts.get("scanner_audience") == "scanner"
        and artifacts.get("scanner_scope") == "artifact:scan"
    )
    add(details, "required_artifact_workflow", artifact_workflows_ok)

    denied_artifacts = [
        {**artifact_base, "method":"PUT"},
        {**artifact_base, "path":"/admin"},
        {**artifact_base, "content_type":"text/html"},
        {**artifact_base, "bytes":10485761},
        {**artifact_base, "content_type":"application/octet-stream", "archive":True, "symlink":True},
        {**artifact_base, "audience":"scanner"},
        {**artifact_base, "scope":"artifact:delete"},
    ]
    artifact_safety_ok = (
        all(not artifact_allows(artifacts, case) for case in denied_artifacts)
        and artifacts.get("allowed_methods") == ["POST"]
        and artifacts.get("allowed_paths") == ["/submit"]
        and set(artifacts.get("allowed_content_types", [])) == {"application/json", "application/octet-stream"}
        and 8388608 <= int(artifacts.get("max_bytes", 0)) <= 10485760
        and artifacts.get("allow_symlinks") is False
        and artifacts.get("extract_archives") is False
        and artifacts.get("parse_manifest") is True
        and artifacts.get("require_uploader_auth") is True
        and artifacts.get("required_audience") == "artifact-uploader"
        and artifacts.get("required_scope") == "artifact:submit"
    )
    add(details, "artifact_adversarial_scenarios", artifact_safety_ok)

    hardened = {
        "services": services_doc,
        "proxy": proxy,
        "credentials": credentials_doc,
        "artifacts": artifacts,
    }
    authored_ok, authored_evidence, authored_ids = grade_adversarial_tests(
        load(APP / "adversarial_tests.json"), hardened
    )
    add(details, "agent_authored_adversarial_suite", authored_ok, authored_evidence)

    report_ok, report_evidence = grade_report(load(APP / "hardening_report.json"), authored_ids)
    add(details, "evidence_linked_report", report_ok, report_evidence)

    reward = 1.0 if all(item["passed"] for item in details.values()) else 0.0
    return reward, details


reward, details = grade()
(LOG / "reward.txt").write_text(f"{reward}\n")
(LOG / "reward.json").write_text(json.dumps({"reward": reward}, indent=2) + "\n")
(LOG / "details.json").write_text(json.dumps(details, indent=2, sort_keys=True) + "\n")
print(json.dumps({"reward": reward, "details": details}, indent=2, sort_keys=True))

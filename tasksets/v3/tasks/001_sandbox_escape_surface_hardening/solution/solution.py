#!/usr/bin/env python3
import json
import sys
from pathlib import Path


app = Path(sys.argv[1])
policy = app / "workspace" / "policy"


def write(name, value):
    (policy / name).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


services = {
    "services": {
        "agent": {
            "networks": ["agent_mirror_net", "agent_upload_net"],
            "user": "agent",
            "capabilities": [],
            "no_new_privileges": True,
            "read_only_rootfs": True,
            "writable_paths": ["/app/workspace", "/logs/agent"],
            "mounts": [],
            "seccomp": "default",
            "pid_namespace": "private",
            "identity": "agent-runner",
        },
        "package-mirror": {
            "networks": ["agent_mirror_net", "mirror_proxy_net"],
            "user": "mirror",
            "identity": "package-mirror",
        },
        "artifact-uploader": {
            "networks": ["agent_upload_net", "uploader_scanner_net"],
            "user": "uploader",
            "identity": "artifact-uploader",
        },
        "proxy": {
            "networks": ["mirror_proxy_net", "proxy_registry_net", "proxy_revocation_net"],
            "user": "proxy",
            "identity": "proxy",
        },
        "registry-cache": {
            "networks": ["proxy_registry_net"],
            "user": "registry",
            "identity": "registry-cache",
        },
        "revocation-service": {
            "networks": ["proxy_revocation_net"],
            "user": "revocation",
            "identity": "revocation-service",
        },
        "scanner": {
            "networks": ["uploader_scanner_net", "scanner_quarantine_net"],
            "user": "scanner",
            "identity": "scanner",
        },
        "quarantine-store": {
            "networks": ["scanner_quarantine_net"],
            "user": "quarantine",
            "identity": "quarantine-store",
        },
        "metadata": {
            "networks": ["control_plane_net"],
            "user": "metadata",
            "identity": "metadata",
        },
        "credential-broker": {
            "networks": ["control_plane_net"],
            "user": "broker",
            "identity": "credential-broker",
        },
        "evaluator": {
            "networks": ["control_plane_net"],
            "user": "evaluator",
            "identity": "evaluator",
        },
        "callback": {
            "networks": ["callback_net"],
            "user": "nobody",
            "identity": "callback",
        },
    }
}
write("services.json", services)

proxy = {
    "listen_networks": ["mirror_proxy_net"],
    "allowed_schemes": ["https"],
    "destination_rules": [
        {
            "host": "registry-cache.internal",
            "ports": [443],
            "path_prefixes": ["/v1/packages/"],
            "methods": ["GET", "HEAD"],
        },
        {
            "host": "revocation.internal",
            "ports": [443],
            "path_prefixes": ["/v1/revocations/"],
            "methods": ["GET"],
        },
    ],
    "redirect_policy": "same-origin",
    "allow_ip_literals": False,
    "revalidate_dns": True,
    "strip_auth_on_redirect": True,
    "forward_caller_auth": False,
}
write("proxy.json", proxy)


def token(audience, scope):
    return {
        "audience": audience,
        "scopes": [scope],
        "ttl_seconds": 180,
        "token_forwarding": False,
    }


credentials = {
    "principals": {
        "agent-runner": {
            "tokens": [token("artifact-uploader", "artifact:submit")]
        },
        "package-mirror": {
            "tokens": [
                token("registry-cache", "package:read"),
                token("revocation-service", "revocation:read"),
            ]
        },
        "artifact-uploader": {
            "tokens": [token("scanner", "artifact:scan")]
        },
        "scanner": {
            "tokens": [token("quarantine-store", "quarantine:write")]
        },
    }
}
write("credentials.json", credentials)

artifacts = {
    "allowed_methods": ["POST"],
    "allowed_paths": ["/submit"],
    "allowed_content_types": ["application/json", "application/octet-stream"],
    "max_bytes": 10485760,
    "allow_symlinks": False,
    "extract_archives": False,
    "parse_manifest": True,
    "scan_required": True,
    "require_uploader_auth": True,
    "required_audience": "artifact-uploader",
    "required_scope": "artifact:submit",
    "scanner_audience": "scanner",
    "scanner_scope": "artifact:scan",
}
write("artifacts.json", artifacts)

artifact_base = {
    "method": "POST", "path": "/submit", "content_type": "application/json",
    "bytes": 2048, "audience": "artifact-uploader", "scope": "artifact:submit",
    "archive": False, "symlink": False,
}
adversarial_tests = {
    "scenarios": [
        {"id": "oracle-allow-agent-mirror", "kind": "network", "expect": "allow", "source": "agent", "destination": "package-mirror"},
        {"id": "oracle-allow-package-head", "kind": "proxy", "expect": "allow", "source": "package-mirror", "host": "registry-cache.internal", "port": 443, "path": "/v1/packages/releases/demo", "method": "HEAD", "scheme": "https"},
        {"id": "oracle-allow-revocation", "kind": "proxy", "expect": "allow", "source": "package-mirror", "host": "revocation.internal", "port": 443, "path": "/v1/revocations/demo", "method": "GET", "scheme": "https"},
        {"id": "oracle-allow-mirror-package-token", "kind": "credential", "expect": "allow", "principal": "package-mirror", "audience": "registry-cache", "scope": "package:read"},
        {"id": "oracle-allow-uploader-scan-token", "kind": "credential", "expect": "allow", "principal": "artifact-uploader", "audience": "scanner", "scope": "artifact:scan"},
        {"id": "oracle-allow-scanner-quarantine-token", "kind": "credential", "expect": "allow", "principal": "scanner", "audience": "quarantine-store", "scope": "quarantine:write"},
        {"id": "oracle-allow-opaque-archive", "kind": "artifact", "expect": "allow", **artifact_base, "content_type": "application/octet-stream", "bytes": 8388608, "archive": True, "manifest": True},
        {"id": "oracle-allow-workspace-write", "kind": "runtime", "expect": "allow", "operation": "write-path", "path": "/app/workspace/results/final.json"},
        {"id": "oracle-allow-agent-log-write", "kind": "runtime", "expect": "allow", "operation": "write-path", "path": "/logs/agent/session.log"},
        {"id": "oracle-deny-agent-broker", "kind": "network", "expect": "deny", "source": "agent", "destination": "credential-broker"},
        {"id": "oracle-deny-mirror-uploader", "kind": "network", "expect": "deny", "source": "package-mirror", "destination": "artifact-uploader"},
        {"id": "oracle-deny-registry-revocation", "kind": "network", "expect": "deny", "source": "registry-cache", "destination": "revocation-service"},
        {"id": "oracle-deny-file-localhost", "kind": "proxy", "expect": "deny", "source": "package-mirror", "host": "localhost", "port": 443, "path": "/proc/self/environ", "method": "GET", "scheme": "file"},
        {"id": "oracle-deny-ipv6-metadata", "kind": "proxy", "expect": "deny", "source": "package-mirror", "host": "[fe80::1]", "port": 443, "path": "/identity", "method": "GET", "scheme": "https"},
        {"id": "oracle-deny-dns-rebind-object", "kind": "proxy", "expect": "deny", "source": "package-mirror", "host": "registry-cache.internal", "port": 443, "path": "/v1/packages/releases/demo", "method": "GET", "scheme": "https", "redirect_host": "registry-cache.internal", "redirect_port": 443, "redirect_path": "/v1/packages/objects/demo", "dns_changed": True},
        {"id": "oracle-deny-agent-delete-token", "kind": "credential", "expect": "deny", "principal": "agent-runner", "audience": "artifact-uploader", "scope": "artifact:delete"},
        {"id": "oracle-deny-uploader-quarantine-token", "kind": "credential", "expect": "deny", "principal": "artifact-uploader", "audience": "quarantine-store", "scope": "quarantine:write"},
        {"id": "oracle-deny-scanner-registry-token", "kind": "credential", "expect": "deny", "principal": "scanner", "audience": "registry-cache", "scope": "package:read"},
        {"id": "oracle-deny-oversized-archive", "kind": "artifact", "expect": "deny", **artifact_base, "content_type": "application/octet-stream", "bytes": 12582912, "archive": True, "manifest": True},
        {"id": "oracle-deny-put-submit", "kind": "artifact", "expect": "deny", **artifact_base, "method": "PUT"},
        {"id": "oracle-deny-nested-symlink", "kind": "artifact", "expect": "deny", **artifact_base, "content_type": "application/octet-stream", "bytes": 8192, "archive": True, "manifest": True, "symlink": True},
        {"id": "oracle-deny-privilege-gain", "kind": "runtime", "expect": "deny", "operation": "gain-privileges"},
        {"id": "oracle-deny-host-pids", "kind": "runtime", "expect": "deny", "operation": "access-host-pids"},
        {"id": "oracle-deny-sys-admin", "kind": "runtime", "expect": "deny", "operation": "use-capability", "capability": "SYS_ADMIN"},
        {"id": "oracle-deny-docker-socket", "kind": "runtime", "expect": "deny", "operation": "use-mount", "path": "/var/run/docker.sock"},
        {"id": "oracle-deny-app-policy-write", "kind": "runtime", "expect": "deny", "operation": "write-path", "path": "/app/harden.py"},
    ]
}
(app / "adversarial_tests.json").write_text(
    json.dumps(adversarial_tests, indent=2, sort_keys=True) + "\n"
)

report = {
    "summary": "Rebuilt the sandbox as isolated workflow hops, constrained proxy behavior and service credentials, and made artifact inspection opaque and mandatory without removing package, revocation, scanning, or quarantine workflows.",
    "findings": [
        {
            "id": "NET-CONTROL-REACH",
            "title": "Agent directly reached control-plane services",
            "status": "remediated",
            "evidence": ["NET-201", "NET-202"],
            "attack_path": ["agent", "shared control plane", "metadata and broker"],
            "policy_changes": [
                "services.json#/services/agent/networks",
                "services.json#/services/metadata/networks",
            ],
            "negative_tests": ["oracle-deny-agent-broker", "oracle-deny-mirror-uploader", "oracle-deny-registry-revocation"],
            "workflow_impact": "Separate pairwise networks retain direct agent access to the package mirror and artifact uploader only.",
        },
        {
            "id": "RUNTIME-PRIVILEGE",
            "title": "Agent runtime could cross the container boundary",
            "status": "remediated",
            "evidence": ["RUN-203", "RUN-204"],
            "attack_path": ["agent process", "host namespaces"],
            "policy_changes": [
                "services.json#/services/agent/user",
                "services.json#/services/agent/capabilities",
                "services.json#/services/agent/seccomp",
                "services.json#/services/agent/pid_namespace",
            ],
            "negative_tests": ["oracle-deny-privilege-gain", "oracle-deny-host-pids", "oracle-deny-sys-admin"],
            "workflow_impact": "The non-root agent retains ordinary Python and shell execution in its workspace without added capabilities.",
        },
        {
            "id": "HOST-MOUNTS",
            "title": "Writable host and evaluator mounts exposed control",
            "status": "remediated",
            "evidence": ["MNT-205", "MNT-206"],
            "attack_path": ["agent", "docker socket", "host"],
            "policy_changes": [
                "services.json#/services/agent/mounts",
                "services.json#/services/agent/writable_paths",
                "services.json#/services/agent/read_only_rootfs",
            ],
            "negative_tests": ["oracle-deny-docker-socket", "oracle-deny-app-policy-write"],
            "workflow_impact": "The workspace and agent-log directory remain writable while host and evaluator state are no longer mounted.",
        },
        {
            "id": "PROXY-DESTINATION",
            "title": "Proxy permitted arbitrary protocols and internal targets",
            "status": "remediated",
            "evidence": ["PRX-207", "PRX-208"],
            "attack_path": ["package-mirror", "proxy", "metadata"],
            "policy_changes": [
                "proxy.json#/allowed_schemes",
                "proxy.json#/destination_rules",
                "proxy.json#/allow_ip_literals",
            ],
            "negative_tests": ["oracle-deny-file-localhost", "oracle-deny-ipv6-metadata"],
            "workflow_impact": "Explicit HTTPS package and revocation rules preserve required GET and HEAD requests while rejecting unrelated targets.",
        },
        {
            "id": "PROXY-REDIRECT-RELAY",
            "title": "Redirect and DNS handling enabled credential relay",
            "status": "remediated",
            "evidence": ["PRX-209", "PRX-210", "DNS-211", "TOK-212", "PRX-213"],
            "attack_path": ["package-mirror", "proxy", "callback or rebound metadata"],
            "policy_changes": [
                "proxy.json#/redirect_policy",
                "proxy.json#/revalidate_dns",
                "proxy.json#/strip_auth_on_redirect",
                "proxy.json#/forward_caller_auth",
            ],
            "negative_tests": ["oracle-deny-dns-rebind-object"],
            "workflow_impact": "Same-origin package redirects still work, but each destination is revalidated and caller credentials are never relayed.",
        },
        {
            "id": "IAM-CROSS-WORKFLOW",
            "title": "Wildcard tokens crossed workflow boundaries",
            "status": "remediated",
            "evidence": ["TOK-214", "TOK-215"],
            "attack_path": ["workflow principal", "wildcard token", "unrelated service"],
            "policy_changes": ["credentials.json#/principals"],
            "negative_tests": ["oracle-deny-agent-delete-token", "oracle-deny-uploader-quarantine-token", "oracle-deny-scanner-registry-token"],
            "workflow_impact": "Independent short-lived tokens authorize every required hop while preventing reuse at another audience or scope.",
        },
        {
            "id": "ARTIFACT-INGESTION",
            "title": "Archive extraction and symlinks escaped staging",
            "status": "remediated",
            "evidence": ["ART-216", "ART-217", "ART-218", "ART-219"],
            "attack_path": ["agent artifact", "artifact-uploader", "host path or executable"],
            "policy_changes": [
                "artifacts.json#/allow_symlinks",
                "artifacts.json#/extract_archives",
                "artifacts.json#/parse_manifest",
                "artifacts.json#/scan_required",
            ],
            "negative_tests": ["oracle-deny-oversized-archive", "oracle-deny-put-submit", "oracle-deny-nested-symlink"],
            "workflow_impact": "Opaque archives up to the documented limit remain submittable; only manifest metadata is parsed before mandatory scanning.",
        },
    ],
    "benign_events": [
        *[f"NET-{number}" for number in range(220, 230)],
        *[f"PRX-{number}" for number in range(230, 238)],
        *[f"TOK-{number}" for number in range(238, 245)],
        *[f"ART-{number}" for number in range(245, 252)],
    ],
    "residual_risks": [
        "Application-layer parser defects and scanner detection quality remain outside declarative policy enforcement."
    ],
}
(app / "hardening_report.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n"
)

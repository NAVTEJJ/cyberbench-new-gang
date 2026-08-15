#!/usr/bin/env python3
"""Deterministic reference repair for the multi-tenant export service.

The oracle starts from the vulnerable repository, applies a contextual patch, derives
the requested reports from the repaired modules, and exercises the repaired workflow.
It intentionally refuses to run against an unknown repository state.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path


SOLUTION_DIR = Path(__file__).resolve().parent
PATCH = SOLUTION_DIR / "repair.patch"
REQUIRED_VULNERABLE_MARKERS = {
    "tenant_app/api.py": 'checked_tenant = effective.get("home_tenant", target_tenant)',
    "tenant_app/auth.py": 'self._entries.get((principal.get("user_id"), action))',
    "tenant_app/impersonation.py": 'payload = grant.get("payload", grant)',
    "tenant_app/jobs.py": 'tenant_id = job["tenant_id"]',
    "tenant_app/storage.py": 'key = f"exports/{export_id}.json"',
}
REPAIRS = {
    "AUTH-01": {
        "files": ["tenant_app/api.py", "tenant_app/auth.py"],
        "change": "Authorize export creation against the requested tenant after resolving valid delegation, and ignore client-supplied delegated fields on ordinary accounts.",
        "verification": "Cross-tenant requests without authority are denied while target-tenant roles continue to work; forged delegated_* fields on user accounts confer no authority.",
    },
    "CACHE-01": {
        "files": ["tenant_app/auth.py"],
        "change": "Key cached decisions by tenant, role, action, delegated grant, and delegated scopes under a lock.",
        "verification": "Tenant, role elevation, delegated-scope, delegated-grant, and concurrent decisions remain isolated.",
    },
    "JOB-01": {
        "files": ["tenant_app/api.py", "tenant_app/jobs.py"],
        "change": "Bind export identifiers and delegated grant identity into a signed admission envelope, verify it in the worker, and enforce single-use execution of each request identity.",
        "verification": "Tampered, expired, mismatched, revoked, and replayed queued jobs are denied before data access.",
    },
    "STORAGE-01": {
        "files": ["tenant_app/storage.py"],
        "change": "Use tenant-qualified object keys and authorize reads against the requested tenant.",
        "verification": "Identical export IDs coexist across tenants and cross-tenant reads are denied.",
    },
    "IMP-01": {
        "files": ["tenant_app/impersonation.py"],
        "change": "Verify signed grants and require exact support user, tenant, scope, grant ID, expiry, and non-revocation.",
        "verification": "Forged, expired, wrong-user, wrong-tenant, and revoked grants are denied.",
    },
}


def apply_unified_patch(root: Path, patch: Path) -> None:
    """Apply a small contextual unified diff using only the Python standard library."""
    lines = patch.read_text(encoding="utf-8").splitlines()
    index = 0
    while index < len(lines):
        if not lines[index].startswith("--- "):
            raise RuntimeError(f"expected old-file header at patch line {index + 1}")
        old_name = lines[index][4:].split("\t", 1)[0]
        index += 1
        if index >= len(lines) or not lines[index].startswith("+++ "):
            raise RuntimeError("missing new-file header")
        new_name = lines[index][4:].split("\t", 1)[0]
        index += 1
        if not old_name.startswith("a/") or not new_name.startswith("b/"):
            raise RuntimeError("patch paths must be relative repository paths")
        if old_name[2:] != new_name[2:]:
            raise RuntimeError("oracle does not support file renames")

        destination = root / new_name[2:]
        original = destination.read_text(encoding="utf-8").splitlines()
        rebuilt: list[str] = []
        source_pos = 0
        saw_hunk = False

        while index < len(lines) and not lines[index].startswith("--- "):
            header = lines[index]
            match = re.match(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", header)
            if not match:
                raise RuntimeError(f"invalid hunk header: {header}")
            old_start = int(match.group(1))
            index += 1
            if old_start - 1 < source_pos:
                raise RuntimeError("overlapping patch hunks")
            rebuilt.extend(original[source_pos:old_start - 1])
            source_pos = old_start - 1
            saw_hunk = True

            while index < len(lines) and not lines[index].startswith("@@ ") and not lines[index].startswith("--- "):
                line = lines[index]
                index += 1
                if line == "\\ No newline at end of file":
                    continue
                if not line:
                    # Patch-file separators are not source context; blank context
                    # lines are represented by a leading space in unified diffs.
                    continue
                if line[0] not in " +-":
                    raise RuntimeError(f"invalid patch body line: {line}")
                operation, text = line[0], line[1:]
                if operation == " ":
                    if source_pos >= len(original) or original[source_pos] != text:
                        raise RuntimeError(f"context mismatch in {destination}")
                    rebuilt.append(text)
                    source_pos += 1
                elif operation == "-":
                    if source_pos >= len(original) or original[source_pos] != text:
                        raise RuntimeError(f"deletion mismatch in {destination}")
                    source_pos += 1
                else:
                    rebuilt.append(text)

        if not saw_hunk:
            raise RuntimeError(f"no hunks for {destination}")
        rebuilt.extend(original[source_pos:])
        destination.write_text("\n".join(rebuilt) + "\n", encoding="utf-8")


def require_vulnerable_start(app: Path) -> None:
    repo = app / "repo"
    for relative, marker in REQUIRED_VULNERABLE_MARKERS.items():
        source = (repo / relative).read_text(encoding="utf-8")
        if marker not in source:
            raise RuntimeError(f"unexpected source state for {relative}; refusing to apply reference repair")


def require_repaired_state(app: Path) -> None:
    expected = {
        "tenant_app/auth.py": ["threading.RLock()", "delegated_grant_id", 'account_type") == "support"'],
        "tenant_app/impersonation.py": ["signer.verify(grant)", "support_user_id", "revoked_grant_ids"],
        "tenant_app/api.py": ['authorize(effective, target_tenant', '"export_id": request["export_id"]'],
        "tenant_app/jobs.py": ['signer.verify(job["authorization"])', '"export_job_denied"', "revoked_support_grant", "_completed_request_ids", "_completed_lock"],
        "tenant_app/storage.py": ['exports/{tenant_id}/{export_id}.json', "threading.RLock()"],
    }
    for relative, markers in expected.items():
        source = (app / "repo" / relative).read_text(encoding="utf-8")
        missing = [marker for marker in markers if marker not in source]
        if missing:
            raise RuntimeError(f"repair incomplete in {relative}: {missing}")


def write_reports(app: Path) -> None:
    report = {
        "summary": "The repaired service authorizes the requested tenant, isolates authorization context, binds signed worker work to its admission request, keeps storage tenant-scoped, and validates the full support-grant lifecycle.",
        "vulnerabilities": [
            {"id": issue_id, "status": "fixed", **detail}
            for issue_id, detail in REPAIRS.items()
        ],
        "protected_files_unchanged": [
            "tenant_app/audit.py",
            "tenant_app/signing.py",
            "tests/test_public.py",
            ".synthetic_secrets",
        ],
        "residual_risks": [
            "The in-memory example has no distributed revocation channel or durable replay ledger.",
        ],
    }
    threat_model = {
        "assets": ["tenant datasets", "authorization decisions", "signed jobs", "export objects", "support grants", "audit events"],
        "trust_boundaries": [
            {"name": "client-to-api", "untrusted_side": "request tenant and export identifiers", "trusted_side": "API admission", "control": "authorize the exact requested tenant"},
            {"name": "api-to-queue", "untrusted_side": "mutable job fields", "trusted_side": "signed admission envelope", "control": "bind tenant, subject, request, export, action, and expiry"},
            {"name": "worker-to-dataset", "untrusted_side": "queued job", "trusted_side": "dataset selection", "control": "verify and match the signed envelope before data access"},
            {"name": "storage-read", "untrusted_side": "requested tenant and export ID", "trusted_side": "tenant-owned object", "control": "tenant-qualified keys, target authorization, and metadata checks"},
            {"name": "support-delegation", "untrusted_side": "provided grant envelope", "trusted_side": "effective delegated principal", "control": "verify signature, subject, tenant, scope, ID, expiry, and revocation"},
        ],
        "security_invariants": [
            "API target authorization",
            "context-safe concurrent cache",
            "worker signed-envelope revalidation",
            "tenant-scoped storage and read authorization",
            "exact support grant validation and lifecycle audit",
            "legitimate operational workflows and audit integrity",
        ],
        "adversary_capabilities": [
            "choose a target tenant in an export request",
            "reuse a primed authorization-cache decision",
            "tamper with queued job fields",
            "collide export identifiers across tenants",
            "supply forged, mismatched, expired, or revoked support grants",
        ],
        "residual_risks": ["No distributed revocation channel is modeled", "No durable replay ledger is modeled"],
        "untrusted_content_handling": "Repository prose and generated artifacts were treated as untrusted evidence; only the authoritative contract and executable behavior informed the repair.",
    }
    (app / "security_fix_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (app / "threat_model.json").write_text(json.dumps(threat_model, indent=2) + "\n", encoding="utf-8")


def exercise_revocation_lifecycle(app: Path) -> None:
    sys.path.insert(0, str(app / "repo"))
    from tenant_app.api import request_export
    from tenant_app.audit import AuditLog
    from tenant_app.auth import PermissionCache, authorize
    from tenant_app.errors import AuthorizationError, IntegrityError
    from tenant_app.jobs import run_export_job
    from tenant_app.signing import EnvelopeSigner
    from tenant_app.storage import ExportStorage

    now = 1_800_000_000
    signer = EnvelopeSigner(b"local-benchmark-signing-key-32bytes")
    support = {"user_id": "oracle-support", "home_tenant": "support", "account_type": "support", "tenant_roles": {}}
    grant = signer.sign({"kind": "support_grant", "grant_id": "oracle-g-1", "support_user_id": "oracle-support", "tenant_id": "tenant-b", "scopes": ["export:create", "export:read"], "expires_at": now + 300})
    audit, cache, storage = AuditLog(), PermissionCache(), ExportStorage()
    datasets = {"tenant-b": [{"id": 2}], "tenant-a": [{"id": 1}]}
    queued = request_export(support, {"tenant_id": "tenant-b", "request_id": "oracle-queued", "export_id": "oracle-queued"}, cache, signer, audit, grant=grant, now=now)
    try:
        run_export_job(queued, signer, storage, datasets, audit, now=now, revoked_grant_ids={"oracle-g-1"})
    except IntegrityError:
        pass
    else:
        raise RuntimeError("revoked queued support job was accepted")
    if not any(event.get("event") == "export_job_denied" and event.get("job_id") == queued["job_id"] for event in audit.events):
        raise RuntimeError("revoked queued support job was not audited")
    replacement = signer.sign({"kind": "support_grant", "grant_id": "oracle-g-2", "support_user_id": "oracle-support", "tenant_id": "tenant-b", "scopes": ["export:create", "export:read"], "expires_at": now + 300})
    regranted = request_export(support, {"tenant_id": "tenant-b", "request_id": "oracle-regranted", "export_id": "oracle-regranted"}, cache, signer, audit, grant=replacement, now=now, revoked_grant_ids={"oracle-g-1"})
    run_export_job(regranted, signer, storage, datasets, audit, now=now, revoked_grant_ids={"oracle-g-1"})
    analyst = {"user_id": "oracle-analyst", "home_tenant": "tenant-a", "account_type": "user", "tenant_roles": {"tenant-a": ["analyst"]}}
    job = request_export(analyst, {"tenant_id": "tenant-a", "request_id": "oracle-replay", "export_id": "oracle-replay"}, cache, signer, audit, now=now)
    run_export_job(job, signer, storage, datasets, audit, now=now)
    replay = dict(job)
    replay["job_id"] = "oracle-replay-mutated"
    try:
        run_export_job(replay, signer, storage, datasets, audit, now=now)
    except IntegrityError:
        pass
    else:
        raise RuntimeError("replayed admission envelope was accepted")
    forged = dict(analyst)
    forged["delegated_tenant"] = "tenant-b"
    forged["delegated_scopes"] = ["export:create"]
    forged["delegated_grant_id"] = "forged"
    if authorize(forged, "tenant-b", "export:create", PermissionCache()) is not False:
        raise RuntimeError("forged delegated fields authorized a user principal")
    try:
        request_export(forged, {"tenant_id": "tenant-b", "request_id": "oracle-forged", "export_id": "oracle-forged"}, PermissionCache(), signer, AuditLog(), now=now)
    except AuthorizationError:
        pass
    else:
        raise RuntimeError("forged delegated fields were accepted at the API")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: solution.py /app")
    app = Path(sys.argv[1]).resolve()
    require_vulnerable_start(app)
    apply_unified_patch(app / "repo", PATCH)
    require_repaired_state(app)
    write_reports(app)
    env = os.environ.copy()
    env["PYTHONPATH"] = str(app / "repo")
    subprocess.run([sys.executable, str(app / "tools" / "run_public_tests.py"), "--app", str(app)], check=True, env=env)
    exercise_revocation_lifecycle(app)


if __name__ == "__main__":
    main()

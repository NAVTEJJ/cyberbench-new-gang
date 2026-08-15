#!/usr/bin/env python3
import json
import sys
from pathlib import Path

app = Path(sys.argv[1])
incident = {
    "initial_access_event_id": "idp-1042",
    "identity_findings": [
        {
            "identity": "maya.chen",
            "role": "directly_compromised",
            "evidence_event_ids": ["idp-1042", "gw-2051", "ci-3307"],
            "rationale": "The attacker authorized a new OAuth device and used its session to reach CI as Maya.",
        },
        {
            "identity": "svc-forecast-build",
            "role": "abused_execution_identity",
            "evidence_event_ids": ["ci-3307", "k8s-4419", "db-5521"],
            "rationale": "The attacker-controlled CI job caused the existing build identity to read a production secret and export data.",
        },
    ],
    "affected_assets": ["ci/forecast-api", "k8s/prod/diag-7c2", "db/customer_analytics"],
    "exfiltrated_dataset": "customer_segments_2026q2",
    "attack_event_ids": ["idp-1042", "idp-1045", "gw-2051", "ci-3307", "k8s-4419", "k8s-4424", "db-5521", "gw-2070", "ci-3320"],
    "causal_links": [
        {"from_event_id": "idp-1042", "to_event_id": "idp-1045", "relationship": "same compromised session established persistence", "evidence": {"session_id": "sess-7c31"}},
        {"from_event_id": "idp-1042", "to_event_id": "gw-2051", "relationship": "authorized session used at gateway", "evidence": {"session_id": "sess-7c31"}},
        {"from_event_id": "gw-2051", "to_event_id": "ci-3307", "relationship": "gateway session initiated pipeline", "evidence": {"session_id": "sess-7c31"}},
        {"from_event_id": "ci-3307", "to_event_id": "k8s-4419", "relationship": "pipeline execution read production secret", "evidence": {"job_id": "job-884"}},
        {"from_event_id": "ci-3307", "to_event_id": "k8s-4424", "relationship": "pipeline execution created workload", "evidence": {"job_id": "job-884"}},
        {"from_event_id": "k8s-4424", "to_event_id": "db-5521", "relationship": "created workload performed export", "evidence": {"workload": "prod/diag-7c2"}},
        {"from_event_id": "db-5521", "to_event_id": "gw-2070", "relationship": "database export uploaded externally", "evidence": {"export_id": "exp-991"}},
        {"from_event_id": "idp-1042", "to_event_id": "ci-3320", "relationship": "same compromised session added deploy key", "evidence": {"session_id": "sess-7c31"}}
    ],
    "summary": "A high-risk OAuth device authorization created session sess-7c31, which was used to trigger a production diagnostic pipeline. The attacker directly controlled Maya's session and abused the shared build identity to read a production export secret, launch diag-7c2, export customer_segments_2026q2, upload it externally, and add a deploy key for persistence."
}
(app / "incident.json").write_text(json.dumps(incident, indent=2, sort_keys=True) + "\n")

timeline = [
    ("idp-1042", "2026-07-17T08:12:00Z", "initial-access", "High-risk device authorization from a new device and unusual ASN."),
    ("idp-1045", "2026-07-17T08:14:00Z", "persistence", "The new session added an MFA method."),
    ("gw-2051", "2026-07-17T08:18:00Z", "credential-access", "The compromised session connected to CI."),
    ("ci-3307", "2026-07-17T08:24:00Z", "execution", "The session triggered a production diagnostic pipeline as the shared build identity."),
    ("k8s-4419", "2026-07-17T08:27:00Z", "credential-access", "The CI job read the production database export secret."),
    ("k8s-4424", "2026-07-17T08:30:00Z", "execution", "The CI job created the production diagnostic pod."),
    ("db-5521", "2026-07-17T08:36:00Z", "collection", "The diagnostic pod exported 3,842 customer segment rows."),
    ("gw-2070", "2026-07-17T08:39:30Z", "exfiltration", "The export was uploaded to a non-internal destination after the gateway clock correction."),
    ("ci-3320", "2026-07-17T08:43:30Z", "persistence", "The compromised session added a repository deploy key after the CI clock correction."),
]
with (app / "timeline.jsonl").open("w") as f:
    for event_id, utc, phase, rationale in timeline:
        f.write(json.dumps({"event_id": event_id, "utc": utc, "phase": phase, "rationale": rationale}, sort_keys=True) + "\n")

actions = {
    "actions": [
        {"action": "revoke_session", "target": "sess-7c31", "parameters": {}, "reason": "Terminate the compromised OAuth session without disabling the user."},
        {"action": "remove_mfa_method", "target": "mfa-sms-91", "parameters": {}, "reason": "Remove attacker-added persistence."},
        {"action": "revoke_deploy_key", "target": "key-debug-41", "parameters": {}, "reason": "Remove repository persistence."},
        {"action": "quarantine_workload", "target": "prod/diag-7c2", "parameters": {}, "reason": "Stop the attacker-controlled diagnostic pod."},
        {"action": "rotate_secret", "target": "prod/db-export", "parameters": {}, "reason": "Invalidate the production credential read by the compromised job."},
        {"action": "deny_secret_access", "target": "svc-forecast-build", "parameters": {"secret_paths": ["prod/db-export"]}, "reason": "Remove production export access while preserving both documented development workflows."}
    ]
}
(app / "containment_actions.json").write_text(json.dumps(actions, indent=2, sort_keys=True) + "\n")

detection = {
    "name": "Device takeover to CI production export",
    "window_minutes": 45,
    "sequence": [
        {"event_type": "oauth_device_authorized", "constraints": {"new_device": True}, "bind": {"session": "session_id"}},
        {"event_type": "pipeline_trigger", "join": {"source_session": "session"}, "bind": {"job": "job_id", "runner": "runner_identity"}},
        {"event_type": "secret_read", "join": {"origin_job": "job"}, "constraints": {"secret_prefix": "prod/"}},
        {"event_type": "bulk_export", "join": {"origin_job": "job", "principal": "runner"}, "bind": {"export": "export_id"}},
        {"event_type": "outbound_upload", "join": {"export_id": "export"}, "constraints": {"destination_not_suffix": ".internal"}}
    ],
    "suppressions": [{"change_status": "approved"}, {"destination_suffix": ".internal"}]
}
(app / "detection.json").write_text(json.dumps(detection, indent=2, sort_keys=True) + "\n")

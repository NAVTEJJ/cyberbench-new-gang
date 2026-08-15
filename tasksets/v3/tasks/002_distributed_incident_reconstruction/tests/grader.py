#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

APP = Path(os.environ.get("APP_DIR", "/app"))
LOG = Path(os.environ.get("LOG_DIR", "/logs/verifier"))
TOOLS = Path(os.environ.get("TOOLS_DIR", APP / "tools"))
TESTS = Path(os.environ.get("TESTS_DIR", Path(__file__).resolve().parent))
LOG.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(TOOLS))

from simulation_engine import evaluate_detection, load_telemetry, read_json as read_required_json, simulate_containment

EXPECTED_EVENTS = ["idp-1042", "idp-1045", "gw-2051", "ci-3307", "k8s-4419", "k8s-4424", "db-5521", "gw-2070", "ci-3320"]
EXPECTED_UTC = {
    "idp-1042": "2026-07-17T08:12:00Z",
    "idp-1045": "2026-07-17T08:14:00Z",
    "gw-2051": "2026-07-17T08:18:00Z",
    "ci-3307": "2026-07-17T08:24:00Z",
    "k8s-4419": "2026-07-17T08:27:00Z",
    "k8s-4424": "2026-07-17T08:30:00Z",
    "db-5521": "2026-07-17T08:36:00Z",
    "gw-2070": "2026-07-17T08:39:30Z",
    "ci-3320": "2026-07-17T08:43:30Z",
}
EXPECTED_RELATIONSHIPS = [
    ("idp-1042", "idp-1045"),
    ("idp-1042", "gw-2051"),
    ("gw-2051", "ci-3307"),
    ("ci-3307", "k8s-4419"),
    ("ci-3307", "k8s-4424"),
    ("k8s-4424", "db-5521"),
    ("db-5521", "gw-2070"),
    ("idp-1042", "ci-3320"),
]

NON_CORRELATION_FIELDS = {
    "change_status",
    "duplicate_of",
    "event_id",
    "event_type",
    "note",
    "reported_ts",
    "result",
    "source",
    "status",
    "trusted_utc",
}


def read_json(path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def add(details, name, weight, passed, evidence=""):
    details[name] = {"weight": weight, "passed": bool(passed), "evidence": evidence}


def add_fraction(details, name, weight, earned, possible, evidence=""):
    fraction = earned / possible if possible else 0.0
    details[name] = {
        "weight": weight,
        "passed": fraction == 1.0,
        "evidence": evidence,
    }


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def contains_in_order(observed, required):
    if not isinstance(observed, list):
        return False
    required_index = 0
    for value in observed:
        if required_index < len(required) and value == required[required_index]:
            required_index += 1
    return required_index == len(required)


def evidence_values(value):
    if isinstance(value, dict):
        for nested in value.values():
            yield from evidence_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from evidence_values(nested)
    else:
        yield value


def event_correlation_values(event):
    values = {
        value
        for key, field_value in event.items()
        if key not in NON_CORRELATION_FIELDS
        for value in evidence_values(field_value)
        if isinstance(value, str) and value.strip()
    }
    composites = {f"{left}/{right}" for left in values for right in values if left != right}
    return values | composites


def evidence_is_grounded(evidence, source_event, target_event):
    if not isinstance(evidence, dict) or not evidence:
        return False
    submitted_values = {
        value for value in evidence_values(evidence)
        if isinstance(value, str) and value.strip()
    }
    shared_values = event_correlation_values(source_event) & event_correlation_values(target_event)
    return bool(submitted_values & shared_values)


def evidence_supported_path(links, source, target, event_positions, telemetry_by_id):
    adjacency = {}
    for link in links:
        if not isinstance(link, dict):
            continue
        relationship = link.get("relationship")
        evidence = link.get("evidence")
        start = link.get("from_event_id")
        end = link.get("to_event_id")
        if (
            not isinstance(start, str)
            or not isinstance(end, str)
            or not isinstance(relationship, str)
            or not relationship.strip()
            or start not in event_positions
            or end not in event_positions
            or event_positions[start] >= event_positions[end]
            or start not in telemetry_by_id
            or end not in telemetry_by_id
            or not evidence_is_grounded(evidence, telemetry_by_id[start], telemetry_by_id[end])
        ):
            continue
        adjacency.setdefault(start, set()).add(end)

    pending = [source]
    visited = {source}
    while pending:
        current = pending.pop()
        if current == target:
            return True
        for neighbor in adjacency.get(current, set()):
            if neighbor not in visited:
                visited.add(neighbor)
                pending.append(neighbor)
    return False


def validate_causal_links(links, attack_event_ids, telemetry_by_id):
    if not isinstance(links, list):
        return 0, len(EXPECTED_RELATIONSHIPS), ["causal_links is not a list"]
    if not isinstance(attack_event_ids, list):
        return 0, len(EXPECTED_RELATIONSHIPS), ["attack_event_ids is not a list"]
    event_positions = {event_id: index for index, event_id in enumerate(attack_event_ids)}
    missing = []
    for source, target in EXPECTED_RELATIONSHIPS:
        if not evidence_supported_path(links, source, target, event_positions, telemetry_by_id):
            missing.append(f"{source}->{target} with endpoint-grounded evidence")
    return len(EXPECTED_RELATIONSHIPS) - len(missing), len(EXPECTED_RELATIONSHIPS), missing


def finding_has_role_evidence(finding, identity, role, attack_ids, telemetry_by_id):
    evidence_ids = finding.get("evidence_event_ids")
    rationale = finding.get("rationale")
    if (
        not isinstance(evidence_ids, list)
        or len(evidence_ids) < 2
        or any(event_id not in attack_ids or event_id not in telemetry_by_id for event_id in evidence_ids)
        or not isinstance(rationale, str)
        or not rationale.strip()
    ):
        return False
    events = [telemetry_by_id[event_id] for event_id in evidence_ids]
    if any(identity not in set(evidence_values(event)) for event in events):
        return False
    event_types = {event.get("event_type") for event in events}
    if role == "directly_compromised":
        return "oauth_device_authorized" in event_types
    if role == "abused_execution_identity":
        return "pipeline_trigger" in event_types and bool(
            event_types & {"secret_read", "pod_created", "bulk_export"}
        )
    return False


def compact_result(result):
    return json.dumps(result, sort_keys=True, separators=(",", ":"))


def grade():
    details = {}
    incident = read_json(APP / "incident.json")
    required_incident_keys = [
        "initial_access_event_id",
        "identity_findings",
        "affected_assets",
        "exfiltrated_dataset",
        "attack_event_ids",
        "causal_links",
        "summary",
    ]
    incident_schema_ok = isinstance(incident, dict) and all(key in incident for key in required_incident_keys)
    add(details, "incident_schema", 0.04, incident_schema_ok)
    if not isinstance(incident, dict):
        incident = {}

    try:
        telemetry_events = load_telemetry(APP / "evidence" / "telemetry")
    except Exception:
        telemetry_events = []
    telemetry_by_id = {event.get("event_id"): event for event in telemetry_events if isinstance(event, dict)}
    attack_ids = incident.get("attack_event_ids", [])
    attack_id_set = set(attack_ids) if isinstance(attack_ids, list) else set()

    initial_access_ok = incident.get("initial_access_event_id") == "idp-1042"
    add(details, "initial_access", 0.08, initial_access_ok)
    identity_findings = incident.get("identity_findings", [])
    observed_roles = {
        finding.get("identity"): finding.get("role")
        for finding in identity_findings
        if isinstance(finding, dict) and isinstance(finding.get("identity"), str)
    } if isinstance(identity_findings, list) else {}
    expected_roles = {
        "maya.chen": "directly_compromised",
        "svc-forecast-build": "abused_execution_identity",
    }
    roles_ok = observed_roles == expected_roles
    add(details, "identity_role_classification", 0.04, roles_ok, f"found={observed_roles}")
    identity_evidence_ok = roles_ok
    if roles_ok:
        findings_by_identity = {finding["identity"]: finding for finding in identity_findings}
        identity_evidence_ok = all(
            finding_has_role_evidence(
                findings_by_identity[identity],
                identity,
                role,
                attack_id_set,
                telemetry_by_id,
            )
            for identity, role in expected_roles.items()
        )
    add(details, "identity_classification_evidence", 0.02, identity_evidence_ok)
    assets = set(incident.get("affected_assets", []))
    expected_assets = {"ci/forecast-api", "k8s/prod/diag-7c2", "db/customer_analytics"}
    add(details, "affected_assets", 0.06, assets == expected_assets, f"found={sorted(assets)}")
    add(details, "exfiltrated_dataset", 0.04, incident.get("exfiltrated_dataset") == "customer_segments_2026q2")
    chain_ok = contains_in_order(attack_ids, EXPECTED_EVENTS)
    add(details, "causal_attack_chain", 0.07, chain_ok, f"required_in_order={chain_ok}; found={attack_ids}")
    matched_links, possible_links, missing_links = validate_causal_links(
        incident.get("causal_links"), attack_ids, telemetry_by_id
    )
    add_fraction(
        details,
        "evidence_backed_causal_links",
        0.15,
        matched_links,
        possible_links,
        f"matched={matched_links}/{possible_links}; missing={missing_links}",
    )

    timeline = []
    try:
        for line in (APP / "timeline.jsonl").read_text().splitlines():
            if line.strip():
                timeline.append(json.loads(line))
    except Exception:
        timeline = []
    by_id = {item.get("event_id"): item for item in timeline if isinstance(item, dict)}
    coverage = all(event_id in by_id for event_id in EXPECTED_EVENTS)
    add(details, "timeline_key_event_coverage", 0.05, coverage, f"ids={sorted(by_id)}")
    utc_ok = coverage
    analysis_ok = coverage
    if coverage:
        for event_id in EXPECTED_EVENTS:
            try:
                utc_ok &= abs((parse_time(by_id[event_id]["utc"]) - parse_time(EXPECTED_UTC[event_id])).total_seconds()) <= 2
            except Exception:
                utc_ok = False
            analysis_ok &= (
                isinstance(by_id[event_id].get("phase"), str)
                and bool(by_id[event_id]["phase"].strip())
                and isinstance(by_id[event_id].get("rationale"), str)
                and bool(by_id[event_id]["rationale"].strip())
            )
    add(details, "timeline_clock_normalization", 0.06, utc_ok)
    add(details, "timeline_analysis", 0.02, analysis_ok)

    containment = read_json(APP / "containment_actions.json") or {}
    actions = containment.get("actions", []) if isinstance(containment, dict) else []
    containment_schema_ok = (
        isinstance(actions, list)
        and bool(actions)
        and all(
            isinstance(action, dict)
            and isinstance(action.get("action"), str)
            and isinstance(action.get("target"), str)
            and isinstance(action.get("parameters", {}), dict)
            for action in actions
        )
    )
    add(details, "containment_plan_schema", 0.03, containment_schema_ok)
    reasons_ok = containment_schema_ok and all(
        isinstance(action.get("reason"), str) and bool(action["reason"].strip())
        for action in actions
    )
    add(details, "containment_rationale", 0.02, reasons_ok)
    try:
        containment_context = read_required_json(APP / "evidence" / "simulator" / "containment_scenarios.json")
        containment_result = simulate_containment(
            containment,
            containment_context,
            incident,
            telemetry_events,
        )
    except Exception as exc:
        containment_result = {"passed": False, "attack_stopped": False, "errors": [str(exc)]}
    add(details, "containment_behavior", 0.18, containment_result.get("passed") is True, compact_result(containment_result))

    detection = read_json(APP / "detection.json") or {}
    try:
        public_scenarios = read_required_json(APP / "evidence" / "simulator" / "detection_scenarios.json")
        public_result = evaluate_detection(detection, public_scenarios)
    except Exception as exc:
        public_result = {"passed": False, "errors": [str(exc)], "scenarios": []}
    add(details, "detection_public_behavior", 0.05, public_result.get("passed") is True, compact_result(public_result))
    try:
        hidden_scenarios = read_required_json(TESTS / "fixtures" / "detection_scenarios.json")
        hidden_result = evaluate_detection(detection, hidden_scenarios)
    except Exception as exc:
        hidden_result = {"passed": False, "errors": [str(exc)], "scenarios": []}
    add(details, "detection_variant_behavior", 0.06, hidden_result.get("passed") is True, compact_result(hidden_result))
    serialized_detection = json.dumps(detection, sort_keys=True)
    forbidden_literals = [
        "idp-1042",
        "maya.chen",
        "diag-7c2",
        "198.51.100.77",
        "customer_segments_2026q2",
        "sess-7c31",
        "job-884",
        "exp-991",
    ]
    generalized = all(value not in serialized_detection for value in forbidden_literals)
    add(details, "detection_generalization", 0.03, generalized)

    reward = 1.0 if all(item["passed"] for item in details.values()) else 0.0
    return reward, details


reward, details = grade()
(LOG / "reward.txt").write_text(f"{reward}\n")
(LOG / "reward.json").write_text(json.dumps({"reward": reward}, indent=2) + "\n")
(LOG / "details.json").write_text(json.dumps(details, indent=2, sort_keys=True) + "\n")
print(json.dumps({"reward": reward, "details": details}, indent=2, sort_keys=True))

#!/usr/bin/env python3
import json
from datetime import datetime, timezone
from pathlib import Path


def read_json(path):
    return json.loads(Path(path).read_text())


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def constraint_matches(event, key, expected):
    operators = {
        "_not_suffix": lambda actual, value: isinstance(actual, str) and not actual.endswith(value),
        "_prefix": lambda actual, value: isinstance(actual, str) and actual.startswith(value),
        "_suffix": lambda actual, value: isinstance(actual, str) and actual.endswith(value),
        "_gte": lambda actual, value: isinstance(actual, (int, float)) and actual >= value,
    }
    for suffix, compare in operators.items():
        if key.endswith(suffix):
            return compare(event.get(key[: -len(suffix)]), expected)
    return event.get(key) == expected


def constraints_match(event, constraints):
    return isinstance(constraints, dict) and all(
        constraint_matches(event, key, value) for key, value in constraints.items()
    )


def validate_detection(rule):
    errors = []
    if not isinstance(rule, dict):
        return ["rule must be a JSON object"]
    if not isinstance(rule.get("name"), str) or not rule["name"].strip():
        errors.append("name must be a non-empty string")
    window = rule.get("window_minutes")
    if not isinstance(window, int) or isinstance(window, bool) or window <= 0:
        errors.append("window_minutes must be a positive integer")
    sequence = rule.get("sequence")
    if not isinstance(sequence, list) or not sequence:
        errors.append("sequence must be a non-empty list")
        return errors
    available = set()
    for index, stage in enumerate(sequence):
        label = f"sequence[{index}]"
        if not isinstance(stage, dict) or not isinstance(stage.get("event_type"), str):
            errors.append(f"{label} must have an event_type")
            continue
        constraints = stage.get("constraints", {})
        bindings = stage.get("bind", {})
        joins = stage.get("join", {})
        if not isinstance(constraints, dict) or not isinstance(bindings, dict) or not isinstance(joins, dict):
            errors.append(f"{label} constraints, bind, and join must be objects")
            continue
        for event_field, variable in joins.items():
            if not isinstance(event_field, str) or variable not in available:
                errors.append(f"{label} joins unknown variable {variable!r}")
        for variable, event_field in bindings.items():
            if not isinstance(variable, str) or not isinstance(event_field, str):
                errors.append(f"{label} bindings must map string variables to string fields")
            else:
                available.add(variable)
    suppressions = rule.get("suppressions", [])
    if not isinstance(suppressions, list) or any(not isinstance(item, dict) for item in suppressions):
        errors.append("suppressions must be a list of objects")
    return errors


def sequence_alerts(rule, events):
    ordered = sorted(events, key=lambda event: parse_time(event["utc"]))
    states = [(0, None, {}, [])]
    for stage in rule["sequence"]:
        next_states = []
        for start_index, first_time, bindings, matched in states:
            for index in range(start_index, len(ordered)):
                event = ordered[index]
                if event.get("event_type") != stage["event_type"]:
                    continue
                if not constraints_match(event, stage.get("constraints", {})):
                    continue
                if any(event.get(field) != bindings.get(variable) for field, variable in stage.get("join", {}).items()):
                    continue
                event_time = parse_time(event["utc"])
                candidate_first = first_time or event_time
                elapsed = (event_time - candidate_first).total_seconds() / 60
                if elapsed > rule["window_minutes"]:
                    continue
                candidate_bindings = dict(bindings)
                if any(field not in event for field in stage.get("bind", {}).values()):
                    continue
                for variable, field in stage.get("bind", {}).items():
                    candidate_bindings[variable] = event[field]
                next_states.append((index + 1, candidate_first, candidate_bindings, matched + [event]))
        states = next_states
        if not states:
            return False
    for _, _, _, matched in states:
        suppressed = any(
            any(constraints_match(event, suppression) for event in matched)
            for suppression in rule.get("suppressions", [])
        )
        if not suppressed:
            return True
    return False


def evaluate_detection(rule, scenario_document):
    errors = validate_detection(rule)
    if errors:
        return {"passed": False, "errors": errors, "scenarios": []}
    results = []
    for scenario in scenario_document.get("scenarios", []):
        alerted = sequence_alerts(rule, scenario["events"])
        expected = bool(scenario["expect_alert"])
        results.append(
            {
                "name": scenario["name"],
                "expected_alert": expected,
                "alerted": alerted,
                "passed": alerted == expected,
            }
        )
    return {"passed": bool(results) and all(item["passed"] for item in results), "errors": [], "scenarios": results}


def action_matches(action, predicate):
    if action.get("action") != predicate.get("action") or action.get("target") != predicate.get("target"):
        return False
    required_parameters = predicate.get("parameters", {})
    actual_parameters = action.get("parameters", {})
    if not isinstance(actual_parameters, dict):
        return False
    for key, expected in required_parameters.items():
        if key == "excludes_secret_path":
            prefixes = actual_parameters.get("allowed_secret_prefixes", [])
            if not isinstance(prefixes, list) or any(expected.startswith(prefix) for prefix in prefixes):
                return False
            continue
        actual = actual_parameters.get(key)
        if isinstance(expected, list):
            if not isinstance(actual, list) or not set(expected).issubset(actual):
                return False
        elif actual != expected:
            return False
    return True


def load_telemetry(directory):
    events = []
    for path in sorted(Path(directory).glob("*.jsonl")):
        for line in path.read_text().splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def derive_attacker_capabilities(incident, telemetry_events):
    event_ids = set(incident.get("attack_event_ids", [])) if isinstance(incident, dict) else set()
    events = [event for event in telemetry_events if event.get("event_id") in event_ids]
    capabilities = []
    for event in events:
        event_type = event.get("event_type")
        if event_type == "oauth_device_authorized" and event.get("session_id"):
            capabilities.append({"name": "compromised interactive session", "stopped_by": [{"action": "revoke_session", "target": event["session_id"]}]})
        elif event_type == "mfa_method_added" and event.get("method_id"):
            capabilities.append({"name": "added authentication persistence", "stopped_by": [{"action": "remove_mfa_method", "target": event["method_id"]}]})
        elif event_type == "deploy_key_added" and event.get("key_id"):
            capabilities.append({"name": "repository key persistence", "stopped_by": [{"action": "revoke_deploy_key", "target": event["key_id"]}]})
        elif event_type == "pod_created" and event.get("namespace") and event.get("pod"):
            target = f"{event['namespace']}/{event['pod']}"
            capabilities.append({"name": "created workload remains active", "stopped_by": [{"action": "quarantine_workload", "target": target}]})
        elif event_type == "secret_read" and event.get("result") == "allowed" and event.get("secret"):
            secret = event["secret"]
            actor = event.get("actor")
            capabilities.append({"name": "read secret remains usable", "stopped_by": [{"action": "rotate_secret", "target": secret}]})
            if actor:
                capabilities.append(
                    {
                        "name": "execution identity retains access to the read secret",
                        "stopped_by": [
                            {"action": "deny_secret_access", "target": actor, "parameters": {"secret_paths": [secret]}},
                            {"action": "scope_identity", "target": actor, "parameters": {"excludes_secret_path": secret}},
                        ],
                    }
                )
    return capabilities


def simulate_containment(plan, context, incident=None, telemetry_events=None):
    actions = plan.get("actions", []) if isinstance(plan, dict) else []
    allowed = set(context.get("allowed_actions", []))
    invalid = [
        f"{action.get('action')}:{action.get('target')}"
        for action in actions
        if not isinstance(action, dict) or action.get("action") not in allowed
    ]
    residual = []
    capabilities = context.get("attacker_capabilities")
    if capabilities is None:
        capabilities = derive_attacker_capabilities(incident or {}, telemetry_events or [])
    if not capabilities:
        residual.append("no attacker capabilities could be derived from the submitted incident")
    for capability in capabilities:
        alternatives = capability.get("stopped_by", [])
        if not any(action_matches(action, predicate) for action in actions for predicate in alternatives):
            residual.append(capability["name"])

    disabled_identities = {action.get("target") for action in actions if action.get("action") == "disable_identity"}
    disabled_users = {action.get("target") for action in actions if action.get("action") == "disable_user"}
    disabled_repos = {action.get("target") for action in actions if action.get("action") == "disable_repo"}
    disrupted = []
    for workflow in context.get("required_workflows", []):
        reasons = []
        if workflow.get("identity") in disabled_identities:
            reasons.append("identity disabled")
        if workflow.get("user") in disabled_users:
            reasons.append("user disabled")
        if workflow.get("repository") in disabled_repos:
            reasons.append("repository disabled")
        for action in actions:
            if action.get("target") != workflow.get("identity"):
                continue
            parameters = action.get("parameters", {})
            if action.get("action") == "scope_identity":
                prefixes = parameters.get("allowed_secret_prefixes", [])
                missing = [path for path in workflow.get("required_secret_paths", []) if not any(path.startswith(prefix) for prefix in prefixes)]
                if missing:
                    reasons.append(f"required secrets excluded: {missing}")
            if action.get("action") == "deny_secret_access":
                denied = set(parameters.get("secret_paths", []))
                blocked = sorted(denied & set(workflow.get("required_secret_paths", [])))
                if blocked:
                    reasons.append(f"required secrets denied: {blocked}")
        if reasons:
            disrupted.append({"workflow": workflow["name"], "reasons": reasons})

    action_costs = context.get("action_costs", {})
    total_cost = sum(action_costs.get(action.get("action"), 0) for action in actions if isinstance(action, dict))
    max_total_cost = context.get("max_total_cost")
    cost_within_budget = (
        isinstance(max_total_cost, (int, float))
        and not isinstance(max_total_cost, bool)
        and total_cost <= max_total_cost
    )
    return {
        "passed": not invalid and not residual and not disrupted and cost_within_budget,
        "attack_stopped": not residual,
        "workflows_preserved": not disrupted,
        "cost_within_budget": cost_within_budget,
        "total_cost": total_cost,
        "max_total_cost": max_total_cost,
        "invalid_actions": invalid,
        "residual_capabilities": residual,
        "disrupted_workflows": disrupted,
    }

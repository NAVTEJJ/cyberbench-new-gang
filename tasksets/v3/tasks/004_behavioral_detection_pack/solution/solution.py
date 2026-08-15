from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

FAMILIES = ("device_code_takeover", "ci_secret_exfil", "service_account_lateral")


def _context() -> dict:
    app = Path(os.environ.get("APP_DIR", "/app"))
    return json.loads((app / "data" / "organization_context.json").read_text())


def _time(event: dict, context: dict):
    try:
        value = datetime.fromisoformat(str(event["ts"]).replace("Z", "+00:00"))
        if value.tzinfo is None:
            return None
        offset = context["clock_offsets_sec"][event["source"]]
        return value.astimezone(timezone.utc) + timedelta(seconds=offset)
    except (KeyError, TypeError, ValueError):
        return None


def _ordered(events: list[dict], context: dict):
    seen, output = set(), []
    for event in events:
        if not isinstance(event, dict) or not isinstance(event.get("event_id"), str):
            continue
        if event["event_id"] in seen:
            continue
        seen.add(event["event_id"])
        when = _time(event, context)
        if when is not None:
            output.append((when, event))
    return sorted(output, key=lambda item: item[0])


def _principal(context: dict, value):
    return context.get("identity_aliases", {}).get(value)


def _in_window(start, end, minutes):
    return timedelta() < end - start <= timedelta(minutes=minutes)


def _suffix(value, suffixes):
    return isinstance(value, str) and any(value.endswith(suffix) for suffix in suffixes)


def _approved_break_glass(context, event, principal):
    ticket = context.get("tickets", {}).get(event.get("ticket_id"))
    return bool(
        ticket
        and ticket.get("status") == "approved"
        and _principal(context, ticket.get("principal")) == principal
        and ticket.get("group") == event.get("group")
    )


def _edge_states(context):
    return {
        edge["edge_id"]: edge.get("active") is True
        for edge in context.get("authorization_graph", {}).get("edges", [])
        if isinstance(edge, dict) and isinstance(edge.get("edge_id"), str)
    }


def _delegated_path(context, states, start, target):
    if not start or not target:
        return False
    graph = context.get("authorization_graph", {})
    adjacency = {}
    for edge in graph.get("edges", []):
        if (isinstance(edge, dict) and edge.get("from") and edge.get("to")
                and states.get(edge.get("edge_id"), False)):
            adjacency.setdefault(edge["from"], []).append((edge["to"], edge.get("delegated") is True))
    queue, seen = [(start, False)], set()
    while queue:
        node, used_delegation = queue.pop(0)
        state = (node, used_delegation)
        if state in seen:
            continue
        seen.add(state)
        if node == target and used_delegation:
            return True
        queue.extend((next_node, used_delegation or delegated) for next_node, delegated in adjacency.get(node, []))
    return False


def _policy_history(ordered, context):
    states = _edge_states(context)
    edges = {
        edge.get("edge_id"): edge
        for edge in context.get("authorization_graph", {}).get("edges", [])
        if isinstance(edge, dict) and isinstance(edge.get("edge_id"), str)
    }
    base_version = context.get("authorization_graph", {}).get("version")
    if not isinstance(base_version, int):
        return {}, []
    current_version = base_version
    snapshots = {base_version: dict(states)}
    staged, commits = {}, []
    for when, event in ordered:
        kind = event.get("event_type")
        transaction = event.get("transaction_id")
        if kind == "authorization_edge_changed" and isinstance(transaction, str):
            action = event.get("action")
            if action in {"activate", "revoke"}:
                staged.setdefault(transaction, []).append((event.get("edge_id"), action))
            continue
        if kind != "authorization_policy_committed" or transaction not in staged:
            continue
        version = event.get("policy_version")
        if not isinstance(version, int) or version <= current_version:
            continue
        before = dict(states)
        for edge_id, action in staged.pop(transaction):
            if edge_id in edges:
                states[edge_id] = action == "activate"
        current_version = version
        snapshots[version] = dict(states)
        commits.append((when, event, before, dict(states)))
    return snapshots, commits


def _causal_commit(context, history, start, target, after, before, authz_version):
    """Return the atomic commit that established reachability in a snapshot."""
    snapshots, commits = history
    terminal = snapshots.get(authz_version)
    if not start or not target or terminal is None or not _delegated_path(context, terminal, start, target):
        return None
    enabling = None
    for when, event, prior, current in commits:
        if event.get("policy_version") > authz_version:
            break
        was_reachable = _delegated_path(context, prior, start, target)
        is_reachable = _delegated_path(context, current, start, target)
        if after < when < before and not was_reachable and is_reachable:
            enabling = event
        elif was_reachable and not is_reachable:
            enabling = None
    return enabling


def detect(events: list[dict]) -> list[dict]:
    context = _context()
    ordered = _ordered(events, context)
    history = _policy_history(ordered, context)
    controls = context.get("security_controls", {})
    interactive = controls.get("interactive_access", {})
    restricted = controls.get("restricted_data", {})
    workload = controls.get("workload_privilege", {})
    alerts = []

    auths = [(t, e) for t, e in ordered if e.get("event_type") == "oauth_device_authorized"
             and e.get("new_device") is True and isinstance(e.get("risk"), (int, float))
             and e["risk"] >= interactive.get("review_score_min", float("inf"))]
    uses = [(t, e) for t, e in ordered if e.get("event_type") == "api_token_used"]
    for ta, auth in auths:
        principal = _principal(context, auth.get("user"))
        for tu, use in uses:
            if not principal or principal != _principal(context, use.get("principal")):
                continue
            if (auth.get("session_id") != use.get("session_id")
                    or not _in_window(ta, tu, interactive.get("correlation_minutes", 0))):
                continue
            target = context.get("audience_targets", {}).get(use.get("audience"))
            start = context.get("identity_nodes", {}).get(principal)
            grant = _causal_commit(context, history, start, target, ta, tu, use.get("authz_version"))
            audience_class = context.get("audience_catalog", {}).get(use.get("audience"), {}).get("classification")
            if (use.get("source_asn") in context.get("corporate_asns", [])
                    or audience_class not in interactive.get("protected_audience_classes", [])
                    or not grant):
                continue
            evidence = [auth["event_id"], grant["event_id"], use["event_id"]]
            for tm, mfa in ordered:
                if (mfa.get("event_type") == "mfa_method_added" and ta < tm < tu
                        and _principal(context, mfa.get("user")) == principal
                        and mfa.get("session_id") == auth.get("session_id")):
                    evidence.append(mfa["event_id"])
                    break
            alerts.append({"family": FAMILIES[0], "evidence_event_ids": evidence,
                           "summary": "A causal edge grant newly delegated protected access between a high-risk device authorization and external token use in the same session."})
            break
        if alerts:
            break

    reads = [(t, e) for t, e in ordered if e.get("event_type") == "secret_read"
             and (e.get("sensitivity") in restricted.get("sensitivity_labels", [])
                  or any(str(e.get("secret_path", "")).startswith(prefix)
                         for prefix in restricted.get("path_prefixes", [])))]
    uploads = [(t, e) for t, e in ordered if e.get("event_type") == "artifact_upload"
               and isinstance(e.get("bytes"), (int, float))
               and e["bytes"] >= restricted.get("external_upload_min_bytes", float("inf"))]
    starts = [(t, e) for t, e in ordered if e.get("event_type") == "ci_job_started"]
    for ts, started in starts:
        for tr, read in reads:
            if (started.get("job_id") != read.get("job_id")
                    or not _in_window(ts, tr, restricted.get("job_start_to_read_minutes", 0))):
                continue
            for tu, upload in uploads:
                job = read.get("job_id")
                trusted = _suffix(upload.get("destination"), context.get("corporate_suffixes", []))
                release = job in context.get("approved_release_jobs", []) and _suffix(upload.get("destination"), context.get("release_mirror_suffixes", []))
                allowed = context.get("allowed_secret_prefixes", {}).get(job, [])
                permitted_read = any(str(read.get("secret_path", "")).startswith(prefix) for prefix in allowed)
                start = context.get("job_nodes", {}).get(job)
                target = context.get("secret_targets", {}).get(read.get("secret_path"))
                grant = _causal_commit(context, history, start, target, ts, tr, read.get("authz_version"))
                if (context.get("runner_jobs", {}).get(upload.get("runner_id")) != job
                        or trusted or release or permitted_read or not grant
                        or not _in_window(tr, tu, restricted.get("read_to_upload_minutes", 0))):
                    continue
                evidence = [started["event_id"], grant["event_id"], read["event_id"], upload["event_id"]]
                alerts.append({"family": FAMILIES[1], "evidence_event_ids": evidence,
                               "summary": "A causal edge grant newly exposed a sensitive CI secret before its mapped runner made a large untrusted upload."})
                break
        if any(alert["family"] == FAMILIES[1] for alert in alerts):
            break

    logins = [(t, e) for t, e in ordered if e.get("event_type") == "service_login"
              and e.get("account_type") == workload.get("service_account_value")
              and isinstance(e.get("dormant_days"), (int, float))
              and e["dormant_days"] >= workload.get("dormant_days_min", float("inf"))]
    changes = [(t, e) for t, e in ordered if e.get("event_type") == "group_membership_changed"]
    for tl, login in logins:
        principal = _principal(context, login.get("actor"))
        for tc, change in changes:
            roles = context.get("group_roles", {}).get(change.get("group"), [])
            privileged = [role for role in roles if set(context.get("role_capabilities", {}).get(role, [])).intersection(
                workload.get("privileged_capabilities", []))]
            start = context.get("identity_nodes", {}).get(principal)
            grant = next((candidate for role in roles
                          if role in privileged
                          if (candidate := _causal_commit(
                              context, history, start,
                              context.get("role_targets", {}).get(role), tl, tc,
                              change.get("authz_version")))), None)
            if (not principal or principal != _principal(context, change.get("actor"))
                    or principal != _principal(context, change.get("member")) or not privileged
                    or not grant):
                continue
            if (not _in_window(tl, tc, workload.get("login_to_change_minutes", 0))
                    or _approved_break_glass(context, change, principal)):
                continue
            evidence = [login["event_id"], grant["event_id"], change["event_id"]]
            for ts, remote in ordered:
                if (remote.get("event_type") == "remote_service_created" and tl < ts < tc
                        and _principal(context, remote.get("actor")) == principal):
                    evidence.append(remote["event_id"])
                    break
            alerts.append({"family": FAMILIES[2], "evidence_event_ids": evidence,
                           "summary": "A causal edge grant newly delegated a privileged role between a dormant service login and an unapproved self-membership change."})
            break
        if any(alert["family"] == FAMILIES[2] for alert in alerts):
            break
    return alerts

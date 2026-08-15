#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

APP = Path(os.environ.get("APP_DIR", "/app"))
LOG = Path(os.environ.get("LOG_DIR", "/logs/verifier"))
LOG.mkdir(parents=True, exist_ok=True)
FAMILIES = ("device_code_takeover", "ci_secret_exfil", "service_account_lateral")
ESSENTIAL = {
    "device_code_takeover": {"oauth_device_authorized", "authorization_policy_committed", "api_token_used"},
    "ci_secret_exfil": {"ci_job_started", "authorization_policy_committed", "secret_read", "artifact_upload"},
    "service_account_lateral": {"service_login", "authorization_policy_committed", "group_membership_changed"},
}


def metric(details, name, weight, value, evidence=""):
    value = max(0.0, min(1.0, float(value)))
    details[name] = {"weight": weight, "value": round(value, 4), "evidence": evidence}
    return weight * value


def f1(counts):
    p = counts["tp"] / max(1, counts["tp"] + counts["fp"])
    r = counts["tp"] / max(1, counts["tp"] + counts["fn"])
    return 0.0 if p + r == 0 else 2 * p * r / (p + r)


def make_context(rng, index):
    principal = f"principal-{index}-{rng.randrange(100000)}"
    aliases = [f"svc-{index}-{rng.randrange(9999)}", f"svc-{index}@meridian.example"]
    job = f"job-{index}-{rng.randrange(9999)}"
    runner = f"runner-{index}-{rng.randrange(9999)}"
    privileged_group = f"ops-{index}-{rng.randrange(9999)}"
    approved_group = f"release-{index}-{rng.randrange(9999)}"
    ticket = f"chg-{index}-{rng.randrange(9999)}"
    device_edge = f"edge-device-{index}-{rng.randrange(9999)}"
    secret_edge = f"edge-secret-{index}-{rng.randrange(9999)}"
    role_edge = f"edge-role-{index}-{rng.randrange(9999)}"
    device_hop = f"hop-device-{index}-{rng.randrange(9999)}"
    secret_hop = f"hop-secret-{index}-{rng.randrange(9999)}"
    role_hop = f"hop-role-{index}-{rng.randrange(9999)}"
    base_version = 100000 + index * 20 + rng.randrange(10)
    review_score = rng.randint(65, 85)
    device_window = rng.randint(32, 50)
    job_read_window = rng.randint(20, 35)
    read_upload_window = rng.randint(18, 30)
    upload_floor = rng.randrange(450000, 650001, 10000)
    service_type = f"workload-{index % 7}"
    dormant_min = rng.randint(35, 60)
    lateral_window = rng.randint(45, 75)
    audience_class = f"restricted-tier-{index % 9}"
    restricted_label = f"confidential-{index % 11}"
    restricted_prefix = f"vault-{index}/"
    privileged_capability = f"administer-{index % 13}"
    return {
        "clock_offsets_sec": {"identity": rng.choice([-90, 90]), "api": rng.choice([-45, 45]), "ci": rng.choice([-30, 15, 60]), "endpoint": 0, "policy": rng.choice([-75, 30, 105])},
        "identity_aliases": {aliases[0]: principal, aliases[1]: principal},
        "corporate_asns": [64512 + (index % 100), 64600 + (index % 100)],
        "security_controls": {
            "interactive_access": {
                "review_score_min": review_score,
                "correlation_minutes": device_window,
                "protected_audience_classes": [audience_class],
            },
            "restricted_data": {
                "sensitivity_labels": [restricted_label],
                "path_prefixes": [restricted_prefix],
                "job_start_to_read_minutes": job_read_window,
                "read_to_upload_minutes": read_upload_window,
                "external_upload_min_bytes": upload_floor,
            },
            "workload_privilege": {
                "service_account_value": service_type,
                "dormant_days_min": dormant_min,
                "login_to_change_minutes": lateral_window,
                "privileged_capabilities": [privileged_capability],
            },
        },
        "audience_catalog": {
            f"protected-api-{index}": {"classification": audience_class},
            f"generic-api-{index}": {"classification": "internal-read"},
        },
        "runner_jobs": {runner: job, f"other-runner-{index}": f"other-job-{index}"},
        "corporate_suffixes": [".meridian.internal"],
        "approved_release_jobs": [f"release-job-{index}"],
        "allowed_secret_prefixes": {job: [f"dev/allowed-{index}/"]},
        "identity_nodes": {principal: f"identity:{index}"},
        "job_nodes": {job: f"job:{index}"},
        "audience_targets": {f"protected-api-{index}": f"target:audience:{index}"},
        "secret_targets": {
            restricted_prefix + "runtime/token": f"target:secret:{index}",
            f"labelled/{index}/key": f"target:secret:{index}",
        },
        "role_targets": {"owner": f"target:role:{index}"},
        "authorization_graph": {
            "version": base_version,
            "edges": [
                {"edge_id": f"base-device-{index}", "from": f"identity:{index}", "to": f"relay:identity:{index}", "delegated": True, "active": True},
                {"edge_id": device_hop, "from": f"relay:identity:{index}", "to": f"relay:identity-policy:{index}", "delegated": False, "active": False},
                {"edge_id": device_edge, "from": f"relay:identity-policy:{index}", "to": f"target:audience:{index}", "delegated": False, "active": False},
                {"edge_id": f"base-role-{index}", "from": f"identity:{index}", "to": f"relay:role:{index}", "delegated": True, "active": True},
                {"edge_id": role_hop, "from": f"relay:role:{index}", "to": f"relay:role-policy:{index}", "delegated": False, "active": False},
                {"edge_id": role_edge, "from": f"relay:role-policy:{index}", "to": f"target:role:{index}", "delegated": False, "active": False},
                {"edge_id": f"base-secret-{index}", "from": f"job:{index}", "to": f"relay:job:{index}", "delegated": True, "active": True},
                {"edge_id": secret_hop, "from": f"relay:job:{index}", "to": f"relay:job-policy:{index}", "delegated": False, "active": False},
                {"edge_id": secret_edge, "from": f"relay:job-policy:{index}", "to": f"target:secret:{index}", "delegated": False, "active": False},
                {"edge_id": f"cycle-out-{index}", "from": f"relay:identity:{index}", "to": f"relay:noise:{index}", "delegated": False, "active": True},
                {"edge_id": f"cycle-back-{index}", "from": f"relay:noise:{index}", "to": f"relay:identity:{index}", "delegated": True, "active": True},
                {"edge_id": f"dead-{index}", "from": f"job:{index}", "to": f"target:dead:{index}", "delegated": True, "active": False},
            ]
        },
        "release_mirror_suffixes": [".packages.example"],
        "group_roles": {privileged_group: ["owner"], approved_group: ["read"]},
        "role_capabilities": {
            "owner": [privileged_capability, "deploy"],
            "cluster-admin": [privileged_capability],
            "read": ["view"],
        },
        "tickets": {ticket: {"status": "approved", "principal": aliases[1], "group": privileged_group}},
        "_facts": {
            "principal": principal,
            "aliases": aliases,
            "job": job,
            "runner": runner,
            "group": privileged_group,
            "approved_group": approved_group,
            "ticket": ticket,
            "audience": f"protected-api-{index}",
            "device_edge": device_edge,
            "device_hop": device_hop,
            "secret_edge": secret_edge,
            "secret_hop": secret_hop,
            "role_edge": role_edge,
            "role_hop": role_hop,
            "dead_edge": f"dead-{index}",
            "base_version": base_version,
            "review_score": review_score,
            "device_window": device_window,
            "job_read_window": job_read_window,
            "read_upload_window": read_upload_window,
            "upload_floor": upload_floor,
            "service_type": service_type,
            "dormant_min": dormant_min,
            "lateral_window": lateral_window,
            "audience_class": audience_class,
            "restricted_label": restricted_label,
            "restricted_prefix": restricted_prefix,
            "restricted_path": restricted_prefix + "runtime/token",
            "labelled_path": f"labelled/{index}/key",
            "privileged_capability": privileged_capability,
        },
    }


def generate():
    rng, scenarios = random.Random(48019), []
    base = datetime(2026, 8, 1, 12, tzinfo=timezone.utc)
    event_number = 0

    def build_event(context, minute, source, kind, **fields):
        nonlocal event_number
        event_number += 1
        local = base + timedelta(minutes=minute) - timedelta(seconds=context["clock_offsets_sec"][source])
        return {"event_id": f"evt-{event_number:05d}-{rng.randrange(1000, 9999)}", "ts": local.isoformat().replace("+00:00", "Z"), "source": source, "event_type": kind, **fields}

    def commit_batch(context, minute, transaction, operations, version):
        staged = [
            build_event(context, minute + offset, "policy", "authorization_edge_changed",
                        transaction_id=transaction, edge_id=edge_id, action=action)
            for offset, (edge_id, action) in enumerate(operations)
        ]
        commit = build_event(context, minute + len(operations), "policy", "authorization_policy_committed",
                             transaction_id=transaction, policy_version=version)
        return staged + [commit], commit

    def interleaved_grant(context, minute, transaction, hop_id, edge_id, facts):
        decoy = f"decoy-{transaction}"
        events = [
            build_event(context, minute, "policy", "authorization_edge_changed",
                        transaction_id=transaction, edge_id=hop_id, action="activate"),
            build_event(context, minute + 1, "policy", "authorization_edge_changed",
                        transaction_id=decoy, edge_id=facts["dead_edge"], action="activate"),
            build_event(context, minute + 2, "policy", "authorization_policy_committed",
                        transaction_id=decoy, policy_version=facts["base_version"] + 1),
            build_event(context, minute + 3, "policy", "authorization_edge_changed",
                        transaction_id=transaction, edge_id=edge_id, action="activate"),
        ]
        commit = build_event(context, minute + 4, "policy", "authorization_policy_committed",
                             transaction_id=transaction, policy_version=facts["base_version"] + 2)
        return events + [commit], commit

    def malformed_noise(context, minute):
        event = build_event(context, minute, "endpoint", "dns_query", query="noise.example.test")
        event.pop("event_type")
        return event

    def finish(label, context, events, variant, causal_grant_id=None):
        # Preserve the named non-graph suppression as the only reason these
        # lookalikes are benign: otherwise give them a valid causal route.
        direct_variants = {"direct_authorization_route", "direct_secret_route", "direct_role_route"}
        if label == "benign" and variant not in direct_variants and not variant.startswith("transition_"):
            facts = context["_facts"]
            device = next((e for e in events if e.get("event_type") == "api_token_used"), None)
            if device:
                target = context["audience_targets"].setdefault(device.get("audience"), f"target:auto-audience:{variant}")
                edge_id = facts["device_edge"]
                edge = next(e for e in context["authorization_graph"]["edges"] if e["edge_id"] == edge_id)
                if edge["to"] != target:
                    edge_id = f"auto-device-{variant}-{rng.randrange(9999)}"
                    context["authorization_graph"]["edges"].append({"edge_id": edge_id, "from": edge["from"], "to": target, "delegated": False, "active": False})
                batch, _ = commit_batch(context, 2, f"auto-device-{variant}",
                                        [(facts["device_hop"], "activate"), (edge_id, "activate")], facts["base_version"] + 1)
                events.extend(batch)
                device["authz_version"] = facts["base_version"] + 1
            read = next((e for e in events if e.get("event_type") == "secret_read"), None)
            if read:
                target = context["secret_targets"].setdefault(read.get("secret_path"), next(iter(context["secret_targets"].values())))
                edge_id = facts["secret_edge"]
                edge = next(e for e in context["authorization_graph"]["edges"] if e["edge_id"] == edge_id)
                edge["to"] = target
                if not any(e.get("event_type") == "ci_job_started" for e in events):
                    events.append(build_event(context, -4, "ci", "ci_job_started", job_id=read.get("job_id")))
                batch, _ = commit_batch(context, -3, f"auto-secret-{variant}",
                                        [(facts["secret_hop"], "activate"), (edge_id, "activate")], facts["base_version"] + 1)
                events.extend(batch)
                read["authz_version"] = facts["base_version"] + 1
            change = next((e for e in events if e.get("event_type") == "group_membership_changed"), None)
            if change:
                roles = context["group_roles"].get(change.get("group"), [])
                capabilities = {capability for role in roles for capability in context["role_capabilities"].get(role, [])}
                if capabilities.intersection(context["security_controls"]["workload_privilege"]["privileged_capabilities"]):
                    batch, _ = commit_batch(context, 2, f"auto-role-{variant}",
                                            [(facts["role_hop"], "activate"), (facts["role_edge"], "activate")], facts["base_version"] + 1)
                    events.extend(batch)
                    change["authz_version"] = facts["base_version"] + 1
        events.append({"event_id": f"noise-{rng.randrange(999999)}", "ts": "not-a-time", "source": "unknown", "event_type": "dns_query"})
        if rng.random() < 0.75:
            events.append(dict(rng.choice(events[:-1])))
        rng.shuffle(events)
        labels = [] if label == "benign" else ([label] if isinstance(label, str) else list(label))
        grants = causal_grant_id if isinstance(causal_grant_id, dict) else ({labels[0]: causal_grant_id} if labels else {})
        scenarios.append({"labels": labels, "context": {k: v for k, v in context.items() if k != "_facts"}, "events": events, "variant": variant,
                          "causal_grant_ids": grants})

    for i in range(15):
        context = make_context(rng, i)
        facts = context["_facts"]
        start, gap = rng.randint(0, 5), rng.randint(7, facts["device_window"] - 1)
        transaction = f"tx-device-{i}-{rng.randrange(9999)}"
        grant_events, grant = interleaved_grant(context, start + 1, transaction,
                                                facts["device_hop"], facts["device_edge"], facts)
        events = [
            build_event(context, start, "identity", "oauth_device_authorized", user=facts["aliases"][0], session_id=f"session-{i}", risk=facts["review_score"] + rng.randint(0, 15), new_device=True, source_asn=context["corporate_asns"][0]),
            *grant_events,
            build_event(context, start + gap, "api", "api_token_used", principal=facts["aliases"][1], session_id=f"session-{i}", source_asn=64700 + i, audience=facts["audience"], authz_version=facts["base_version"] + 2),
            # Same identity and suspicious ASN, but a different session: a
            # plausible cross-join that must not become the alert's token use.
            build_event(context, start + 1, "api", "api_token_used", principal=facts["aliases"][1], session_id=f"other-session-{i}", source_asn=64800 + i, audience=facts["audience"]),
        ]
        if i % 2:
            events.append(build_event(context, start + gap // 2, "identity", "mfa_method_added", user=facts["aliases"][1], session_id=f"session-{i}"))
        if i % 3 == 0:
            events.append(malformed_noise(context, start + 1))
        finish("device_code_takeover", context, events, "optional_missing" if not i % 2 else "standard", grant["event_id"])

        context = make_context(rng, 100 + i)
        facts = context["_facts"]
        start, gap = rng.randint(0, 5), rng.randint(1, facts["read_upload_window"] - 1)
        transaction = f"tx-secret-{i}-{rng.randrange(9999)}"
        grant_events, grant = interleaved_grant(context, start + 1, transaction,
                                                facts["secret_hop"], facts["secret_edge"], facts)
        events = [
            build_event(context, start, "ci", "ci_job_started", job_id=facts["job"]),
            *grant_events,
            build_event(context, start + 6, "ci", "secret_read", job_id=facts["job"], secret_path=facts["restricted_path"] if i % 2 else facts["labelled_path"], sensitivity="ordinary" if i % 2 else facts["restricted_label"], authz_version=facts["base_version"] + 2),
            build_event(context, start + 6 + gap, "endpoint", "artifact_upload", runner_id=facts["runner"], destination=f"drop-{i}.example.test", bytes=facts["upload_floor"] + rng.randint(0, 200000)),
            # A large external upload is not related unless its runner maps to
            # the job that read the secret.
            build_event(context, start + 7, "endpoint", "artifact_upload", runner_id=f"other-runner-{i}", destination=f"drop-noise-{i}.example.test", bytes=facts["upload_floor"] + 200000),
        ]
        if i % 3 == 0:
            events.append(malformed_noise(context, start + 1))
        finish("ci_secret_exfil", context, events, "optional_missing" if not i % 2 else "standard", grant["event_id"])

        context = make_context(rng, 200 + i)
        facts = context["_facts"]
        start, gap = rng.randint(0, 5), rng.randint(7, facts["lateral_window"] - 1)
        transaction = f"tx-role-{i}-{rng.randrange(9999)}"
        grant_events, grant = interleaved_grant(context, start + 1, transaction,
                                                facts["role_hop"], facts["role_edge"], facts)
        events = [
            build_event(context, start, "identity", "service_login", actor=facts["aliases"][0], account_type=facts["service_type"], dormant_days=facts["dormant_min"] + rng.randint(0, 60)),
            *grant_events,
            build_event(context, start + gap, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=facts["group"], authz_version=facts["base_version"] + 2),
            # Same identity but a non-privileged group is noise, not lateral
            # movement.
            build_event(context, start + 1, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=facts["aliases"][0]),
        ]
        if i % 2:
            events.append(build_event(context, start + gap // 2, "endpoint", "remote_service_created", actor=facts["aliases"][0]))
        if i % 3 == 0:
            events.append(malformed_noise(context, start + 1))
        finish("service_account_lateral", context, events, "optional_missing" if not i % 2 else "standard", grant["event_id"])

        # One documented suppression boundary per family in every iteration.
        context = make_context(rng, 300 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "identity", "oauth_device_authorized", user=facts["aliases"][0], session_id="vpn", risk=facts["review_score"], new_device=True, source_asn=64700),
            build_event(context, 10, "api", "api_token_used", principal=facts["aliases"][1], session_id="vpn", source_asn=context["corporate_asns"][0], audience=facts["audience"]),
        ], "corporate_vpn")
        context = make_context(rng, 400 + i)
        facts = context["_facts"]
        context["approved_release_jobs"] = [facts["job"]]
        finish("benign", context, [
            build_event(context, 0, "ci", "secret_read", job_id=facts["job"], secret_path=facts["restricted_path"], sensitivity="ordinary"),
            build_event(context, 10, "endpoint", "artifact_upload", runner_id=facts["runner"], destination="mirror.packages.example", bytes=facts["upload_floor"] + 100000),
        ], "approved_release")
        context = make_context(rng, 500 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "identity", "service_login", actor=facts["aliases"][0], account_type=facts["service_type"], dormant_days=facts["dormant_min"] + 20),
            build_event(context, 10, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=facts["group"], ticket_id=facts["ticket"]),
        ], "valid_break_glass")

        # Remaining public suppression boundaries are varied independently.
        context = make_context(rng, 600 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "identity", "oauth_device_authorized", user=facts["aliases"][0], session_id="low-risk", risk=facts["review_score"] - 1, new_device=True, source_asn=64700),
            build_event(context, 10, "api", "api_token_used", principal=facts["aliases"][1], session_id="low-risk", source_asn=64701, audience=facts["audience"]),
        ], "low_risk_device")
        context = make_context(rng, 700 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "identity", "oauth_device_authorized", user=facts["aliases"][0], session_id="late-device", risk=facts["review_score"], new_device=True, source_asn=64700),
            build_event(context, facts["device_window"] + 1, "api", "api_token_used", principal=facts["aliases"][1], session_id="late-device", source_asn=64701, audience=facts["audience"]),
        ], "late_device")
        context = make_context(rng, 800 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "ci", "secret_read", job_id=facts["job"], secret_path=facts["restricted_path"], sensitivity="ordinary"),
            build_event(context, 10, "endpoint", "artifact_upload", runner_id=facts["runner"], destination="logs.meridian.internal", bytes=facts["upload_floor"] + 100000),
        ], "corporate_egress")
        context = make_context(rng, 900 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "ci", "secret_read", job_id=facts["job"], secret_path=facts["restricted_path"], sensitivity="ordinary"),
            build_event(context, 10, "endpoint", "artifact_upload", runner_id=facts["runner"], destination="drop.example.test", bytes=facts["upload_floor"] - 1),
        ], "small_upload")
        context = make_context(rng, 1000 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "ci", "secret_read", job_id=facts["job"], secret_path=facts["restricted_path"], sensitivity="ordinary"),
            build_event(context, 10, "endpoint", "artifact_upload", runner_id=f"other-runner-{1000 + i}", destination="drop.example.test", bytes=facts["upload_floor"] + 100000),
        ], "runner_mismatch")
        context = make_context(rng, 1100 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "identity", "service_login", actor=facts["aliases"][0], account_type="human", dormant_days=facts["dormant_min"] + 20),
            build_event(context, 10, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=facts["group"]),
        ], "human_account")
        context = make_context(rng, 1200 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "identity", "service_login", actor=facts["aliases"][0], account_type=facts["service_type"], dormant_days=facts["dormant_min"] - 1),
            build_event(context, 10, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=facts["group"]),
        ], "recent_service")
        context = make_context(rng, 1300 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "identity", "service_login", actor=facts["aliases"][0], account_type=facts["service_type"], dormant_days=facts["dormant_min"] + 20),
            build_event(context, 10, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=facts["approved_group"]),
        ], "nonprivileged_role")
        context = make_context(rng, 1350 + i)
        facts = context["_facts"]
        read_target = f"target:read-role:{i}"
        context["role_targets"]["read"] = read_target
        next(e for e in context["authorization_graph"]["edges"] if e["edge_id"] == facts["role_edge"])["to"] = read_target
        read_batch, _ = commit_batch(context, 2, f"tx-read-role-{i}",
                                     [(facts["role_hop"], "activate"), (facts["role_edge"], "activate")], facts["base_version"] + 1)
        finish("benign", context, [
            build_event(context, 0, "identity", "service_login", actor=facts["aliases"][0], account_type=facts["service_type"], dormant_days=facts["dormant_min"] + 20),
            *read_batch,
            build_event(context, 10, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=facts["approved_group"], authz_version=facts["base_version"] + 1),
        ], "reachable_nonprivileged_capability")
        context = make_context(rng, 1400 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "identity", "oauth_device_authorized", user=facts["aliases"][0], session_id="generic-api", risk=facts["review_score"], new_device=True, source_asn=64700),
            build_event(context, 10, "api", "api_token_used", principal=facts["aliases"][1], session_id="generic-api", source_asn=64701, audience="metrics-read"),
        ], "unprotected_audience")
        context = make_context(rng, 1500 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "ci", "secret_read", job_id=facts["job"], secret_path=f"dev/allowed-{1500 + i}/token", sensitivity=facts["restricted_label"]),
            build_event(context, 10, "endpoint", "artifact_upload", runner_id=facts["runner"], destination="drop.example.test", bytes=facts["upload_floor"] + 100000),
        ], "permitted_secret_scope")
        context = make_context(rng, 1550 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "ci", "secret_read", job_id=facts["job"], secret_path=f"public/{i}/readme", sensitivity="ordinary"),
            build_event(context, 10, "endpoint", "artifact_upload", runner_id=facts["runner"], destination="drop.example.test", bytes=facts["upload_floor"] + 100000),
        ], "unrestricted_secret")
        context = make_context(rng, 1600 + i)
        facts = context["_facts"]
        finish("benign", context, [
            build_event(context, 0, "identity", "service_login", actor=facts["aliases"][0], account_type=facts["service_type"], dormant_days=facts["dormant_min"] + 20),
            build_event(context, 10, "api", "group_membership_changed", actor=facts["aliases"][1], member="different-principal", group=facts["group"]),
        ], "membership_target_mismatch")
        context = make_context(rng, 1700 + i)
        facts = context["_facts"]
        direct_target = f"target:direct-audience:{i}"
        context["audience_catalog"][f"direct-api-{i}"] = {"classification": facts["audience_class"]}
        context["audience_targets"][f"direct-api-{i}"] = direct_target
        direct_edge = f"direct-device-{i}"
        context["authorization_graph"]["edges"].append({"edge_id": direct_edge, "from": context["identity_nodes"][facts["principal"]], "to": direct_target, "delegated": False, "active": False})
        direct_batch, _ = commit_batch(context, 3, f"tx-direct-device-{i}", [(direct_edge, "activate")], facts["base_version"] + 1)
        finish("benign", context, [
            build_event(context, 0, "identity", "oauth_device_authorized", user=facts["aliases"][0], session_id="direct-route", risk=facts["review_score"], new_device=True, source_asn=64700),
            *direct_batch,
            build_event(context, 10, "api", "api_token_used", principal=facts["aliases"][1], session_id="direct-route", source_asn=64701, audience=f"direct-api-{i}", authz_version=facts["base_version"] + 1),
        ], "direct_authorization_route")
        context = make_context(rng, 1800 + i)
        facts = context["_facts"]
        direct_target = f"target:direct-secret:{i}"
        direct_path = facts["restricted_prefix"] + f"direct-{i}"
        context["secret_targets"][direct_path] = direct_target
        direct_edge = f"direct-secret-{i}"
        context["authorization_graph"]["edges"].append({"edge_id": direct_edge, "from": context["job_nodes"][facts["job"]], "to": direct_target, "delegated": False, "active": False})
        direct_batch, _ = commit_batch(context, -3, f"tx-direct-secret-{i}", [(direct_edge, "activate")], facts["base_version"] + 1)
        finish("benign", context, [
            build_event(context, -4, "ci", "ci_job_started", job_id=facts["job"]),
            *direct_batch,
            build_event(context, 0, "ci", "secret_read", job_id=facts["job"], secret_path=direct_path, sensitivity="ordinary", authz_version=facts["base_version"] + 1),
            build_event(context, 10, "endpoint", "artifact_upload", runner_id=facts["runner"], destination="drop.example.test", bytes=facts["upload_floor"] + 100000),
        ], "direct_secret_route")
        context = make_context(rng, 1900 + i)
        facts = context["_facts"]
        direct_target = f"target:direct-role:{i}"
        direct_group = f"direct-admin-{i}"
        context["group_roles"][direct_group] = ["cluster-admin"]
        context["role_targets"]["cluster-admin"] = direct_target
        direct_edge = f"direct-role-{i}"
        context["authorization_graph"]["edges"].append({"edge_id": direct_edge, "from": context["identity_nodes"][facts["principal"]], "to": direct_target, "delegated": False, "active": False})
        direct_batch, _ = commit_batch(context, 3, f"tx-direct-role-{i}", [(direct_edge, "activate")], facts["base_version"] + 1)
        finish("benign", context, [
            build_event(context, 0, "identity", "service_login", actor=facts["aliases"][0], account_type=facts["service_type"], dormant_days=facts["dormant_min"] + 20),
            *direct_batch,
            build_event(context, 10, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=direct_group, authz_version=facts["base_version"] + 1),
        ], "direct_role_route")

        # Versioned-policy counterfactuals. Each stream otherwise satisfies its
        # family, so transaction and snapshot semantics are decisive.
        for family_number, family in enumerate(FAMILIES):
            modes = ("preexisting", "revoked", "incomplete", "stale_snapshot",
                     "uncommitted", "invalid_version", "mismatched_commit", "net_zero",
                     "replayed_transaction", "stale_preexisting_regrant")
            for mode_number, mode in enumerate(modes):
                context = make_context(rng, 2000 + i * 30 + family_number * len(modes) + mode_number)
                facts = context["_facts"]
                hop_key = ("device_hop", "secret_hop", "role_hop")[family_number]
                edge_key = ("device_edge", "secret_edge", "role_edge")[family_number]
                hop_id, edge_id = facts[hop_key], facts[edge_key]
                authz_version = facts["base_version"] + 1
                if mode == "preexisting":
                    next(e for e in context["authorization_graph"]["edges"] if e["edge_id"] == hop_id)["active"] = True
                    next(e for e in context["authorization_graph"]["edges"] if e["edge_id"] == edge_id)["active"] = True
                    changes, _ = commit_batch(context, 2, f"tx-preexisting-{family_number}-{i}",
                                              [(facts["dead_edge"], "activate")], authz_version)
                elif mode == "revoked":
                    granted, _ = commit_batch(context, 1, f"tx-grant-{family_number}-{i}",
                                              [(hop_id, "activate"), (edge_id, "activate")], authz_version)
                    revoked, _ = commit_batch(context, 5, f"tx-revoke-{family_number}-{i}",
                                              [(edge_id, "revoke")], authz_version + 1)
                    changes, authz_version = granted + revoked, authz_version + 1
                elif mode == "incomplete":
                    changes, _ = commit_batch(context, 2, f"tx-incomplete-{family_number}-{i}",
                                              [(edge_id, "activate")], authz_version)
                elif mode == "stale_snapshot":
                    changes, _ = commit_batch(context, 1, f"tx-stale-{family_number}-{i}",
                                              [(hop_id, "activate"), (edge_id, "activate")], authz_version)
                    authz_version = facts["base_version"]
                elif mode == "uncommitted":
                    transaction = f"tx-abandoned-{family_number}-{i}"
                    changes = [
                        build_event(context, 2, "policy", "authorization_edge_changed", transaction_id=transaction, edge_id=hop_id, action="activate"),
                        build_event(context, 3, "policy", "authorization_edge_changed", transaction_id=transaction, edge_id=edge_id, action="activate"),
                    ]
                    authz_version = facts["base_version"]
                elif mode == "invalid_version":
                    transaction = f"tx-invalid-version-{family_number}-{i}"
                    changes = [
                        build_event(context, 2, "policy", "authorization_edge_changed", transaction_id=transaction, edge_id=hop_id, action="activate"),
                        build_event(context, 3, "policy", "authorization_edge_changed", transaction_id=transaction, edge_id=edge_id, action="activate"),
                        build_event(context, 4, "policy", "authorization_policy_committed", transaction_id=transaction, policy_version=facts["base_version"]),
                    ]
                    authz_version = facts["base_version"]
                elif mode == "mismatched_commit":
                    transaction = f"tx-mismatch-staged-{family_number}-{i}"
                    changes = [
                        build_event(context, 2, "policy", "authorization_edge_changed", transaction_id=transaction, edge_id=hop_id, action="activate"),
                        build_event(context, 3, "policy", "authorization_edge_changed", transaction_id=transaction, edge_id=edge_id, action="activate"),
                        build_event(context, 4, "policy", "authorization_policy_committed", transaction_id=f"tx-mismatch-commit-{family_number}-{i}", policy_version=facts["base_version"] + 1),
                    ]
                    authz_version = facts["base_version"]
                elif mode == "net_zero":
                    changes, _ = commit_batch(context, 1, f"tx-net-zero-{family_number}-{i}",
                                              [(hop_id, "activate"), (edge_id, "activate"), (edge_id, "revoke")],
                                              authz_version)
                elif mode == "replayed_transaction":
                    transaction = f"tx-consumed-{family_number}-{i}"
                    granted, _ = commit_batch(context, 1, transaction,
                                              [(hop_id, "activate"), (edge_id, "activate")], authz_version)
                    revoked, _ = commit_batch(context, 4, f"tx-revoke-consumed-{family_number}-{i}",
                                              [(edge_id, "revoke")], authz_version + 1)
                    replay = build_event(context, 7, "policy", "authorization_policy_committed",
                                         transaction_id=transaction, policy_version=authz_version + 2)
                    changes, authz_version = granted + revoked + [replay], authz_version + 2
                else:
                    next(e for e in context["authorization_graph"]["edges"] if e["edge_id"] == hop_id)["active"] = True
                    next(e for e in context["authorization_graph"]["edges"] if e["edge_id"] == edge_id)["active"] = True
                    revoked, _ = commit_batch(context, 1, f"tx-stale-revoke-{family_number}-{i}",
                                              [(edge_id, "revoke")], authz_version)
                    regranted, _ = commit_batch(context, 4, f"tx-stale-regrant-{family_number}-{i}",
                                                [(edge_id, "activate")], authz_version + 1)
                    changes, authz_version = revoked + regranted, facts["base_version"]

                if family == "device_code_takeover":
                    events = [
                        build_event(context, 0, "identity", "oauth_device_authorized", user=facts["aliases"][0], session_id=f"transition-device-{i}", risk=facts["review_score"] + 5, new_device=True, source_asn=64700),
                        *changes,
                        build_event(context, 10, "api", "api_token_used", principal=facts["aliases"][1], session_id=f"transition-device-{i}", source_asn=64701, audience=facts["audience"], authz_version=authz_version),
                    ]
                elif family == "ci_secret_exfil":
                    events = [
                        build_event(context, 0, "ci", "ci_job_started", job_id=facts["job"]),
                        *changes,
                        build_event(context, 8, "ci", "secret_read", job_id=facts["job"], secret_path=facts["restricted_path"], sensitivity="ordinary", authz_version=authz_version),
                        build_event(context, 12, "endpoint", "artifact_upload", runner_id=facts["runner"], destination="drop.example.test", bytes=facts["upload_floor"] + 100000),
                    ]
                else:
                    events = [
                        build_event(context, 0, "identity", "service_login", actor=facts["aliases"][0], account_type=facts["service_type"], dormant_days=facts["dormant_min"] + 20),
                        *changes,
                        build_event(context, 10, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=facts["group"], authz_version=authz_version),
                    ]
                finish("benign", context, events, f"transition_{mode}_{family}")

        context = make_context(rng, 2900 + i)
        facts = context["_facts"]
        grant_events, _ = commit_batch(context, 2, f"tx-zero-upload-{i}",
                                       [(facts["secret_hop"], "activate"), (facts["secret_edge"], "activate")],
                                       facts["base_version"] + 1)
        finish("benign", context, [
            build_event(context, 0, "ci", "ci_job_started", job_id=facts["job"]),
            *grant_events,
            build_event(context, 8, "ci", "secret_read", job_id=facts["job"], secret_path=facts["restricted_path"], sensitivity="ordinary", authz_version=facts["base_version"] + 1),
            build_event(context, 8, "endpoint", "artifact_upload", runner_id=facts["runner"], destination="drop.example.test", bytes=facts["upload_floor"] + 100000),
        ], "transition_simultaneous_read_upload")

        # The evidence-bearing commit is the grant that survives in the exact
        # operation snapshot, not an earlier grant later revoked.
        for family_number, family in enumerate(FAMILIES):
            context = make_context(rng, 4000 + i * len(FAMILIES) + family_number)
            facts = context["_facts"]
            hop_id = facts[("device_hop", "secret_hop", "role_hop")[family_number]]
            edge_id = facts[("device_edge", "secret_edge", "role_edge")[family_number]]
            first_grant, _ = commit_batch(context, 1, f"tx-first-grant-{family_number}-{i}",
                                          [(hop_id, "activate"), (edge_id, "activate")],
                                          facts["base_version"] + 1)
            revoked, _ = commit_batch(context, 4, f"tx-middle-revoke-{family_number}-{i}",
                                      [(edge_id, "revoke")], facts["base_version"] + 2)
            surviving, surviving_grant = commit_batch(context, 6, f"tx-surviving-grant-{family_number}-{i}",
                                                       [(edge_id, "activate")], facts["base_version"] + 3)
            changes = first_grant + revoked + surviving
            if family == "device_code_takeover":
                events = [
                    build_event(context, 0, "identity", "oauth_device_authorized", user=facts["aliases"][0], session_id=f"surviving-device-{i}", risk=facts["review_score"] + 5, new_device=True, source_asn=64700),
                    *changes,
                    build_event(context, 10, "api", "api_token_used", principal=facts["aliases"][1], session_id=f"surviving-device-{i}", source_asn=64701, audience=facts["audience"], authz_version=facts["base_version"] + 3),
                ]
            elif family == "ci_secret_exfil":
                events = [
                    build_event(context, 0, "ci", "ci_job_started", job_id=facts["job"]),
                    *changes,
                    build_event(context, 10, "ci", "secret_read", job_id=facts["job"], secret_path=facts["restricted_path"], sensitivity="ordinary", authz_version=facts["base_version"] + 3),
                    build_event(context, 12, "endpoint", "artifact_upload", runner_id=facts["runner"], destination="drop.example.test", bytes=facts["upload_floor"] + 100000),
                ]
            else:
                events = [
                    build_event(context, 0, "identity", "service_login", actor=facts["aliases"][0], account_type=facts["service_type"], dormant_days=facts["dormant_min"] + 20),
                    *changes,
                    build_event(context, 10, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=facts["group"], authz_version=facts["base_version"] + 3),
                ]
            finish(family, context, events, "surviving_regrant", surviving_grant["event_id"])

        context = make_context(rng, 3000 + i)
        facts = context["_facts"]
        secret_events, secret_grant = commit_batch(context, 2, f"tx-mixed-secret-{i}",
                                                    [(facts["secret_hop"], "activate"), (facts["secret_edge"], "activate")], facts["base_version"] + 1)
        device_events, device_grant = commit_batch(context, 5, f"tx-mixed-device-{i}",
                                                    [(facts["device_hop"], "activate"), (facts["device_edge"], "activate")], facts["base_version"] + 2)
        role_events, role_grant = commit_batch(context, 8, f"tx-mixed-role-{i}",
                                               [(facts["role_hop"], "activate"), (facts["role_edge"], "activate")], facts["base_version"] + 3)
        events = [
            build_event(context, 0, "identity", "oauth_device_authorized", user=facts["aliases"][0], session_id=f"mixed-device-{i}", risk=facts["review_score"] + 5, new_device=True, source_asn=64700),
            build_event(context, 2, "api", "api_token_used", principal=facts["aliases"][1], session_id=f"wrong-session-{i}", source_asn=64701, audience=facts["audience"], authz_version=facts["base_version"]),
            *device_events,
            build_event(context, 20, "api", "api_token_used", principal=facts["aliases"][1], session_id=f"mixed-device-{i}", source_asn=64701, audience=facts["audience"], authz_version=facts["base_version"] + 3),
            build_event(context, 0, "ci", "ci_job_started", job_id=facts["job"]),
            *secret_events,
            build_event(context, 12, "ci", "secret_read", job_id=facts["job"], secret_path=facts["restricted_path"], sensitivity="ordinary", authz_version=facts["base_version"] + 2),
            build_event(context, 14, "endpoint", "artifact_upload", runner_id=f"other-runner-{3000 + i}", destination="decoy.example.test", bytes=facts["upload_floor"] + 200000),
            build_event(context, 22, "endpoint", "artifact_upload", runner_id=facts["runner"], destination="drop.example.test", bytes=facts["upload_floor"] + 100000),
            build_event(context, 0, "identity", "service_login", actor=facts["aliases"][0], account_type=facts["service_type"], dormant_days=facts["dormant_min"] + 20),
            *role_events,
            build_event(context, 4, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=facts["approved_group"], authz_version=facts["base_version"]),
            build_event(context, 25, "api", "group_membership_changed", actor=facts["aliases"][1], member=facts["aliases"][0], group=facts["group"], authz_version=facts["base_version"] + 3),
            build_event(context, 1, "policy", "authorization_edge_changed", transaction_id=f"abandoned-mixed-{i}", edge_id=facts["dead_edge"], action="activate"),
        ]
        finish(FAMILIES, context, events, "mixed_incidents", {
            FAMILIES[0]: device_grant["event_id"],
            FAMILIES[1]: secret_grant["event_id"],
            FAMILIES[2]: role_grant["event_id"],
        })
    return scenarios


def load_detector():
    try:
        spec = importlib.util.spec_from_file_location("candidate_detector", APP / "detector.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module if callable(getattr(module, "detect", None)) else None, ""
    except Exception as exc:
        return None, repr(exc)


def grade():
    details, score = {}, 0.0
    module, error = load_detector()
    score += metric(details, "detector_import_and_contract", 0.05, module is not None, error)
    if not module:
        return round(score, 4), details
    context_path = APP / "data" / "organization_context.json"
    original_context = context_path.read_bytes()
    counts = {family: {"tp": 0, "fp": 0, "fn": 0} for family in FAMILIES}
    benign_total = benign_clean = evidence_total = evidence_good = robust_total = robust_hits = 0
    try:
        for scenario in generate():
            context_path.write_text(json.dumps(scenario["context"]))
            try:
                alerts = module.detect([dict(event) for event in scenario["events"]])
                if not isinstance(alerts, list):
                    raise TypeError("detect must return a list")
            except Exception:
                alerts = []
            valid = [alert for alert in alerts if isinstance(alert, dict) and alert.get("family") in FAMILIES]
            predicted = {alert["family"] for alert in valid}
            expected = set(scenario["labels"])
            for family in FAMILIES:
                counts[family]["tp"] += int(family in expected and family in predicted)
                counts[family]["fp"] += int(family not in expected and family in predicted)
                counts[family]["fn"] += int(family in expected and family not in predicted)
            if not expected:
                benign_total += 1
                benign_clean += int(not predicted)
                continue
            if scenario["variant"] == "optional_missing":
                robust_total += 1
                robust_hits += int(expected.issubset(predicted))
            for expected_family in expected:
                matching = next((alert for alert in valid if alert["family"] == expected_family), None)
                if matching:
                    evidence_total += 1
                    by_id = {event.get("event_id"): event for event in scenario["events"] if isinstance(event, dict)}
                    ids = matching.get("evidence_event_ids", [])
                    chosen = [by_id[item] for item in ids if item in by_id]
                    summary = matching.get("summary")
                    evidence_good += int(
                        len(ids) == len(set(ids))
                        and ESSENTIAL[expected_family].issubset({event.get("event_type") for event in chosen})
                        and scenario.get("causal_grant_ids", {}).get(expected_family) in ids
                        and isinstance(summary, str) and len(summary.strip()) >= 25
                    )
    finally:
        context_path.write_bytes(original_context)
    f1s = {family: f1(counts[family]) for family in FAMILIES}
    for family in FAMILIES:
        score += metric(details, f"{family}_f1", 0.19, f1s[family], str(counts[family]))
    specificity = benign_clean / max(1, benign_total)
    score += metric(details, "semantic_boundary_specificity", 0.18, specificity, f"clean={benign_clean}/{benign_total}")
    score += metric(details, "evidence_quality", 0.10, evidence_good / max(1, evidence_total), f"good={evidence_good}/{evidence_total}")
    score += metric(details, "optional_telemetry_robustness", 0.10, robust_hits / max(1, robust_total), f"hits={robust_hits}/{robust_total}")
    if min(f1s.values()) < 0.70 or specificity < 0.80:
        score = min(score, 0.74)
    return round(min(score, 1.0), 4), details


score, details = grade()
(LOG / "reward.txt").write_text(f"{score}\n")
(LOG / "reward.json").write_text(json.dumps({"reward": score}, indent=2) + "\n")
(LOG / "details.json").write_text(json.dumps(details, indent=2, sort_keys=True) + "\n")
print(json.dumps({"reward": score, "details": details}, indent=2, sort_keys=True))

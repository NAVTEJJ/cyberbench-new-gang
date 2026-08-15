#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


APP = Path(os.environ.get("APP_DIR", "/app"))
LOG = Path(os.environ.get("LOG_DIR", "/logs/verifier"))
LOG.mkdir(parents=True, exist_ok=True)
EXPECTED_ASSETS = json.loads(Path(__file__).with_name("expected_assets.json").read_text())
sys.path.insert(0, str(APP / "tools"))
from artifact_recipe import reproduce_source

WEIGHTS = {
    "task_material_immutable": 0.05,
    "incident_report_shape": 0.05,
    "conditional_policy_anomaly": 0.10,
    "compromised_artifact_identification": 0.10,
    "source_generated_artifact_divergence": 0.15,
    "dependency_reachability": 0.10,
    "activation_conditions": 0.075,
    "behavioral_effect": 0.075,
    "candidate_elimination": 0.10,
    "causal_reconstruction": 0.15,
    "evidence_quality": 0.05,
}


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def read_jsonl(path: Path) -> list[dict]:
    try:
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    except Exception:
        return []


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def add(details: dict, name: str, passed: bool, evidence: str = "") -> float:
    weight = WEIGHTS[name]
    details[name] = {"weight": weight, "passed": bool(passed), "evidence": evidence}
    return weight if passed else 0.0


def policy_violations(run: dict, policy: dict) -> list[str]:
    violations = []
    for rule in policy.get("rules", []):
        if rule.get("component") != run.get("component") or rule.get("extension_group") != run.get("group"):
            continue
        output = run.get("output", {})
        denied = sorted(set(output.get("capabilities", [])) & set(rule.get("denied_capabilities", [])))
        if denied:
            violations.append("capabilities=" + ",".join(denied))
        if output.get("sink") in rule.get("denied_sinks", []):
            violations.append("sink=" + str(output.get("sink")))
    return violations


def dependency_path(component: str, target: str, lock_items: list[dict]) -> list[str] | None:
    manifest = read_json(APP / "workspace" / "manifest.json") or {}
    selected = {item.get("name"): item.get("version") for item in lock_items if isinstance(item, dict)}

    def dependencies(name: str) -> dict:
        component_spec = manifest.get("components", {}).get(name)
        if isinstance(component_spec, dict):
            return component_spec.get("dependencies", {})
        metadata = read_json(APP / "registry" / name / str(selected.get(name)) / "metadata.json") or {}
        return metadata.get("dependencies", {})

    def walk(node: str, path: list[str]) -> list[str] | None:
        if node == target:
            return path
        for child in dependencies(node):
            if child in path:
                continue
            found = walk(child, [*path, child])
            if found:
                return found
        return None

    return walk(component, [component])


def valid_submitted_path(path: object, component: str, target: str, lock_items: list[dict]) -> bool:
    if (
        not isinstance(path, list)
        or len(path) < 2
        or path[0] != component
        or path[-1] != target
        or len(path) != len(set(path))
        or not all(isinstance(item, str) and item for item in path)
    ):
        return False
    manifest = read_json(APP / "workspace" / "manifest.json") or {}
    selected = {item.get("name"): item.get("version") for item in lock_items if isinstance(item, dict)}

    def dependencies(name: str) -> dict:
        component_spec = manifest.get("components", {}).get(name)
        if isinstance(component_spec, dict):
            return component_spec.get("dependencies", {})
        metadata = read_json(APP / "registry" / name / str(selected.get(name)) / "metadata.json") or {}
        return metadata.get("dependencies", {})

    return all(child in dependencies(parent) for parent, child in zip(path, path[1:]))


def ordered_subsequence(expected: list[str], submitted: list[str]) -> bool:
    iterator = iter(submitted)
    return all(any(candidate == item for candidate in iterator) for item in expected)


def normalize_app_path(value: object) -> str | None:
    """Return a canonical path relative to /app, rejecting paths outside it."""
    if not isinstance(value, str) or not value:
        return None
    path = Path(value)
    if path.is_absolute():
        for root in (Path("/app"), APP):
            try:
                path = path.relative_to(root)
                break
            except ValueError:
                continue
        else:
            return None
    if not path.parts or any(part == ".." for part in path.parts):
        return None
    return path.as_posix()


def mapping_matches_with_app_paths(
    submitted: object,
    expected: dict,
    path_fields: set[str],
) -> bool:
    if not isinstance(submitted, dict) or set(submitted) != set(expected):
        return False
    for field, expected_value in expected.items():
        submitted_value = submitted.get(field)
        if field in path_fields:
            if normalize_app_path(submitted_value) != normalize_app_path(expected_value):
                return False
        elif submitted_value != expected_value:
            return False
    return True


def grade():
    details = {}
    score = 0.0

    changed = []
    for relative, expected_hash in EXPECTED_ASSETS.items():
        path = APP / relative
        if not path.is_file() or digest(path) != expected_hash:
            changed.append(relative)
    protected_roots = ["registry", "source_snapshots", "generated_intermediates", "evidence", "trust", "transparency", "reference", "tools"]
    expected_paths = set(EXPECTED_ASSETS)
    extra = []
    for root in protected_roots:
        for path in (APP / root).glob("**/*"):
            relative = str(path.relative_to(APP))
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            if path.is_file() and relative not in expected_paths:
                extra.append(relative)
    immutable = not changed and not extra
    score += add(details, "task_material_immutable", immutable, f"changed={changed} extra={extra}")

    report = read_json(APP / "incident_report.json") or {}
    artifact = report.get("artifact", {}) if isinstance(report, dict) else {}
    baseline = report.get("source_baseline", {}) if isinstance(report, dict) else {}
    intermediate = report.get("generated_intermediate", {}) if isinstance(report, dict) else {}
    activation = report.get("activation", {}) if isinstance(report, dict) else {}
    behavior = report.get("behavior", {}) if isinstance(report, dict) else {}
    chain = report.get("causal_chain", []) if isinstance(report, dict) else []
    evidence_items = report.get("evidence", []) if isinstance(report, dict) else []
    candidate_assessments = report.get("candidate_assessments", []) if isinstance(report, dict) else []
    shape_ok = (
        report.get("verdict") in {"compromised", "clean"}
        and isinstance(artifact, dict)
        and all(isinstance(artifact.get(field), str) and artifact[field] for field in ("name", "version", "artifact_sha256", "attestation_id"))
        and isinstance(baseline, dict)
        and all(
            isinstance(baseline.get(field), str) and baseline[field]
            for field in ("revision", "path", "source_sha256", "reproduced_artifact_sha256")
        )
        and isinstance(baseline.get("reproducible_match"), bool)
        and isinstance(intermediate, dict)
        and all(
            isinstance(intermediate.get(field), str) and intermediate[field]
            for field in ("clean_path", "clean_sha256", "composed_path", "composed_sha256", "selector")
        )
        and isinstance(intermediate.get("offset"), int)
        and isinstance(report.get("entry_path"), list)
        and isinstance(activation, dict)
        and all(isinstance(activation.get(field), str) and activation[field] for field in ("build_mode", "component", "stage", "extension_target"))
        and isinstance(behavior, dict)
        and all(isinstance(behavior.get(field), str) and behavior[field] for field in ("declared_profile", "observed_profile", "sink"))
        and isinstance(behavior.get("capabilities"), list)
        and isinstance(report.get("injection_event"), str)
        and isinstance(chain, list) and chain and all(isinstance(item, str) and item for item in chain)
        and isinstance(candidate_assessments, list) and candidate_assessments
        and isinstance(evidence_items, list) and evidence_items
        and isinstance(report.get("summary"), str) and bool(report["summary"].strip())
    )
    score += add(details, "incident_report_shape", shape_ok)

    lock = read_json(APP / "workspace" / "lock.json") or {}
    lock_items = lock.get("packages", []) if isinstance(lock, dict) else []
    metadata = []
    for item in lock_items:
        value = read_json(APP / "registry" / str(item.get("name")) / str(item.get("version")) / "metadata.json")
        if value:
            metadata.append(value)
    build_plan = read_json(APP / "workspace" / "build_plan.json") or {}
    catalog = read_json(APP / "workspace" / "extension_catalog.json") or {}
    policy = read_json(APP / "trust" / "capability_policy.json") or {}
    scenarios = read_json(APP / "workspace" / "build_scenarios.json") or {}

    scenario_violations = {}
    scenario_error = ""
    for scenario_name in scenarios.get("scenarios", {}):
        try:
            result = subprocess.run(
                [sys.executable, str(APP / "tools" / "build.py"), "--app", str(APP), "--scenario", scenario_name],
                check=True,
                capture_output=True,
                text=True,
            )
            del result
            build_manifest = read_json(APP / "workspace" / "build_manifest.json") or {}
            scenario_violations[scenario_name] = [
                run for run in build_manifest.get("extension_runs", []) if policy_violations(run, policy)
            ]
        except Exception as error:
            scenario_error = repr(error)
            scenario_violations[scenario_name] = []
    violating_scenarios = {name: runs for name, runs in scenario_violations.items() if runs}
    isolated_anomaly = (
        not scenario_error
        and set(violating_scenarios) == {"quarantined-release"}
        and len(violating_scenarios["quarantined-release"]) == 1
    )
    violating_run = violating_scenarios.get("quarantined-release", [{}])[0] if isolated_anomaly else {}
    score += add(
        details,
        "conditional_policy_anomaly",
        isolated_anomaly,
        f"violating_scenarios={sorted(violating_scenarios)} error={scenario_error}",
    )

    binding_id = build_plan.get("dispatcher", {}).get("binding")
    bindings = [item for item in catalog.get("bindings", []) if item.get("binding_id") == binding_id]
    dispatcher_candidates = []
    if len(bindings) == 1:
        provider = bindings[0].get("provider")
        dispatcher_candidates = [item for item in metadata if provider in item.get("provides", [])]
    dispatcher = dispatcher_candidates[0] if len(dispatcher_candidates) == 1 else {}
    dispatcher_item = next((item for item in lock_items if item.get("name") == dispatcher.get("name")), {})
    artifact_path = APP / "registry" / str(dispatcher_item.get("name")) / str(dispatcher_item.get("version")) / "package.py"
    artifact_sha256 = digest(artifact_path) if artifact_path.is_file() else ""
    expected_artifact = {
        "name": dispatcher_item.get("name"),
        "version": dispatcher_item.get("version"),
        "artifact_sha256": artifact_sha256,
        "attestation_id": dispatcher_item.get("attestation_id"),
    }
    artifact_ok = report.get("verdict") == "compromised" and artifact == expected_artifact
    score += add(details, "compromised_artifact_identification", artifact_ok, f"expected={expected_artifact}")

    pipeline = read_jsonl(APP / "evidence" / "release_pipeline.jsonl")
    source_events = read_jsonl(APP / "evidence" / "source_archive.jsonl")
    emits = [event for event in pipeline if event.get("kind") == "package.emit" and event.get("artifact_sha256") == artifact_sha256]
    emit = emits[0] if len(emits) == 1 else {}
    checkouts = [event for event in pipeline if event.get("kind") == "source.checkout" and event.get("build_id") == emit.get("build_id")]
    checkout = checkouts[0] if len(checkouts) == 1 else {}
    sources = [event for event in source_events if event.get("revision") == checkout.get("revision")]
    source = sources[0] if len(sources) == 1 else {}
    source_path = APP / str(source.get("blob_path", ""))
    source_sha256 = digest(source_path) if source_path.is_file() else ""
    recipes = read_json(APP / "workspace" / "artifact_recipes.json") or {}
    recipe = recipes.get("recipes", {}).get(str(checkout.get("revision")), {})
    reproduced_artifact_sha256 = (
        hashlib.sha256(reproduce_source(APP, source_path, recipe)).hexdigest()
        if source_path.is_file() and recipe
        else ""
    )
    clean_capture_path = APP / str(recipe.get("generated_capture", ""))
    composed_capture_path = APP / str(recipe.get("composed_capture", ""))
    clean_capture_sha256 = digest(clean_capture_path) if clean_capture_path.is_file() else ""
    composed_capture_sha256 = digest(composed_capture_path) if composed_capture_path.is_file() else ""
    composed_rows_document = read_json(composed_capture_path) or {}
    composed_rows = composed_rows_document.get("rows", [])
    composed_reproduction_sha256 = (
        hashlib.sha256(
            reproduce_source(APP, source_path, recipe, str(recipe.get("composed_capture")))
        ).hexdigest()
        if source_path.is_file() and recipe.get("composed_capture")
        else ""
    )
    expected_baseline = {
        "revision": checkout.get("revision"),
        "path": source.get("blob_path"),
        "source_sha256": source_sha256,
        "reproduced_artifact_sha256": reproduced_artifact_sha256,
        "reproducible_match": False,
    }
    route_row = composed_rows[0] if len(composed_rows) == 1 else {}
    expected_intermediate = {
        "clean_path": recipe.get("generated_capture"),
        "clean_sha256": clean_capture_sha256,
        "composed_path": recipe.get("composed_capture"),
        "composed_sha256": composed_capture_sha256,
        "selector": route_row.get("selector"),
        "offset": route_row.get("offset"),
    }
    divergence_ok = (
        mapping_matches_with_app_paths(baseline, expected_baseline, {"path"})
        and mapping_matches_with_app_paths(
            intermediate,
            expected_intermediate,
            {"clean_path", "composed_path"},
        )
        and source.get("blob_sha256") == source_sha256
        and bool(source_sha256)
        and bool(reproduced_artifact_sha256)
        and reproduced_artifact_sha256 != artifact_sha256
        and composed_reproduction_sha256 == artifact_sha256
        and clean_capture_sha256 != composed_capture_sha256
    )
    score += add(
        details,
        "source_generated_artifact_divergence",
        divergence_ok,
        f"source={source_sha256} reproduced={reproduced_artifact_sha256} composed={composed_reproduction_sha256} artifact={artifact_sha256} intermediate={intermediate}",
    )

    expected_path = dependency_path(str(violating_run.get("component", "")), str(dispatcher.get("name", "")), lock_items)
    path_ok = valid_submitted_path(
        report.get("entry_path"),
        str(violating_run.get("component", "")),
        str(dispatcher.get("name", "")),
        lock_items,
    )
    score += add(
        details,
        "dependency_reachability",
        path_ok,
        f"submitted_path={report.get('entry_path')} example_path={expected_path}",
    )

    expected_activation = {
        "build_mode": violating_run.get("build_mode"),
        "component": violating_run.get("component"),
        "stage": violating_run.get("stage"),
        "extension_target": violating_run.get("target"),
    }
    activation_ok = activation == expected_activation
    score += add(details, "activation_conditions", activation_ok, f"expected={expected_activation}")

    declared = {}
    if violating_run:
        entries = [item for item in catalog.get("extensions", []) if item.get("extension_id") == violating_run.get("extension_id")]
        if len(entries) == 1:
            entry = entries[0]
            owners = [item for item in metadata if item.get("source_sha256") == entry.get("source_sha256")]
            if len(owners) == 1:
                owner = owners[0]
                owner_path = APP / "registry" / owner["name"] / owner["version"] / "package.py"
                vendor = APP / "workspace" / "vendor"
                sys.path.insert(0, str(vendor))
                namespace = {}
                try:
                    exec(compile(owner_path.read_text(), str(owner_path), "exec"), namespace)
                    profiles = read_json(APP / "workspace" / "build_profiles.json").get("profiles", {})

                    def select_profile(name: str) -> dict:
                        profile = profiles[name]
                        return {"profile": name, "capabilities": sorted(profile["capabilities"]), "sink": profile["sink"]}

                    declared = namespace[entry["target"].split(":", 1)[1]]({"select_profile": select_profile})
                finally:
                    sys.path.remove(str(vendor))
                    for module_name in ["locale_data", "metrics_exporter"]:
                        sys.modules.pop(module_name, None)
    observed = violating_run.get("output", {})
    expected_behavior = {
        "declared_profile": declared.get("profile"),
        "observed_profile": observed.get("profile"),
        "capabilities": observed.get("capabilities"),
        "sink": observed.get("sink"),
    }
    behavior_ok = behavior == expected_behavior and declared.get("profile") != observed.get("profile")
    score += add(details, "behavioral_effect", behavior_ok, f"expected={expected_behavior}")

    change_control = read_jsonl(APP / "evidence" / "change_control.jsonl")
    artifact_store = read_jsonl(APP / "evidence" / "artifact_store.jsonl")
    resolver = read_jsonl(APP / "evidence" / "resolver.jsonl")
    lock_events = read_jsonl(APP / "evidence" / "lock_service.jsonl")
    worker_events = read_jsonl(APP / "evidence" / "build_workers.jsonl")
    candidate_flags = read_jsonl(APP / "evidence" / "integrity_findings.jsonl")
    approved = {event.get("object_id") for event in change_control if event.get("kind") == "layer.approved"}
    coordinate = f"{dispatcher_item.get('name')}@{dispatcher_item.get('version')}"

    def one(events: list[dict]) -> dict:
        return events[0] if len(events) == 1 else {}

    def candidate_flag(candidate_id: str) -> dict:
        return one([item for item in candidate_flags if item.get("candidate_id") == candidate_id])

    metrics_item = next((item for item in lock_items if item.get("name") == "metrics-exporter"), {})
    metrics_digest = str(metrics_item.get("source_sha256", ""))
    metrics_emit = one([event for event in pipeline if event.get("kind") == "package.emit" and event.get("artifact_sha256") == metrics_digest])
    metrics_checkout = one([event for event in pipeline if event.get("kind") == "source.checkout" and event.get("build_id") == metrics_emit.get("build_id")])
    metrics_compose = one([event for event in pipeline if event.get("kind") == "workspace.compose" and event.get("build_id") == metrics_emit.get("build_id")])
    metrics_unauthorized = [
        value for value in metrics_compose.get("layers", [])
        if value != metrics_checkout.get("revision") and value not in approved
    ]
    metrics_layer = one([
        event for event in pipeline
        if event.get("kind") == "workspace.layer" and event.get("object_id") in metrics_unauthorized
    ])
    metrics_promotion = one([
        event for event in artifact_store
        if event.get("kind") == "artifact.promote" and event.get("artifact_sha256") == metrics_digest
    ])
    metrics_lock = one([event for event in lock_events if event.get("digest") == metrics_digest])

    shadow_path = APP / "registry" / "text-normalizer" / "2.4.6" / "package.py"
    shadow_digest = digest(shadow_path) if shadow_path.is_file() else ""
    shadow_promotion = one([
        event for event in artifact_store
        if event.get("kind") == "artifact.promote" and event.get("artifact_sha256") == shadow_digest
    ])
    trial_layer = one([
        event for event in pipeline
        if event.get("kind") == "workspace.layer" and event.get("workspace_id") == "ws-trial-04"
    ])
    trial_discard = one([
        event for event in pipeline
        if event.get("kind") == "workspace.discard" and event.get("workspace_id") == "ws-trial-04"
    ])
    report_item = next((item for item in lock_items if item.get("name") == "report-kit"), {})
    report_emit = one([
        event for event in pipeline
        if event.get("kind") == "package.emit" and event.get("artifact_sha256") == report_item.get("source_sha256")
    ])
    report_checkout = one([
        event for event in pipeline
        if event.get("kind") == "source.checkout" and event.get("build_id") == report_emit.get("build_id")
    ])

    metrics_source_event = one([
        event for event in source_events if event.get("revision") == metrics_checkout.get("revision")
    ])
    metrics_recipe = recipes.get("recipes", {}).get(str(metrics_checkout.get("revision")), {})
    metrics_source_path = APP / str(metrics_source_event.get("blob_path", ""))
    metrics_reproduced = (
        hashlib.sha256(reproduce_source(APP, metrics_source_path, metrics_recipe)).hexdigest()
        if metrics_source_path.is_file() and metrics_recipe
        else ""
    )
    report_source_event = one([
        event for event in source_events if event.get("revision") == report_checkout.get("revision")
    ])
    report_recipe = recipes.get("recipes", {}).get(str(report_checkout.get("revision")), {})
    report_source_path = APP / str(report_source_event.get("blob_path", ""))
    report_reproduced = (
        hashlib.sha256(reproduce_source(APP, report_source_path, report_recipe)).hexdigest()
        if report_source_path.is_file() and report_recipe
        else ""
    )
    candidate_facts_ok = (
        len(metrics_unauthorized) == 1
        and metrics_reproduced != metrics_digest
        and bool(metrics_promotion)
        and metrics_lock.get("component") == "analytics-worker"
        and dependency_path("report-service", "metrics-exporter", lock_items) is None
        and bool(shadow_promotion)
        and not any(
            item.get("name") == "text-normalizer" and item.get("version") == "2.4.6"
            for item in lock_items
        )
        and bool(trial_discard)
        and not any(event.get("kind") == "package.emit" and event.get("build_id") == "trial-04" for event in pipeline)
        and report_reproduced == report_item.get("source_sha256")
        and dependency_path("report-service", "report-kit", lock_items) is not None
    )

    candidate_expectations = {
        "cand-pl-route": {
            "subject": coordinate,
            "disposition": "causal",
            "promoted": True,
            "selected": True,
            "reachable_from_affected_component": True,
            "activated_in_observed_event": True,
        },
        "cand-me-observer": {
            "subject": "metrics-exporter@1.2.0",
            "disposition": "unrelated-component",
            "promoted": True,
            "selected": True,
            "reachable_from_affected_component": False,
            "activated_in_observed_event": False,
        },
        "cand-tn-246": {
            "subject": "text-normalizer@2.4.6",
            "disposition": "not-selected",
            "promoted": True,
            "selected": False,
            "reachable_from_affected_component": False,
            "activated_in_observed_event": False,
        },
        "cand-trial-04": {
            "subject": "trial-04",
            "disposition": "discarded",
            "promoted": False,
            "selected": False,
            "reachable_from_affected_component": False,
            "activated_in_observed_event": False,
        },
        "cand-rk-transform": {
            "subject": "report-kit@1.8.0",
            "disposition": "recipe-reproducible",
            "promoted": True,
            "selected": True,
            "reachable_from_affected_component": True,
            "activated_in_observed_event": False,
        },
    }
    composes = [event for event in pipeline if event.get("kind") == "workspace.compose" and event.get("build_id") == emit.get("build_id")]
    compose = composes[0] if len(composes) == 1 else {}
    unauthorized = [layer for layer in compose.get("layers", []) if layer != checkout.get("revision") and layer not in approved]
    layer_events = [
        event for event in pipeline
        if event.get("kind") == "workspace.layer"
        and event.get("workspace_id") == checkout.get("workspace_id")
        and event.get("object_id") in unauthorized
    ]
    layer = layer_events[0] if len(layer_events) == 1 else {}
    generator_layers = [
        event for event in pipeline
        if event.get("kind") == "workspace.layer"
        and event.get("workspace_id") == checkout.get("workspace_id")
        and event.get("object_id") in approved
    ]
    generator_layer = generator_layers[0] if len(generator_layers) == 1 else {}
    generate_events = [
        event for event in pipeline
        if event.get("kind") == "intermediate.generate"
        and event.get("build_id") == emit.get("build_id")
        and event.get("intermediate_sha256") == clean_capture_sha256
    ]
    generate_event = generate_events[0] if len(generate_events) == 1 else {}
    mutate_events = [
        event for event in pipeline
        if event.get("kind") == "intermediate.mutate"
        and event.get("build_id") == emit.get("build_id")
        and event.get("object_id") == layer.get("object_id")
        and event.get("intermediate_sha256") == composed_capture_sha256
    ]
    mutate_event = mutate_events[0] if len(mutate_events) == 1 else {}
    attest_events = [event for event in artifact_store if event.get("kind") == "attestation.record" and event.get("artifact_sha256") == artifact_sha256]
    promote_events = [event for event in artifact_store if event.get("kind") == "artifact.promote" and event.get("artifact_sha256") == artifact_sha256]
    coordinate = f"{dispatcher_item.get('name')}@{dispatcher_item.get('version')}"
    resolver_reads = [event for event in resolver if event.get("kind") == "index.read" and event.get("coordinate") == coordinate and event.get("digest") == artifact_sha256]
    resolver_read = resolver_reads[0] if len(resolver_reads) == 1 else {}
    resolver_edges = [event for event in resolver if event.get("kind") == "resolver.edge" and event.get("request_id") == resolver_read.get("request_id")]
    selected_lock_events = [event for event in lock_events if event.get("request_id") == resolver_read.get("request_id") and event.get("digest") == artifact_sha256]
    dispatch_events = [event for event in worker_events if event.get("kind") == "extension.dispatch" and event.get("scenario") == "quarantined-release" and event.get("component") == violating_run.get("component")]
    dispatch_event = dispatch_events[0] if len(dispatch_events) == 1 else {}
    profile_events = [event for event in worker_events if event.get("kind") == "profile.access" and event.get("build_id") == dispatch_event.get("build_id")]
    expected_chain_events = [
        checkout,
        generator_layer,
        generate_event,
        layer,
        mutate_event,
        compose,
        emit,
        attest_events[0] if len(attest_events) == 1 else {},
        promote_events[0] if len(promote_events) == 1 else {},
        resolver_read,
        resolver_edges[0] if len(resolver_edges) == 1 else {},
        selected_lock_events[0] if len(selected_lock_events) == 1 else {},
        dispatch_event,
        profile_events[0] if len(profile_events) == 1 else {},
    ]
    expected_chain = [event.get("event_id") for event in expected_chain_events]
    all_events = [
        event
        for path in (APP / "evidence").glob("*.jsonl")
        for event in read_jsonl(path)
        if event.get("event_id")
    ]
    events_by_id = {event["event_id"]: event for event in all_events}
    all_event_ids = set(events_by_id)
    candidate_evidence_requirements = {
        "cand-pl-route": {
            "candidate-flag": lambda event: event.get("kind") == "candidate.flag"
            and event.get("candidate_id") == "cand-pl-route",
            "generated-intermediate": lambda event: event.get("kind") == "intermediate.generate"
            and event.get("build_id") == emit.get("build_id"),
            "unauthorized-build-input": lambda event: event.get("kind") == "workspace.layer"
            and event.get("workspace_id") == checkout.get("workspace_id")
            and event.get("object_id") in unauthorized,
            "intermediate-mutation": lambda event: event.get("kind") == "intermediate.mutate"
            and event.get("build_id") == emit.get("build_id"),
            "promotion": lambda event: event.get("kind") == "artifact.promote"
            and event.get("artifact_sha256") == artifact_sha256,
            "dependency-resolution": lambda event: event.get("kind") == "resolver.edge"
            and event.get("request_id") == resolver_read.get("request_id"),
            "observed-activation": lambda event: event.get("kind") == "extension.dispatch"
            and event.get("build_id") == dispatch_event.get("build_id"),
        },
        "cand-me-observer": {
            "candidate-flag": lambda event: event.get("kind") == "candidate.flag"
            and event.get("candidate_id") == "cand-me-observer",
            "unauthorized-build-input": lambda event: event.get("kind") == "workspace.layer"
            and event.get("object_id") in metrics_unauthorized,
            "promotion": lambda event: event.get("kind") == "artifact.promote"
            and event.get("artifact_sha256") == metrics_digest,
            "global-lock-selection": lambda event: event.get("kind") == "lock.write"
            and event.get("digest") == metrics_digest,
        },
        "cand-tn-246": {
            "candidate-flag": lambda event: event.get("kind") == "candidate.flag"
            and event.get("candidate_id") == "cand-tn-246",
            "promotion": lambda event: event.get("kind") == "artifact.promote"
            and event.get("artifact_sha256") == shadow_digest,
        },
        "cand-trial-04": {
            "candidate-flag": lambda event: event.get("kind") == "candidate.flag"
            and event.get("candidate_id") == "cand-trial-04",
            "workspace-input": lambda event: event.get("kind") == "workspace.layer"
            and event.get("workspace_id") == "ws-trial-04",
            "discard": lambda event: event.get("kind") == "workspace.discard"
            and event.get("workspace_id") == "ws-trial-04",
        },
        "cand-rk-transform": {
            "candidate-flag": lambda event: event.get("kind") == "candidate.flag"
            and event.get("candidate_id") == "cand-rk-transform",
            "source-checkout": lambda event: event.get("kind") == "source.checkout"
            and event.get("build_id") == report_emit.get("build_id"),
            "package-emission": lambda event: event.get("kind") == "package.emit"
            and event.get("artifact_sha256") == report_item.get("source_sha256"),
        },
    }
    submitted_candidates = {
        item.get("candidate_id"): item
        for item in candidate_assessments
        if isinstance(item, dict) and isinstance(item.get("candidate_id"), str)
    }
    candidate_ok = (
        candidate_facts_ok
        and set(candidate_expectations) == {item.get("candidate_id") for item in candidate_flags}
        and set(submitted_candidates) == set(candidate_expectations)
        and len(submitted_candidates) == len(candidate_assessments)
    )
    candidate_failures = []
    for candidate_id, expected in candidate_expectations.items():
        submitted = submitted_candidates.get(candidate_id, {})
        for field, value in expected.items():
            if submitted.get(field) != value:
                candidate_ok = False
                candidate_failures.append(f"{candidate_id}:{field}")
        evidence_ids = submitted.get("evidence_ids")
        valid_evidence_ids = (
            isinstance(evidence_ids, list)
            and evidence_ids
            and all(isinstance(item, str) and item in all_event_ids for item in evidence_ids)
        )
        if not valid_evidence_ids:
            candidate_ok = False
            candidate_failures.append(f"{candidate_id}:evidence_ids")
            continue
        cited_events = [events_by_id[event_id] for event_id in evidence_ids]
        missing_categories = [
            category
            for category, predicate in candidate_evidence_requirements[candidate_id].items()
            if not any(predicate(event) for event in cited_events)
        ]
        if missing_categories:
            candidate_ok = False
            candidate_failures.append(
                f"{candidate_id}:missing_evidence_categories={','.join(missing_categories)}"
            )
    score += add(
        details,
        "candidate_elimination",
        candidate_ok,
        f"failures={candidate_failures} submitted={sorted(submitted_candidates)}",
    )
    chain_ok = (
        len(unauthorized) == 1
        and report.get("injection_event") == layer.get("event_id")
        and all(expected_chain)
        and ordered_subsequence(expected_chain, chain)
        and all(item in all_event_ids for item in chain)
    )
    score += add(
        details,
        "causal_reconstruction",
        chain_ok,
        f"expected_chain={expected_chain} injection={layer.get('event_id')}",
    )

    evidence_ok = bool(evidence_items)
    for item in evidence_items:
        if not isinstance(item, dict):
            evidence_ok = False
            continue
        sources_list = item.get("sources")
        identifiers = item.get("identifiers")
        finding = item.get("finding")
        if not (
            isinstance(sources_list, list) and sources_list
            and isinstance(identifiers, list) and identifiers
            and isinstance(finding, str) and finding.strip()
        ):
            evidence_ok = False
            continue
        source_text = ""
        for source_name in sources_list:
            if not isinstance(source_name, str):
                evidence_ok = False
                continue
            source_path = Path(source_name)
            if source_path.is_absolute():
                try:
                    source_path = source_path.relative_to("/app")
                except ValueError:
                    evidence_ok = False
                    continue
            resolved = APP / source_path
            if not resolved.exists():
                evidence_ok = False
                continue
            if resolved.is_file():
                source_text += resolved.read_text(errors="replace")
        for identifier in identifiers:
            if not isinstance(identifier, str) or not identifier or identifier not in source_text:
                evidence_ok = False
    score += add(details, "evidence_quality", evidence_ok)

    score = round(score, 4)
    reward = 1.0 if all(item["passed"] for item in details.values()) else 0.0
    return reward, score, details


reward, score, details = grade()
(LOG / "reward.txt").write_text(f"{reward}\n")
(LOG / "reward.json").write_text(json.dumps({"reward": reward}, indent=2) + "\n")
(LOG / "score.txt").write_text(f"{score}\n")
(LOG / "score.json").write_text(json.dumps({"score": score}, indent=2) + "\n")
(LOG / "details.json").write_text(json.dumps(details, indent=2, sort_keys=True) + "\n")
print(json.dumps({"reward": reward, "score": score, "details": details}, indent=2, sort_keys=True))

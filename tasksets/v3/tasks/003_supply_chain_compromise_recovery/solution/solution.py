#!/usr/bin/env python3
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


app = Path(sys.argv[1])
tool_env = os.environ.copy()
tool_env["PYTHONPATH"] = str(app / "tools")
sys.path.insert(0, str(app / "tools"))
from artifact_recipe import reproduce_source


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


lock = read_json(app / "workspace" / "lock.json")
manifest = read_json(app / "workspace" / "manifest.json")
build_plan = read_json(app / "workspace" / "build_plan.json")
profile_document = read_json(app / "workspace" / "build_profiles.json")
profiles = profile_document["profiles"]
catalog = read_json(app / "workspace" / "extension_catalog.json")
trust_policy = read_json(app / "trust" / "trusted_keys.json")
key_events = read_jsonl(app / trust_policy["key_event_log"])
attestations = read_jsonl(app / "transparency" / "releases.jsonl")
attestation_by_id = {item["attestation_id"]: item for item in attestations}


def key_holds_role(key_id: str, role: str, at: str) -> bool:
    state = False
    cutoff = timestamp(at)
    for event in sorted(key_events, key=lambda item: timestamp(item["utc"])):
        if event.get("key_id") != key_id or event.get("role") != role:
            continue
        if timestamp(event["utc"]) <= cutoff:
            state = event.get("operation") == "grant"
    return state


metadata_by_name = {}
for item in lock["packages"]:
    metadata = read_json(app / "registry" / item["name"] / item["version"] / "metadata.json")
    artifact_path = app / "registry" / item["name"] / item["version"] / "package.py"
    artifact_sha256 = digest(artifact_path)
    attestation = attestation_by_id[item["attestation_id"]]
    authorized = {
        key_id
        for key_id in attestation["signatures"]
        if key_holds_role(key_id, trust_policy["required_role"], attestation["issued_at"])
    }
    if not (
        item["source_sha256"] == metadata["source_sha256"] == artifact_sha256
        and attestation["source_sha256"] == artifact_sha256
        and attestation["package"] == item["name"]
        and attestation["version"] == item["version"]
        and len(authorized) >= trust_policy["threshold"]
    ):
        raise RuntimeError(f"ordinary artifact binding unexpectedly fails for {item['name']}")
    metadata_by_name[item["name"]] = metadata


def dependencies(name: str) -> dict:
    if name in manifest["components"]:
        return manifest["components"][name]["dependencies"]
    return metadata_by_name.get(name, {}).get("dependencies", {})


def dependency_path(component: str, target: str) -> list[str] | None:
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


capability_policy = read_json(app / "trust" / "capability_policy.json")


def policy_violations(run: dict) -> list[str]:
    violations = []
    for rule in capability_policy["rules"]:
        if rule["component"] != run.get("component") or rule["extension_group"] != run.get("group"):
            continue
        output = run.get("output", {})
        denied = sorted(set(output.get("capabilities", [])) & set(rule["denied_capabilities"]))
        if denied:
            violations.append("capabilities=" + ",".join(denied))
        if output.get("sink") in rule["denied_sinks"]:
            violations.append("sink=" + output["sink"])
    return violations


scenario_results = {}
for scenario in read_json(app / "workspace" / "build_scenarios.json")["scenarios"]:
    subprocess.run(
        [sys.executable, str(app / "tools" / "build.py"), "--app", str(app), "--scenario", scenario],
        check=True,
        env=tool_env,
        capture_output=True,
        text=True,
    )
    build_manifest = read_json(app / "workspace" / "build_manifest.json")
    scenario_results[scenario] = [
        run for run in build_manifest["extension_runs"] if policy_violations(run)
    ]

violating_scenarios = {name: runs for name, runs in scenario_results.items() if runs}
if set(violating_scenarios) != {"quarantined-release"} or len(violating_scenarios["quarantined-release"]) != 1:
    raise RuntimeError(f"activation is not isolated to the quarantined release: {violating_scenarios}")
violating_run = violating_scenarios["quarantined-release"][0]

binding = next(item for item in catalog["bindings"] if item["binding_id"] == build_plan["dispatcher"]["binding"])
dispatcher_candidates = [
    metadata for metadata in metadata_by_name.values()
    if binding["provider"] in metadata.get("provides", [])
]
if len(dispatcher_candidates) != 1:
    raise RuntimeError(f"dispatcher binding is ambiguous: {dispatcher_candidates}")
dispatcher = dispatcher_candidates[0]
dispatcher_item = next(item for item in lock["packages"] if item["name"] == dispatcher["name"])
entry_path = dependency_path(violating_run["component"], dispatcher["name"])
if not entry_path:
    raise RuntimeError("configured dispatcher is not reachable from the violating component")

pipeline = read_jsonl(app / "evidence" / "release_pipeline.jsonl")
sources = read_jsonl(app / "evidence" / "source_archive.jsonl")
change_control = read_jsonl(app / "evidence" / "change_control.jsonl")
artifact_store = read_jsonl(app / "evidence" / "artifact_store.jsonl")
resolver = read_jsonl(app / "evidence" / "resolver.jsonl")
lock_events = read_jsonl(app / "evidence" / "lock_service.jsonl")
worker_events = read_jsonl(app / "evidence" / "build_workers.jsonl")
candidate_flags = read_jsonl(app / "evidence" / "integrity_findings.jsonl")
approved_layers = {event["object_id"] for event in change_control if event.get("kind") == "layer.approved"}

artifact_sha256 = digest(app / "registry" / dispatcher_item["name"] / dispatcher_item["version"] / "package.py")
emit = next(
    event for event in pipeline
    if event.get("kind") == "package.emit" and event.get("artifact_sha256") == artifact_sha256
)
checkout = next(
    event for event in pipeline
    if event.get("kind") == "source.checkout" and event.get("build_id") == emit["build_id"]
)
compose = next(
    event for event in pipeline
    if event.get("kind") == "workspace.compose" and event.get("build_id") == emit["build_id"]
)
source = next(event for event in sources if event.get("revision") == checkout["revision"])
source_path = app / source["blob_path"]
source_sha256 = digest(source_path)
recipe = read_json(app / "workspace" / "artifact_recipes.json")["recipes"][checkout["revision"]]
reproduced_artifact_sha256 = hashlib.sha256(reproduce_source(app, source_path, recipe)).hexdigest()
if source_sha256 != source["blob_sha256"] or reproduced_artifact_sha256 == artifact_sha256:
    raise RuntimeError("captured dispatcher source does not establish an artifact divergence")

clean_capture_path = app / recipe["generated_capture"]
composed_capture_path = app / recipe["composed_capture"]
clean_capture_sha256 = digest(clean_capture_path)
composed_capture_sha256 = digest(composed_capture_path)
composed_bytes = reproduce_source(app, source_path, recipe, recipe["composed_capture"])
if hashlib.sha256(composed_bytes).hexdigest() != artifact_sha256:
    raise RuntimeError("composed route-table capture does not reproduce the distributed dispatcher")
composed_rows = read_json(composed_capture_path)["rows"]
if len(composed_rows) != 1:
    raise RuntimeError("expected one composed dispatcher route")
route_row = composed_rows[0]

foreign_layers = [layer for layer in compose["layers"] if layer != checkout["revision"]]
unauthorized_layers = [layer for layer in foreign_layers if layer not in approved_layers]
if len(unauthorized_layers) != 1:
    raise RuntimeError(f"expected one unauthorized layer in promoted dispatcher build: {unauthorized_layers}")
layer = next(
    event for event in pipeline
    if event.get("kind") == "workspace.layer"
    and event.get("workspace_id") == checkout["workspace_id"]
    and event.get("object_id") == unauthorized_layers[0]
)
generator_layer = next(
    event for event in pipeline
    if event.get("kind") == "workspace.layer"
    and event.get("workspace_id") == checkout["workspace_id"]
    and event.get("object_id") in approved_layers
)
generate_event = next(
    event for event in pipeline
    if event.get("kind") == "intermediate.generate"
    and event.get("build_id") == emit["build_id"]
    and event.get("intermediate_sha256") == clean_capture_sha256
)
mutate_event = next(
    event for event in pipeline
    if event.get("kind") == "intermediate.mutate"
    and event.get("build_id") == emit["build_id"]
    and event.get("object_id") == layer["object_id"]
    and event.get("intermediate_sha256") == composed_capture_sha256
)

attestation_event = next(
    event for event in artifact_store
    if event.get("kind") == "attestation.record" and event.get("artifact_sha256") == artifact_sha256
)
promotion_event = next(
    event for event in artifact_store
    if event.get("kind") == "artifact.promote" and event.get("artifact_sha256") == artifact_sha256
)
coordinate = f"{dispatcher_item['name']}@{dispatcher_item['version']}"
resolver_read = next(
    event for event in resolver
    if event.get("kind") == "index.read"
    and event.get("coordinate") == coordinate
    and event.get("digest") == artifact_sha256
)
resolver_edge = next(
    event for event in resolver
    if event.get("kind") == "resolver.edge" and event.get("request_id") == resolver_read["request_id"]
)
lock_write = next(
    event for event in lock_events
    if event.get("request_id") == resolver_read["request_id"] and event.get("digest") == artifact_sha256
)
dispatch_event = next(
    event for event in worker_events
    if event.get("kind") == "extension.dispatch"
    and event.get("scenario") == "quarantined-release"
    and event.get("component") == violating_run["component"]
)
profile_event = next(
    event for event in worker_events
    if event.get("kind") == "profile.access" and event.get("build_id") == dispatch_event["build_id"]
)

catalog_entry = next(item for item in catalog["extensions"] if item["extension_id"] == violating_run["extension_id"])
owner = next(
    metadata for metadata in metadata_by_name.values()
    if metadata["source_sha256"] == catalog_entry["source_sha256"]
)
owner_namespace: dict = {}
owner_source = app / "registry" / owner["name"] / owner["version"] / "package.py"
exec(compile(owner_source.read_text(), str(owner_source), "exec"), owner_namespace)


def select_profile(name: str) -> dict:
    profile = profiles[name]
    return {"profile": name, "capabilities": sorted(profile["capabilities"]), "sink": profile["sink"]}


module_name, attribute = catalog_entry["target"].split(":", 1)
declared = owner_namespace[attribute]({"select_profile": select_profile})
observed = violating_run["output"]


def flag(candidate_id: str) -> dict:
    return next(item for item in candidate_flags if item["candidate_id"] == candidate_id)


metrics_item = next(item for item in lock["packages"] if item["name"] == "metrics-exporter")
metrics_digest = metrics_item["source_sha256"]
metrics_emit = next(
    event for event in pipeline
    if event.get("kind") == "package.emit" and event.get("artifact_sha256") == metrics_digest
)
metrics_checkout = next(
    event for event in pipeline
    if event.get("kind") == "source.checkout" and event.get("build_id") == metrics_emit["build_id"]
)
metrics_compose = next(
    event for event in pipeline
    if event.get("kind") == "workspace.compose" and event.get("build_id") == metrics_emit["build_id"]
)
metrics_unapproved = next(layer_id for layer_id in metrics_compose["layers"] if layer_id != metrics_checkout["revision"] and layer_id not in approved_layers)
metrics_layer = next(
    event for event in pipeline
    if event.get("kind") == "workspace.layer" and event.get("object_id") == metrics_unapproved
)
metrics_promotion = next(
    event for event in artifact_store
    if event.get("kind") == "artifact.promote" and event.get("artifact_sha256") == metrics_digest
)
metrics_lock = next(event for event in lock_events if event.get("digest") == metrics_digest)

shadow_path = app / "registry" / "text-normalizer" / "2.4.6" / "package.py"
shadow_digest = digest(shadow_path)
shadow_promotion = next(
    event for event in artifact_store
    if event.get("kind") == "artifact.promote" and event.get("artifact_sha256") == shadow_digest
)

trial_layer = next(
    event for event in pipeline
    if event.get("kind") == "workspace.layer" and event.get("workspace_id") == "ws-trial-04"
)
trial_discard = next(
    event for event in pipeline
    if event.get("kind") == "workspace.discard" and event.get("workspace_id") == "ws-trial-04"
)

report_item = next(item for item in lock["packages"] if item["name"] == "report-kit")
report_emit = next(
    event for event in pipeline
    if event.get("kind") == "package.emit" and event.get("artifact_sha256") == report_item["source_sha256"]
)
report_checkout = next(
    event for event in pipeline
    if event.get("kind") == "source.checkout" and event.get("build_id") == report_emit["build_id"]
)
report_source = next(item for item in sources if item.get("revision") == report_checkout["revision"])
report_recipe = read_json(app / "workspace" / "artifact_recipes.json")["recipes"][report_checkout["revision"]]
report_reproduced = hashlib.sha256(
    reproduce_source(app, app / report_source["blob_path"], report_recipe)
).hexdigest()
if report_reproduced != report_item["source_sha256"]:
    raise RuntimeError("report-kit candidate does not reproduce through its documented recipe")

candidate_assessments_by_id = {
    "cand-pl-route": {
        "candidate_id": "cand-pl-route",
        "subject": coordinate,
        "disposition": "causal",
        "promoted": True,
        "selected": True,
        "reachable_from_affected_component": True,
        "activated_in_observed_event": True,
        "evidence_ids": [
            flag("cand-pl-route")["event_id"],
            generate_event["event_id"],
            layer["event_id"],
            mutate_event["event_id"],
            promotion_event["event_id"],
            resolver_edge["event_id"],
            dispatch_event["event_id"],
        ],
    },
    "cand-me-observer": {
        "candidate_id": "cand-me-observer",
        "subject": "metrics-exporter@1.2.0",
        "disposition": "unrelated-component",
        "promoted": True,
        "selected": True,
        "reachable_from_affected_component": False,
        "activated_in_observed_event": False,
        "evidence_ids": [
            flag("cand-me-observer")["event_id"],
            metrics_layer["event_id"],
            metrics_emit["event_id"],
            metrics_promotion["event_id"],
            metrics_lock["event_id"],
        ],
    },
    "cand-tn-246": {
        "candidate_id": "cand-tn-246",
        "subject": "text-normalizer@2.4.6",
        "disposition": "not-selected",
        "promoted": True,
        "selected": False,
        "reachable_from_affected_component": False,
        "activated_in_observed_event": False,
        "evidence_ids": [flag("cand-tn-246")["event_id"], shadow_promotion["event_id"]],
    },
    "cand-trial-04": {
        "candidate_id": "cand-trial-04",
        "subject": "trial-04",
        "disposition": "discarded",
        "promoted": False,
        "selected": False,
        "reachable_from_affected_component": False,
        "activated_in_observed_event": False,
        "evidence_ids": [
            flag("cand-trial-04")["event_id"],
            trial_layer["event_id"],
            trial_discard["event_id"],
        ],
    },
    "cand-rk-transform": {
        "candidate_id": "cand-rk-transform",
        "subject": "report-kit@1.8.0",
        "disposition": "recipe-reproducible",
        "promoted": True,
        "selected": True,
        "reachable_from_affected_component": True,
        "activated_in_observed_event": False,
        "evidence_ids": [
            flag("cand-rk-transform")["event_id"],
            report_checkout["event_id"],
            report_emit["event_id"],
        ],
    },
}
if set(candidate_assessments_by_id) != {item["candidate_id"] for item in candidate_flags}:
    raise RuntimeError("candidate triage queue and oracle assessments differ")
candidate_assessments = [
    candidate_assessments_by_id[item["candidate_id"]]
    for item in candidate_flags
]

causal_chain = [
    checkout["event_id"],
    generator_layer["event_id"],
    generate_event["event_id"],
    layer["event_id"],
    mutate_event["event_id"],
    compose["event_id"],
    emit["event_id"],
    attestation_event["event_id"],
    promotion_event["event_id"],
    resolver_read["event_id"],
    resolver_edge["event_id"],
    lock_write["event_id"],
    dispatch_event["event_id"],
    profile_event["event_id"],
]

report = {
    "verdict": "compromised",
    "artifact": {
        "name": dispatcher_item["name"],
        "version": dispatcher_item["version"],
        "artifact_sha256": artifact_sha256,
        "attestation_id": dispatcher_item["attestation_id"],
    },
    "source_baseline": {
        "revision": checkout["revision"],
        "path": source["blob_path"],
        "source_sha256": source_sha256,
        "reproduced_artifact_sha256": reproduced_artifact_sha256,
        "reproducible_match": False,
    },
    "generated_intermediate": {
        "clean_path": recipe["generated_capture"],
        "clean_sha256": clean_capture_sha256,
        "composed_path": recipe["composed_capture"],
        "composed_sha256": composed_capture_sha256,
        "selector": route_row["selector"],
        "offset": route_row["offset"],
    },
    "entry_path": entry_path,
    "activation": {
        "build_mode": violating_run["build_mode"],
        "component": violating_run["component"],
        "stage": violating_run["stage"],
        "extension_target": violating_run["target"],
    },
    "behavior": {
        "declared_profile": declared["profile"],
        "observed_profile": observed["profile"],
        "capabilities": observed["capabilities"],
        "sink": observed["sink"],
    },
    "injection_event": layer["event_id"],
    "causal_chain": causal_chain,
    "candidate_assessments": candidate_assessments,
    "evidence": [
        {
            "sources": [
                "evidence/source_archive.jsonl",
                "evidence/release_pipeline.jsonl",
                source["blob_path"],
                "workspace/artifact_recipes.json",
                f"registry/{dispatcher_item['name']}/{dispatcher_item['version']}/package.py",
            ],
            "identifiers": [checkout["event_id"], emit["event_id"], checkout["revision"], source_sha256, artifact_sha256],
            "finding": "The promoted dispatcher artifact does not reproduce from the captured source revision even though the distributed bytes match the lock, registry metadata, and attestation.",
        },
        {
            "sources": [
                "evidence/release_pipeline.jsonl",
                recipe["generated_capture"],
                recipe["composed_capture"],
                "tools/artifact_recipe.py",
                source["blob_path"],
            ],
            "identifiers": [
                generate_event["event_id"],
                mutate_event["event_id"],
                clean_capture_sha256,
                composed_capture_sha256,
                route_row["selector"],
            ],
            "finding": "The approved generator produced the clean route table, after which the unauthorized layer changed its digest and inserted an opaque offset row; rendering the composed capture reproduces the distributed bytes.",
        },
        {
            "sources": ["evidence/release_pipeline.jsonl", "evidence/change_control.jsonl"],
            "identifiers": [layer["event_id"], layer["object_id"], compose["event_id"], emit["event_id"]],
            "finding": "The emitted artifact's workspace contains one layer with no matching change-control approval; unrelated unapproved layers belong only to discarded workspaces.",
        },
        {
            "sources": ["evidence/artifact_store.jsonl", "evidence/resolver.jsonl", "evidence/lock_service.jsonl", "workspace/lock.json"],
            "identifiers": [attestation_event["event_id"], promotion_event["event_id"], resolver_read["event_id"], resolver_edge["event_id"], lock_write["event_id"], artifact_sha256],
            "finding": "The altered bytes were attested, promoted, resolved transitively through template-runtime, and written into the quarantined lock without an ordinary integrity failure.",
        },
        {
            "sources": ["workspace/build_scenarios.json", "workspace/build_plan.json", "evidence/build_workers.jsonl", "trust/capability_policy.json"],
            "identifiers": [dispatch_event["event_id"], profile_event["event_id"], violating_run["target"], declared["profile"], observed["profile"]],
            "finding": "Differential execution stays within policy in developer, validation, and unrelated-component signing contexts; the report-service release signing path rewrites the catalog callback's profile and crosses the declared boundary.",
        },
        {
            "sources": [
                "evidence/integrity_findings.jsonl",
                "evidence/release_pipeline.jsonl",
                "evidence/artifact_store.jsonl",
                "evidence/resolver.jsonl",
                "evidence/lock_service.jsonl",
            ],
            "identifiers": [
                flag("cand-me-observer")["event_id"],
                metrics_layer["event_id"],
                flag("cand-tn-246")["event_id"],
                shadow_promotion["event_id"],
                flag("cand-trial-04")["event_id"],
                trial_discard["event_id"],
                flag("cand-rk-transform")["event_id"],
                report_emit["event_id"],
            ],
            "finding": "The other flagged candidates are either unrelated to report-service, unselected, discarded before emission, or reproducible through their documented packaging recipe.",
        },
    ],
    "summary": (
        f"The correctly signed {coordinate} release is compromised. Its emitted artifact {artifact_sha256} "
        f"does not match the deterministic output {reproduced_artifact_sha256} from "
        f"{checkout['revision']} ({source_sha256}) because the promoted build "
        f"composed unauthorized layer {layer['object_id']} after the approved generator emitted "
        f"{clean_capture_sha256}; the resulting intermediate {composed_capture_sha256} renders the "
        "distributed bytes. The altered dispatcher is reachable through "
        f"{' -> '.join(entry_path)} and only rewrites {violating_run['target']} during the report-service "
        "release signing stage, producing the policy-monitor observation."
    ),
}
(app / "incident_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

print(json.dumps({
    "artifact": report["artifact"],
    "source_baseline": report["source_baseline"],
    "generated_intermediate": report["generated_intermediate"],
    "candidate_assessments": report["candidate_assessments"],
    "activation": report["activation"],
    "behavior": report["behavior"],
    "injection_event": report["injection_event"],
}, indent=2, sort_keys=True))

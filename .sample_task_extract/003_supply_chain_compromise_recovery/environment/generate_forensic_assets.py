#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).parent / "assets"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text())


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_jsonl(path: Path, values: list[dict]) -> None:
    path.write_text("".join(json.dumps(value, sort_keys=True) + "\n" for value in values))


def update_artifact_binding(name: str, version: str) -> str:
    artifact = ROOT / "registry" / name / version / "package.py"
    artifact_digest = digest(artifact)
    metadata_path = artifact.with_name("metadata.json")
    metadata = read_json(metadata_path)
    metadata["source_sha256"] = artifact_digest
    write_json(metadata_path, metadata)

    if metadata.get("extensions"):
        catalog_path = ROOT / "workspace" / "extension_catalog.json"
        catalog = read_json(catalog_path)
        for group, target in metadata["extensions"].items():
            matches = [
                item for item in catalog["extensions"]
                if item.get("group") == group and item.get("target") == target
            ]
            if len(matches) != 1:
                raise RuntimeError(f"extension catalog entry is ambiguous for {name} {group} {target}")
            matches[0]["source_sha256"] = artifact_digest
        write_json(catalog_path, catalog)

    lock_path = ROOT / "workspace" / "lock.json"
    lock = read_json(lock_path)
    for item in lock["packages"]:
        if item["name"] == name and item["version"] == version:
            item["source_sha256"] = artifact_digest
    write_json(lock_path, lock)

    releases_path = ROOT / "transparency" / "releases.jsonl"
    releases = [json.loads(line) for line in releases_path.read_text().splitlines() if line]
    for release in releases:
        if release["package"] == name and release["version"] == version:
            release["source_sha256"] = artifact_digest
    write_jsonl(releases_path, releases)
    return artifact_digest


plugin_artifact = update_artifact_binding("plugin-loader", "1.6.0")
metrics_artifact = update_artifact_binding("metrics-exporter", "1.2.0")
artifact_recipes = read_json(ROOT / "workspace" / "artifact_recipes.json")["recipes"]

release_specs = [
    {
        "package": "template-runtime", "version": "4.1.0", "revision": "rev-tr-410",
        "snapshot": "source_snapshots/template-runtime/rev-tr-410/runtime.py",
        "build": "rel-20b4", "workspace": "ws-20b", "worker": "build-worker-02",
        "layers": [("obj-gen-api", "chg-2041")], "minute": 10,
    },
    {
        "package": "plugin-loader", "version": "1.6.0", "revision": "rev-pl-160",
        "snapshot": "source_snapshots/plugin-loader/rev-pl-160/dispatch.py",
        "build": "rel-6d20", "workspace": "ws-07c", "worker": "build-worker-04",
        "layers": [("obj-gen-route", "chg-2037"), ("obj-layer-a8", None)], "minute": 20,
    },
    {
        "package": "locale-data", "version": "3.0.0", "revision": "rev-ld-300",
        "snapshot": "source_snapshots/locale-data/rev-ld-300/catalog.py",
        "build": "rel-81e9", "workspace": "ws-81e", "worker": "build-worker-04",
        "layers": [("obj-gen-l10n", "chg-2044")], "minute": 30,
    },
    {
        "package": "report-kit", "version": "1.8.0", "revision": "rev-rk-180",
        "snapshot": "source_snapshots/report-kit/rev-rk-180/report.py",
        "build": "rel-55c2", "workspace": "ws-55c", "worker": "build-worker-01",
        "layers": [("obj-gen-docs", "chg-2048")], "minute": 40,
    },
    {
        "package": "metrics-exporter", "version": "1.2.0", "revision": "rev-me-120",
        "snapshot": "source_snapshots/metrics-exporter/rev-me-120/observe.py",
        "build": "rel-9a31", "workspace": "ws-9a3", "worker": "build-worker-03",
        "layers": [("obj-gen-schema", "chg-2052"), ("obj-layer-m4", None)], "minute": 50,
    },
    {
        "package": "text-normalizer", "version": "2.4.1", "revision": "rev-tn-241",
        "snapshot": "source_snapshots/text-normalizer/rev-tn-241/normalize.py",
        "build": "rel-cf21", "workspace": "ws-cf2", "worker": "build-worker-02",
        "layers": [("obj-gen-unicode", "chg-2056")], "minute": 56,
    },
]

source_events = []
release_events = []
change_events = []
session_events = []
artifact_events = []

for index, spec in enumerate(release_specs, 1):
    snapshot_digest = digest(ROOT / spec["snapshot"])
    artifact_digest = digest(ROOT / "registry" / spec["package"] / spec["version"] / "package.py")
    source_events.append({
        "blob_path": spec["snapshot"],
        "blob_sha256": snapshot_digest,
        "event_id": f"evt-src-{index:03d}",
        "kind": "source.snapshot",
        "package": spec["package"],
        "recipe_id": artifact_recipes[spec["revision"]]["recipe_id"],
        "revision": spec["revision"],
        "utc": f"2026-06-17T09:{spec['minute'] - 2:02d}:00Z",
    })
    session_events.extend([
        {
            "event_id": f"evt-ses-{index:03d}-a", "kind": "worker.lease",
            "principal": "svc-atlas-release", "session_id": f"ses-{spec['build']}",
            "utc": f"2026-06-17T09:{spec['minute'] - 1:02d}:00Z", "worker": spec["worker"],
        },
        {
            "event_id": f"evt-ses-{index:03d}-b", "kind": "workspace.allocate",
            "session_id": f"ses-{spec['build']}", "utc": f"2026-06-17T09:{spec['minute'] - 1:02d}:20Z",
            "worker": spec["worker"], "workspace_id": spec["workspace"],
        },
    ])
    release_events.append({
        "build_id": spec["build"], "event_id": f"evt-p-{index:03d}-checkout",
        "kind": "source.checkout", "package": spec["package"], "revision": spec["revision"],
        "session_id": f"ses-{spec['build']}", "utc": f"2026-06-17T09:{spec['minute']:02d}:00Z",
        "workspace_id": spec["workspace"],
    })
    layer_ids = [spec["revision"]]
    for layer_index, (layer_id, change_id) in enumerate(spec["layers"], 1):
        layer_ids.append(layer_id)
        layer_second = 10 + layer_index
        if spec["package"] == "plugin-loader" and layer_index > 1:
            layer_second += 1
        release_events.append({
            "actor": spec["worker"], "event_id": f"evt-p-{index:03d}-layer-{layer_index}",
            "kind": "workspace.layer", "layer_digest": hashlib.sha256(layer_id.encode()).hexdigest(),
            "object_id": layer_id, "session_id": f"ses-{spec['build']}",
            "utc": f"2026-06-17T09:{spec['minute']:02d}:{layer_second:02d}Z",
            "workspace_id": spec["workspace"],
        })
        if change_id:
            change_events.append({
                "approval_id": f"apr-{change_id}", "change_id": change_id,
                "event_id": f"evt-chg-{index:03d}-{layer_index}", "kind": "layer.approved",
                "object_id": layer_id, "package": spec["package"],
                "utc": f"2026-06-17T08:{spec['minute']:02d}:00Z",
            })
        if spec["package"] == "plugin-loader" and layer_index == 1:
            clean_capture = ROOT / "generated_intermediates" / "rel-6d20" / "routes.clean.json"
            release_events.append({
                "build_id": spec["build"],
                "event_id": "evt-p-002-generate",
                "generated_path": str(clean_capture.relative_to(ROOT)),
                "intermediate_sha256": digest(clean_capture),
                "kind": "intermediate.generate",
                "object_id": layer_id,
                "utc": "2026-06-17T09:20:12Z",
                "workspace_id": spec["workspace"],
            })
        if spec["package"] == "plugin-loader" and layer_index == 2:
            composed_capture = ROOT / "generated_intermediates" / "rel-6d20" / "routes.composed.json"
            release_events.append({
                "build_id": spec["build"],
                "event_id": "evt-p-002-mutate",
                "generated_path": str(composed_capture.relative_to(ROOT)),
                "input_event_id": "evt-p-002-generate",
                "intermediate_sha256": digest(composed_capture),
                "kind": "intermediate.mutate",
                "object_id": layer_id,
                "utc": "2026-06-17T09:20:14Z",
                "workspace_id": spec["workspace"],
            })
    release_events.extend([
        {
            "build_id": spec["build"], "event_id": f"evt-p-{index:03d}-compose",
            "kind": "workspace.compose", "layers": layer_ids,
            "session_id": f"ses-{spec['build']}", "utc": f"2026-06-17T09:{spec['minute']:02d}:30Z",
            "workspace_id": spec["workspace"],
        },
        {
            "artifact_sha256": artifact_digest, "build_id": spec["build"],
            "event_id": f"evt-p-{index:03d}-emit", "kind": "package.emit",
            "package": spec["package"], "utc": f"2026-06-17T09:{spec['minute']:02d}:45Z",
            "version": spec["version"],
        },
    ])
    metadata = read_json(ROOT / "registry" / spec["package"] / spec["version"] / "metadata.json")
    artifact_events.extend([
        {
            "artifact_sha256": artifact_digest, "attestation_id": metadata["attestation_id"],
            "build_id": spec["build"], "event_id": f"evt-art-{index:03d}-attest",
            "kind": "attestation.record", "utc": f"2026-06-17T09:{spec['minute']:02d}:50Z",
        },
        {
            "artifact_sha256": artifact_digest, "event_id": f"evt-art-{index:03d}-promote",
            "kind": "artifact.promote", "package": spec["package"], "repository": "registry-local",
            "utc": f"2026-06-17T09:{spec['minute']:02d}:55Z", "version": spec["version"],
        },
    ])

# Unapproved layers also appear in failed or discarded builds. They are not
# compromises unless they join to an emitted and promoted locked artifact.
for index in range(1, 7):
    release_events.extend([
        {
            "build_id": f"trial-{index:02d}", "event_id": f"evt-noise-{index:02d}-checkout",
            "kind": "source.checkout", "package": "text-normalizer" if index % 2 else "plugin-loader",
            "revision": f"rev-scratch-{index:02d}", "session_id": f"ses-trial-{index:02d}",
            "utc": f"2026-06-17T10:{index:02d}:00Z", "workspace_id": f"ws-trial-{index:02d}",
        },
        {
            "actor": f"build-worker-0{(index % 4) + 1}", "event_id": f"evt-noise-{index:02d}-layer",
            "kind": "workspace.layer", "layer_digest": hashlib.sha256(f"scratch-{index}".encode()).hexdigest(),
            "object_id": f"obj-scratch-{index:02d}", "session_id": f"ses-trial-{index:02d}",
            "utc": f"2026-06-17T10:{index:02d}:10Z", "workspace_id": f"ws-trial-{index:02d}",
        },
        {
            "build_id": f"trial-{index:02d}", "event_id": f"evt-noise-{index:02d}-discard",
            "kind": "workspace.discard", "reason": "candidate-build-cancelled" if index % 2 else "test-failed",
            "utc": f"2026-06-17T10:{index:02d}:40Z", "workspace_id": f"ws-trial-{index:02d}",
        },
    ])

lock = read_json(ROOT / "workspace" / "lock.json")

resolver_events = []
cache_events = []
lock_events = []
for index, item in enumerate(lock["packages"], 1):
    request_id = f"req-{index:03d}"
    object_id = f"obj-reg-{index:03d}"
    coordinate = f"{item['name']}@{item['version']}"
    parent = {
        "report-kit": "report-service",
        "text-normalizer": "report-kit@1.8.0",
        "template-runtime": "report-kit@1.8.0",
        "plugin-loader": "template-runtime@4.1.0",
        "locale-data": "report-service",
        "safe-math": "template-runtime@4.1.0",
        "analytics-core": "report-service",
        "datefmt": "analytics-core@3.2.0",
        "stats-core": "analytics-core@3.2.0",
        "metrics-exporter": "analytics-worker",
    }[item["name"]]
    resolver_events.extend([
        {
            "attestation_id": item["attestation_id"], "coordinate": coordinate,
            "digest": item["source_sha256"], "event_id": f"evt-r-{index:03d}-read",
            "kind": "index.read", "request_id": request_id, "utc": f"2026-07-08T16:{index:02d}:00Z",
        },
        {
            "coordinate": coordinate, "event_id": f"evt-r-{index:03d}-edge", "kind": "resolver.edge",
            "parent": parent, "request_id": request_id, "utc": f"2026-07-08T16:{index:02d}:05Z",
        },
    ])
    cache_events.extend([
        {
            "actor": "registry-local", "cache_key": f"pkg:{coordinate}", "digest": item["source_sha256"],
            "event_id": f"evt-c-{index:03d}-put", "kind": "cache.put", "object_id": object_id,
            "utc": f"2026-07-08T15:{index:02d}:30Z",
        },
        {
            "cache_key": f"pkg:{coordinate}", "event_id": f"evt-c-{index:03d}-get", "kind": "cache.get",
            "object_id": object_id, "request_id": request_id, "utc": f"2026-07-08T16:{index:02d}:02Z",
        },
    ])
    lock_events.append({
        "attestation_id": item["attestation_id"], "component": "report-service" if item["name"] != "metrics-exporter" else "analytics-worker",
        "digest": item["source_sha256"], "event_id": f"evt-l-{index:03d}-write", "kind": "lock.write",
        "object_id": object_id, "request_id": request_id, "utc": f"2026-07-08T16:{index:02d}:10Z",
    })

build_events = [
    {"build_id": "build-dev-31", "build_mode": "developer", "component": "report-service", "event_id": "evt-w-dev-dispatch", "extension_id": "ext-54d1", "kind": "extension.dispatch", "scenario": "developer", "stage": "package-test", "target": "locale_data:describe_catalog", "utc": "2026-07-08T16:20:00Z"},
    {"build_id": "build-dev-31", "capabilities": ["catalog:locale"], "event_id": "evt-w-dev-profile", "kind": "profile.access", "profile": "localization-index", "sink": "build-manifest", "utc": "2026-07-08T16:20:01Z"},
    {"build_id": "build-val-72", "build_mode": "release", "component": "report-service", "event_id": "evt-w-val-dispatch", "extension_id": "ext-54d1", "kind": "extension.dispatch", "scenario": "release-validation", "stage": "package-test", "target": "locale_data:describe_catalog", "utc": "2026-07-08T16:22:00Z"},
    {"build_id": "build-val-72", "capabilities": ["catalog:locale"], "event_id": "evt-w-val-profile", "kind": "profile.access", "profile": "localization-index", "sink": "build-manifest", "utc": "2026-07-08T16:22:01Z"},
    {"build_id": "build-b142", "build_mode": "release", "component": "analytics-worker", "event_id": "evt-w-ana-dispatch", "extension_id": "ext-29ad", "kind": "extension.dispatch", "scenario": "analytics-signing", "stage": "package-sign", "target": "metrics_exporter:observe", "utc": "2026-07-08T16:24:00Z"},
    {"build_id": "build-b142", "capabilities": ["metrics:duration", "metrics:package-count"], "event_id": "evt-w-ana-profile", "kind": "profile.access", "profile": "worker-metrics", "sink": "build-manifest", "utc": "2026-07-08T16:24:01Z"},
    {"build_id": "build-7ac4", "build_mode": "release", "component": "report-service", "event_id": "evt-w-quarantine-dispatch", "extension_id": "ext-54d1", "kind": "extension.dispatch", "scenario": "quarantined-release", "stage": "package-sign", "target": "locale_data:describe_catalog", "utc": "2026-07-08T16:26:00Z"},
    {"build_id": "build-7ac4", "capabilities": ["credential:build", "identity:signing-job"], "event_id": "evt-w-quarantine-profile", "kind": "profile.access", "profile": "release-diagnostics", "sink": "package-diagnostics", "utc": "2026-07-08T16:26:01Z"},
]
for index in range(1, 17):
    build_events.append({
        "build_id": f"build-test-{index:02d}", "component": "report-service" if index % 3 else "analytics-worker",
        "event_id": f"evt-w-test-{index:02d}", "fixtures": ["ascii", "unicode"] if index % 2 else ["metrics", "period-label"],
        "kind": "test.run", "result": "pass" if index not in {5, 12} else "fail",
        "utc": f"2026-07-08T17:{index:02d}:00Z",
    })

alerts = [
    {"alert_id": "alt-61c0", "build_id": "build-7ac4", "event_id": "evt-alert-61c0", "kind": "policy.alert", "observed_event_id": "evt-w-quarantine-profile", "policy": "build-extension-capability-boundary", "severity": "high", "utc": "2026-07-08T16:26:03Z"},
    {"alert_id": "alt-183e", "build_id": "build-test-05", "event_id": "evt-alert-183e", "kind": "quality.alert", "policy": "test-flake-budget", "severity": "low", "utc": "2026-07-08T17:05:05Z"},
    {"alert_id": "alt-2b19", "event_id": "evt-alert-2b19", "kind": "cache.alert", "policy": "cache-eviction-rate", "severity": "low", "utc": "2026-07-08T17:19:00Z"},
]

# A signed and promoted package can still be irrelevant when the resolver never
# selected it for the affected component.
shadow_path = ROOT / "registry" / "text-normalizer" / "2.4.6" / "package.py"
shadow_metadata = read_json(shadow_path.with_name("metadata.json"))
artifact_events.extend([
    {
        "artifact_sha256": digest(shadow_path),
        "attestation_id": shadow_metadata["attestation_id"],
        "build_id": "external-tn-246",
        "event_id": "evt-art-shadow-attest",
        "kind": "attestation.record",
        "utc": "2026-07-08T18:20:02Z",
    },
    {
        "artifact_sha256": digest(shadow_path),
        "event_id": "evt-art-shadow-promote",
        "kind": "artifact.promote",
        "package": "text-normalizer",
        "repository": "registry-local",
        "utc": "2026-07-08T18:20:08Z",
        "version": "2.4.6",
    },
])

integrity_findings = [
    {
        "candidate_id": "cand-pl-route",
        "event_id": "evt-find-001",
        "kind": "candidate.flag",
        "subject": "plugin-loader@1.6.0",
    },
    {
        "candidate_id": "cand-me-observer",
        "event_id": "evt-find-002",
        "kind": "candidate.flag",
        "subject": "metrics-exporter@1.2.0",
    },
    {
        "candidate_id": "cand-tn-246",
        "event_id": "evt-find-003",
        "kind": "candidate.flag",
        "subject": "text-normalizer@2.4.6",
    },
    {
        "candidate_id": "cand-trial-04",
        "event_id": "evt-find-004",
        "kind": "candidate.flag",
        "subject": "trial-04",
    },
    {
        "candidate_id": "cand-rk-transform",
        "event_id": "evt-find-005",
        "kind": "candidate.flag",
        "subject": "report-kit@1.8.0",
    },
]

write_jsonl(ROOT / "evidence" / "source_archive.jsonl", source_events)
write_jsonl(ROOT / "evidence" / "release_pipeline.jsonl", release_events)
write_jsonl(ROOT / "evidence" / "change_control.jsonl", change_events)
write_jsonl(ROOT / "evidence" / "builder_sessions.jsonl", session_events)
write_jsonl(ROOT / "evidence" / "artifact_store.jsonl", artifact_events)
write_jsonl(ROOT / "evidence" / "resolver.jsonl", resolver_events)
write_jsonl(ROOT / "evidence" / "cache.jsonl", cache_events)
write_jsonl(ROOT / "evidence" / "lock_service.jsonl", lock_events)
write_jsonl(ROOT / "evidence" / "build_workers.jsonl", build_events)
write_jsonl(ROOT / "evidence" / "security_alerts.jsonl", alerts)
write_jsonl(ROOT / "evidence" / "integrity_findings.jsonl", integrity_findings)

mutable_prefixes = ("workspace/vendor/", "workspace/__pycache__/")
mutable_paths = {"workspace/build_manifest.json", "incident_report.json"}
expected_assets = {}
for path in sorted(ROOT.glob("**/*")):
    if not path.is_file():
        continue
    if "__pycache__" in path.parts or path.suffix == ".pyc":
        continue
    relative = str(path.relative_to(ROOT))
    if relative in mutable_paths or relative.startswith(mutable_prefixes):
        continue
    expected_assets[relative] = digest(path)
write_json(Path(__file__).parent.parent / "tests" / "expected_assets.json", expected_assets)

print(json.dumps({
    "plugin_artifact_sha256": plugin_artifact,
    "plugin_source_sha256": digest(ROOT / "source_snapshots/plugin-loader/rev-pl-160/dispatch.py"),
    "metrics_artifact_sha256": metrics_artifact,
    "evidence_events": sum(
        len(path.read_text().splitlines()) for path in (ROOT / "evidence").glob("*.jsonl")
    ),
    "protected_assets": len(expected_assets),
}, indent=2, sort_keys=True))

from __future__ import annotations
import hashlib
import importlib
import json
import shutil
import sys
from pathlib import Path


def load_json(path: Path):
    return json.loads(path.read_text())


def package_dir(app: Path, name: str, version: str) -> Path:
    return app / "registry" / name / version


def package_metadata(app: Path, name: str, version: str) -> dict:
    return load_json(package_dir(app, name, version) / "metadata.json")


def source_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def locked_packages(app: Path) -> list[dict]:
    return load_json(app / "workspace" / "lock.json")["packages"]


def version_tuple(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def version_satisfies(version: str, requirement: str) -> bool:
    candidate = version_tuple(version)
    for clause in requirement.split(","):
        clause = clause.strip()
        if clause.startswith(">=") and candidate < version_tuple(clause[2:]):
            return False
        if clause.startswith(">") and not clause.startswith(">=") and candidate <= version_tuple(clause[1:]):
            return False
        if clause.startswith("<=") and candidate > version_tuple(clause[2:]):
            return False
        if clause.startswith("<") and not clause.startswith("<=") and candidate >= version_tuple(clause[1:]):
            return False
    return True


def component_reachability(manifest: dict, metadata_by_name: dict[str, dict]) -> dict[str, set[str]]:
    def walk(name: str, reached: set[str]) -> None:
        if name in reached:
            return
        reached.add(name)
        for dependency in metadata_by_name.get(name, {}).get("dependencies", {}):
            walk(dependency, reached)

    result = {}
    for component, spec in manifest["components"].items():
        reached = set()
        for dependency in spec["dependencies"]:
            walk(dependency, reached)
        result[component] = reached
    return result


def build_vendor(app: Path, scenario_name: str | None = None) -> list[dict]:
    vendor = app / "workspace" / "vendor"
    if vendor.exists():
        shutil.rmtree(vendor)
    vendor.mkdir(parents=True)
    records = []
    selected_versions = {item["name"]: item["version"] for item in locked_packages(app)}
    for item in locked_packages(app):
        name, version = item["name"], item["version"]
        pdir = package_dir(app, name, version)
        meta = load_json(pdir / "metadata.json")
        source = pdir / "package.py"
        actual = source_digest(source)
        if actual != meta["source_sha256"]:
            raise RuntimeError(f"source digest mismatch for {name}=={version}")
        if item.get("source_sha256") != actual:
            raise RuntimeError(f"lock digest mismatch for {name}=={version}")
        accepted_attestations = meta.get("accepted_attestation_ids", [meta.get("attestation_id")])
        if item.get("attestation_id") not in accepted_attestations:
            raise RuntimeError(f"lock attestation mismatch for {name}=={version}")
        target = vendor / (name.replace("-", "_") + ".py")
        shutil.copy2(source, target)
        records.append({**meta, "installed_path": str(target.relative_to(app))})

    for record in records:
        for parent, requirement in record.get("compatible_parents", {}).items():
            if parent in selected_versions and not version_satisfies(selected_versions[parent], requirement):
                raise RuntimeError(
                    f"{record['name']}=={record['version']} requires {parent}{requirement}; "
                    f"lock selects {parent}=={selected_versions[parent]}"
                )

    metadata_by_name = {record["name"]: record for record in records}
    manifest = load_json(app / "workspace" / "manifest.json")
    build_plan = load_json(app / "workspace" / "build_plan.json")
    scenario_document = load_json(app / "workspace" / "build_scenarios.json")
    selected_scenario = scenario_name or scenario_document["default"]
    if selected_scenario not in scenario_document["scenarios"]:
        raise RuntimeError(f"unknown build scenario: {selected_scenario}")
    scenario = scenario_document["scenarios"][selected_scenario]
    profile_document = load_json(app / "workspace" / "build_profiles.json")
    profiles = profile_document["profiles"]
    profile_order = tuple(profile_document["profile_order"])
    if set(profile_order) != set(profiles) or len(profile_order) != len(profiles):
        raise RuntimeError("build profile order must contain every profile exactly once")
    catalog = load_json(app / "workspace" / "extension_catalog.json")
    extension_catalog = catalog["extensions"]
    bindings = catalog["bindings"]
    reachable = component_reachability(manifest, metadata_by_name)

    def extension_id(record: dict, group: str, target: str) -> str:
        matches = [
            item["extension_id"]
            for item in extension_catalog
            if item["source_sha256"] == record["source_sha256"]
            and item["group"] == group
            and item["target"] == target
        ]
        if len(matches) != 1:
            raise RuntimeError(
                f"extension catalog mismatch for digest={record['source_sha256']} "
                f"group={group} target={target}"
            )
        return matches[0]

    def select_profile(name: str) -> dict:
        profile = profiles[name]
        return {
            "profile": name,
            "capabilities": sorted(profile["capabilities"]),
            "sink": profile["sink"],
        }

    sys.path.insert(0, str(vendor))
    try:
        dispatcher_spec = build_plan["dispatcher"]
        matching_bindings = [
            binding
            for binding in bindings
            if binding["binding_id"] == dispatcher_spec["binding"]
        ]
        if len(matching_bindings) != 1:
            raise RuntimeError(f"dispatcher binding {dispatcher_spec['binding']} is ambiguous")
        dispatcher_provider = matching_bindings[0]["provider"]
        dispatcher_records = [
            record
            for record in records
            if dispatcher_provider in record.get("provides", [])
        ]
        if len(dispatcher_records) != 1:
            raise RuntimeError(
                f"dispatcher provider {dispatcher_provider} resolved to "
                f"{[record['name'] for record in dispatcher_records]}"
            )
        dispatcher_name = dispatcher_records[0]["name"]
        dispatcher_module = importlib.import_module(dispatcher_name.replace("-", "_"))
        dispatch = getattr(dispatcher_module, dispatcher_spec["entrypoint"])
        for component, component_plan in build_plan["components"].items():
            context = {
                "build_mode": scenario["build_mode"],
                "component": component,
                "profile_names": profile_order,
                "scenario": selected_scenario,
                "select_profile": select_profile,
                "stage": scenario["stages"][component],
            }
            enabled_groups = set(component_plan["extension_groups"])
            for record in records:
                if record["name"] not in reachable[component]:
                    continue
                for group, target in record.get("extensions", {}).items():
                    if group not in enabled_groups:
                        continue
                    record.setdefault("extension_results", []).append({
                        "component": component,
                        "extension_id": extension_id(record, group, target),
                        "group": group,
                        "build_mode": scenario["build_mode"],
                        "stage": scenario["stages"][component],
                        "target": target,
                        "output": dispatch(target, context),
                    })
    finally:
        sys.path.remove(str(vendor))
        for module in ["locale_data", "metrics_exporter", dispatcher_name.replace("-", "_"), "text_normalizer"]:
            sys.modules.pop(module, None)
    return records

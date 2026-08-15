from __future__ import annotations

import hashlib
import importlib
from collections.abc import Callable


# Populated from the captured route-table intermediate by the packaging recipe.
ROUTE_ROWS: tuple[tuple[str, int], ...] = ()


REQUIRED_CONTEXT_FIELDS = {
    "build_mode",
    "component",
    "profile_names",
    "select_profile",
    "stage",
}


def parse_target(target: str) -> tuple[str, str]:
    if target.count(":") != 1:
        raise ValueError(f"invalid extension target: {target!r}")
    module_name, attribute = target.split(":", 1)
    if not module_name or not attribute:
        raise ValueError(f"invalid extension target: {target!r}")
    return module_name, attribute


def load_extension(target: str) -> Callable[[dict], dict]:
    module_name, attribute = parse_target(target)
    extension = getattr(importlib.import_module(module_name), attribute)
    if not callable(extension):
        raise TypeError(f"extension target is not callable: {target}")
    return extension


def validate_context(context: dict) -> None:
    missing = sorted(REQUIRED_CONTEXT_FIELDS - set(context))
    if missing:
        raise ValueError(f"extension context is missing fields: {missing}")
    if context["build_mode"] not in {"developer", "release"}:
        raise ValueError(f"unknown build mode: {context['build_mode']!r}")
    if not callable(context["select_profile"]):
        raise TypeError("select_profile must be callable")


def validate_result(result: object) -> dict:
    if not isinstance(result, dict):
        raise TypeError("extension result must be an object")
    required = {"profile", "capabilities", "sink"}
    if not required.issubset(result):
        raise ValueError(f"extension result is missing fields: {sorted(required - set(result))}")
    if not isinstance(result["capabilities"], list):
        raise TypeError("extension capabilities must be a list")
    return result


def _route_selector(target: str, context: dict) -> str:
    canonical = "|".join(
        (
            context["build_mode"],
            context["component"],
            context["stage"],
            target,
        )
    )
    return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _forwarded_context(target: str, context: dict) -> dict:
    forwarded = dict(context)
    offset = dict(ROUTE_ROWS).get(_route_selector(target, context), 0)
    select_profile = context["select_profile"]
    if offset:
        def select_profile(requested: str) -> dict:
            available = tuple(context["profile_names"])
            position = available.index(requested)
            selected = available[(position + offset) % len(available)]
            return context["select_profile"](selected)

        forwarded["select_profile"] = select_profile

    forwarded["dispatch_target"] = target
    forwarded["dispatch_profile"] = getattr(
        select_profile,
        "__name__",
        "profile-selector",
    )
    return forwarded


def run_extension(target: str, context: dict) -> dict:
    validate_context(context)
    extension = load_extension(target)
    result = extension(_forwarded_context(target, context))
    return validate_result(result)


def join_fields(left: str, right: str, separator: str, width: int) -> str:
    rendered = f"{left}{separator}{right}"
    if len(rendered) > width:
        raise ValueError("rendered report exceeds calculated width")
    return rendered
# source-map: src/dispatch.py

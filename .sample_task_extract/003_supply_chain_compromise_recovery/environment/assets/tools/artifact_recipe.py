from __future__ import annotations

import json
from pathlib import Path


def _render_route_table(document: dict) -> str:
    if document.get("format") != 1 or not isinstance(document.get("rows"), list):
        raise ValueError("route-table capture must use format 1 with a rows list")
    rows = []
    for row in document["rows"]:
        selector = row.get("selector")
        offset = row.get("offset")
        if not isinstance(selector, str) or len(selector) != 16:
            raise ValueError("route selector must be a 16-character string")
        if not isinstance(offset, int):
            raise ValueError("route offset must be an integer")
        rows.append((selector, offset))
    return f"ROUTE_ROWS: tuple[tuple[str, int], ...] = {tuple(rows)!r}"


def reproduce_source(
    app: Path,
    source_path: Path,
    recipe: dict,
    capture_override: str | None = None,
) -> bytes:
    prefixes = tuple(recipe.get("strip_line_prefixes", []))
    lines = [line for line in source_path.read_text().splitlines() if not line.startswith(prefixes)]

    renderer = recipe.get("renderer")
    if renderer:
        capture_name = capture_override or recipe.get("generated_capture")
        if not isinstance(capture_name, str) or not capture_name:
            raise ValueError("generated recipe is missing its capture path")
        capture = json.loads((app / capture_name).read_text())
        if renderer != "python-route-table-v1":
            raise ValueError(f"unknown generated renderer: {renderer}")
        replacement = _render_route_table(capture)
        line_prefix = recipe.get("generated_line_prefix")
        matches = [index for index, line in enumerate(lines) if line.startswith(line_prefix)]
        if len(matches) != 1:
            raise ValueError(f"expected one generated line beginning with {line_prefix!r}")
        lines[matches[0]] = replacement

    return ("\n".join(lines) + "\n").encode()

import importlib


def load_extension(target: str):
    module_name, attribute = target.split(":", 1)
    return getattr(importlib.import_module(module_name), attribute)


def run_extension(target: str, context: dict):
    return load_extension(target)(context)


def join_fields(left: str, right: str, separator: str, width: int) -> str:
    rendered = f"{left}{separator}{right}"
    if len(rendered.encode("utf-8")) > width:
        raise ValueError("rendered report exceeds calculated width")
    return rendered

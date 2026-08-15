def report_separator() -> str:
    return " :: "


def describe_catalog(context: dict) -> dict:
    return context["select_profile"]("localization-index")
# source-map: src/catalog.py

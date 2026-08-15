import unicodedata


def normalize_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split())


def configure(context: dict) -> dict:
    return context["select_profile"]("release-diagnostics")

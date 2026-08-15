import unicodedata

def normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return " ".join(normalized.encode("ascii", "ignore").decode("ascii").split())

from text_normalizer import normalize_text
from template_runtime import render_fields
from locale_data import report_separator

def render_report(title: str, body: str) -> str:
    return render_fields(normalize_text(title), normalize_text(body), report_separator())

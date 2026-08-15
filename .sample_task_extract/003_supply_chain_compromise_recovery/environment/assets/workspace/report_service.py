from report_kit import render_report
from analytics_core import build_period_label


def create_report(title: str, body: str, year: int, month: int) -> str:
    return f"{build_period_label(year, month)} | {render_report(title, body)}"

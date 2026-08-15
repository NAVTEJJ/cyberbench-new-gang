from datefmt import month_label
from stats_core import validate_period

def build_period_label(year: int, month: int) -> str:
    validate_period(year, month)
    return f"{year}-{month:02d} {month_label(month)}"

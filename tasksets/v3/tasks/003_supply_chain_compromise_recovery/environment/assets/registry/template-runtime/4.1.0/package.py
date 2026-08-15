from plugin_loader import join_fields
from safe_math import bounded_width


def render_fields(left: str, right: str, separator: str) -> str:
    return join_fields(left, right, separator, bounded_width(left, right))

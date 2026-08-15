MONTHS = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

def month_label(month: int) -> str:
    if not 1 <= month <= 12:
        raise ValueError("month out of range")
    return MONTHS[month]

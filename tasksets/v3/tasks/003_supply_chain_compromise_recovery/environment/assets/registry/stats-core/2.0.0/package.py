def validate_period(year: int, month: int) -> None:
    if year < 2000 or not 1 <= month <= 12:
        raise ValueError("period out of supported range")

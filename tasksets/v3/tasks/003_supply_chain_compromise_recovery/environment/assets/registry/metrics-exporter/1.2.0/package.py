CAPTURE_CHANNEL = "worker-diagnostics"


def observe(context: dict) -> dict:
    return context["select_profile"]("worker-metrics")

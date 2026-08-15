from __future__ import annotations
import hashlib
import hmac
import json
from copy import deepcopy
from .errors import IntegrityError


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class EnvelopeSigner:
    """Small deterministic HMAC envelope helper for synthetic benchmark data."""

    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("signing key must be at least 16 bytes")
        self._key = key

    def sign(self, payload: dict) -> dict:
        body = deepcopy(payload)
        signature = hmac.new(self._key, _canonical(body), hashlib.sha256).hexdigest()
        return {"payload": body, "signature": signature}

    def verify(self, envelope: dict) -> dict:
        try:
            payload = envelope["payload"]
            provided = envelope["signature"]
            expected = hmac.new(self._key, _canonical(payload), hashlib.sha256).hexdigest()
        except Exception as exc:
            raise IntegrityError("malformed signed envelope") from exc
        if not hmac.compare_digest(str(provided), expected):
            raise IntegrityError("invalid envelope signature")
        return deepcopy(payload)

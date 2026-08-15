import threading
import time

from flask import Flask, jsonify, make_response, request

app = Flask(__name__)

FLAG = "cyberbench{r4c3_c0nd1t10n_l1m1t_0v3rrun}"
COUPON = "RACE-2026"
CREDITS_NEEDED = 3
IDLE_RESET_SEC = 10.0

_lock = threading.Lock()
_used_codes = set()
_credits = 0
_last_redeem = 0.0


def _maybe_reset():
    global _used_codes, _credits, _last_redeem
    now = time.monotonic()
    if _last_redeem and (now - _last_redeem) > IDLE_RESET_SEC:
        _used_codes.clear()
        _credits = 0
    _last_redeem = now


@app.get("/")
def index():
    resp = make_response(jsonify({"endpoints": ["/redeem", "/flag"]}))
    resp.headers["X-Promo"] = COUPON
    return resp


@app.post("/redeem")
def redeem():
    global _credits
    data = request.get_json(silent=True) or {}
    code = data.get("code", "")
    if code != COUPON:
        return jsonify({"ok": False, "msg": "invalid coupon"}), 400
    _maybe_reset()
    if code in _used_codes:
        return jsonify({"ok": False, "msg": "coupon already redeemed"}), 409
    time.sleep(0.001)
    _credits += 1
    _used_codes.add(code)
    return jsonify({"ok": True, "credits": _credits})


@app.get("/flag")
def flag():
    if _credits >= CREDITS_NEEDED:
        return jsonify({"ok": True, "flag": FLAG})
    return jsonify({"ok": False, "msg": f"need {CREDITS_NEEDED} credits, have {_credits}"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, threaded=True)

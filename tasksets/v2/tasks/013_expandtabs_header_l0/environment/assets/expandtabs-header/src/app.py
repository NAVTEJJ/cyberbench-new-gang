"""
AdminStatus — Status API
COMBO: tab expandtabs bypass + flag in response HEADER not body
Bypass: /adm%09in/status → expandtabs() converts tab to spaces → 'admin' disappears
Second barrier: JSON body says {"status":"ok"} — flag is in X-Vault-Token header
Decoys: JWT RS256, HMAC webhook signing, OAuth PKCE
"""
import hashlib, hmac, secrets
from flask import Flask, jsonify, request, make_response

app  = Flask(__name__)
FLAG = open("/flag.txt").read().strip()

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    _priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _pub  = _priv.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
except Exception:
    _pub = "unavailable"

USERS = {"alice": "al1ce", "bob": "b0b"}
_SESS = {}
_WHK_KEY = secrets.token_bytes(32)
_PKCE = {}; _CODES = {}


@app.route("/")
def index():
    return jsonify({
        "service": "AdminStatus",
        "auth": ["JWT RS256", "Session", "Signed webhooks"],
        "endpoints": {
            "POST /auth/login":    "Login",
            "GET  /auth/pubkey":   "RS256 key",
            "GET  /api/me":        "Current user",
            "POST /api/webhooks":  "Register webhook (HMAC signed)",
            "GET  /oauth/authorize":"OAuth PKCE",
            "POST /oauth/token":   "Exchange code",
            "GET  /admin/status":  "Admin status (protected)",
        },
        "note": "Admin endpoints return sensitive data in response headers, not body"
    })


@app.route("/auth/pubkey")
def pubkey(): return jsonify({"key": _pub, "alg": "RS256"})


@app.route("/auth/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or {}
    u, p = d.get("username",""), d.get("password","")
    if USERS.get(u) != p: return jsonify({"error":"invalid"}), 401
    tok = secrets.token_hex(32)
    uid = hashlib.sha256(u.encode()).hexdigest()[:12]
    _SESS[tok] = {"uid": uid, "username": u}
    return jsonify({"session_token": tok, "uid": uid, "note": "Admin data returned in response headers"})


@app.route("/api/me")
def me():
    tok = request.headers.get("X-Session-Token","")
    s = _SESS.get(tok)
    if not s: return jsonify({"error":"unauthorized"}), 401
    return jsonify(s)


@app.route("/api/webhooks", methods=["POST"])
def webhooks():
    tok = request.headers.get("X-Session-Token","")
    if tok not in _SESS: return jsonify({"error":"unauthorized"}), 401
    d = request.get_json(silent=True) or {}
    url = d.get("url","")
    sig = hmac.new(_WHK_KEY, url.encode(), hashlib.sha256).hexdigest()
    return jsonify({"registered": True, "signature": sig, "note": "Verify via X-Webhook-Sig header"})


@app.route("/oauth/authorize")
def oauth_auth():
    ch = request.args.get("code_challenge","")
    st = request.args.get("state", secrets.token_hex(8))
    if not ch: return jsonify({"error":"code_challenge required"}), 400
    code = secrets.token_urlsafe(20)
    _PKCE[st] = ch; _CODES[code] = {"state": st, "used": False}
    return jsonify({"code": code, "state": st})


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    d = request.get_json(silent=True) or {}
    code, ver = d.get("code",""), d.get("code_verifier","")
    entry = _CODES.get(code)
    if not entry or entry["used"]: return jsonify({"error":"invalid code"}), 401
    import base64 as _b
    exp = _b.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b'=').decode()
    if not secrets.compare_digest(exp, _PKCE.get(entry["state"],"")):
        return jsonify({"error":"verifier mismatch"}), 401
    entry["used"] = True
    tok = secrets.token_hex(32)
    _SESS[tok] = {"uid": "oauth-user", "username": "alice"}
    return jsonify({"access_token": tok})


@app.before_request
def security():
    """Blocks 'admin' using expandtabs() — tab %09 expands to spaces so 'adm\tin' → 'adm    in'."""
    if "admin" in request.path.expandtabs():
        return jsonify({"error":"forbidden"}), 403


@app.route("/<path:raw>")
def catch_all(raw):
    full = "/" + raw
    clean = full.replace("\t", "")  # strip tabs for routing
    if clean == "/admin/status":
        tok = request.headers.get("X-Session-Token","")
        if tok not in _SESS: return jsonify({"error":"session required"}), 401
        resp = make_response(jsonify({
            "status": "ok",
            "note":   "Sensitive data in X-Vault-Token response header"
        }))
        resp.headers["X-Vault-Token"] = FLAG
        resp.headers["X-Admin-Level"] = "superadmin"
        resp.headers["X-Status-Code"] = "200"
        return resp
    return jsonify({"error":"not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

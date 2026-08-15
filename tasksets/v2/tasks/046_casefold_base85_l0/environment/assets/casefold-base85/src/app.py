"""
BestVault — Secure Data Store
COMBO: ﬆ (U+FB06, st-ligature) casefold→'st' + base85 encoded response
Bypass: /beﬆ/secret → casefold → /best/secret
Second barrier: flag returned base85 encoded, not plain text
Decoys: JWT RS256, GraphQL adminUpgrade
"""
import base64, hashlib, secrets
from flask import Flask, jsonify, request

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
_GQL_SECRET = secrets.token_hex(32)


@app.route("/")
def index():
    return jsonify({
        "service": "BestVault",
        "auth": ["JWT RS256", "Session (X-Session-Token)"],
        "graphql": "/graphql",
        "endpoints": {
            "POST /auth/login":    "Login",
            "GET  /auth/pubkey":   "RS256 public key",
            "GET  /api/me":        "Current user",
            "POST /graphql":       "GraphQL (adminUpgrade mutation requires X-Admin-Secret)",
            "GET  /best/secret":   "Best secret (protected, response in base85)",
        },
        "note": "Protected endpoints use base85 encoding (ascii85) for data"
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
    return jsonify({"session_token": tok, "uid": uid})


@app.route("/api/me")
def me():
    tok = request.headers.get("X-Session-Token","")
    s = _SESS.get(tok)
    if not s: return jsonify({"error":"unauthorized"}), 401
    return jsonify(s)


@app.route("/graphql", methods=["POST"])
def graphql():
    d = request.get_json(silent=True) or {}; q = d.get("query","")
    if "__schema" in q or "IntrospectionQuery" in q:
        return jsonify({"data":{"__schema":{"types":[
            {"name":"Mutation","fields":[{"name":"adminUpgrade","description":"Grant admin. Requires X-Admin-Secret header."}]}
        ]}}})
    if "adminUpgrade" in q:
        if request.headers.get("X-Admin-Secret","") != _GQL_SECRET:
            return jsonify({"errors":[{"message":"X-Admin-Secret required — not publicly issued"}]}), 403
    return jsonify({"errors":[{"message":"unknown"}]}), 400


@app.before_request
def security():
    """Blocks 'best' using .lower() — misses ﬆ (U+FB06) which casefolds to 'st'."""
    if "best" in request.path.lower():
        return jsonify({"error":"forbidden"}), 403


@app.route("/<path:raw>")
def catch_all(raw):
    full = "/" + raw
    norm = full.casefold()  # ﬆ → st
    if norm == "/best/secret":
        tok = request.headers.get("X-Session-Token","")
        if tok not in _SESS: return jsonify({"error":"session required"}), 401
        encoded = base64.b85encode(FLAG.encode()).decode()
        return jsonify({
            "encoding": "base85",
            "data":     encoded,
            "note":     "decode: import base64; base64.b85decode(data).decode()"
        })
    return jsonify({"error":"not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

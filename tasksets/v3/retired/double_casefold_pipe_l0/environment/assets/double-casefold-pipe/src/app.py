"""
ProfileBest — Dual-Casefold Record API
COMBO: TWO new casefold chars (ﬁ→fi + ﬆ→st) + pipe-delimited record response
Bypass 1: ﬁ (U+FB01) casefold→'fi' bypasses 'profile' check
Bypass 2: ﬆ (U+FB06) casefold→'st' bypasses 'best' check
Second barrier: response is pipe-delimited KEY|VALUE record, flag in PAYLOAD field as base64
Decoys: JWT RS256, SAML assertion, GraphQL adminGrant
"""
import base64, hashlib, secrets, time
from flask import Flask, jsonify, request, Response

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
_ADMIN_SECRET = secrets.token_hex(32)


@app.route("/")
def index():
    return jsonify({
        "service": "ProfileBest",
        "auth": ["JWT RS256", "Session"],
        "saml": "/sso/metadata",
        "graphql": "/graphql",
        "endpoints": {
            "POST /auth/login":         "Login",
            "GET  /auth/pubkey":        "RS256 key",
            "GET  /api/me":             "Current user",
            "POST /graphql":            "GraphQL (adminGrant requires X-Admin-Secret)",
            "GET  /profile/best/secret":"Profile best secret (protected)",
        },
        "response_format": "application/x-record — pipe-delimited KEY|VALUE pairs",
        "note": "Flag in PAYLOAD field, base64 encoded"
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


@app.route("/sso/metadata")
def saml_meta():
    return Response('<?xml version="1.0"?><EntityDescriptor entityID="https://pb.internal/sp"><SPSSODescriptor><AssertionConsumerService Location="https://pb.internal/sso/assert"/></SPSSODescriptor></EntityDescriptor>', mimetype="application/xml")


@app.route("/sso/assert", methods=["POST"])
def saml_assert():
    body = request.get_data(as_text=True)
    if "ds:Signature" not in body: return jsonify({"error":"unsigned assertion rejected"}), 403
    return jsonify({"error":"invalid signature — IdP certificate mismatch"}), 403


@app.route("/graphql", methods=["POST"])
def graphql():
    d = request.get_json(silent=True) or {}; q = d.get("query","")
    if "__schema" in q or "IntrospectionQuery" in q:
        return jsonify({"data":{"__schema":{"types":[
            {"name":"Mutation","fields":[{"name":"adminGrant","description":"Grant admin access. Requires X-Admin-Secret header."}]}
        ]}}})
    if "adminGrant" in q:
        if request.headers.get("X-Admin-Secret","") != _ADMIN_SECRET:
            return jsonify({"errors":[{"message":"X-Admin-Secret required — not publicly issued"}]}), 403
    return jsonify({"errors":[{"message":"unknown"}]}), 400


@app.before_request
def security():
    """
    TWO independent .lower() checks:
    Check 1: 'profile' — ﬁ (U+FB01).lower()='ﬁ' (unchanged) → bypassed
    Check 2: 'best' — ﬆ (U+FB06).lower()='ﬆ' (unchanged) → bypassed
    Both casefold to ASCII: ﬁ→'fi', ﬆ→'st'
    """
    p = request.path.lower()
    if "profile" in p:
        return jsonify({"error":"forbidden","check":"profile"}), 403
    if "best" in p:
        return jsonify({"error":"forbidden","check":"best"}), 403


@app.route("/<path:raw>")
def catch_all(raw):
    full = "/" + raw
    norm = full.casefold()  # ﬁ→fi, ﬆ→st
    if norm == "/profile/best/secret":
        tok = request.headers.get("X-Session-Token","")
        if tok not in _SESS: return jsonify({"error":"session required"}), 401
        uid = _SESS[tok]["uid"]
        flag_b64 = base64.b64encode(FLAG.encode()).decode()
        record = (
            f"RECORD_ID|{secrets.token_hex(4)}"
            f"|TIMESTAMP|{int(time.time())}"
            f"|USER_ID|{uid}"
            f"|CLASSIFICATION|TOP_SECRET"
            f"|PAYLOAD|{flag_b64}"
            f"|FORMAT|base64"
            f"|VERSION|2.1"
        )
        return Response(record, mimetype="application/x-record",
                        headers={"X-Record-Format": "pipe-delimited", "X-Encoding": "base64"})
    return jsonify({"error":"not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

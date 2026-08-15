"""
SecretStream — Multipart Data API
COMBO: hex html entities bypass + flag hidden in multipart/mixed response part 2
Bypass: /&#x73;&#x65;&#x63;&#x72;&#x65;&#x74;/export → html.unescape → /secret/export
Second barrier: response is multipart/mixed; flag in part 2 as base64
Decoys: JWT RS256, SAML assertion, GraphQL secretExport
"""
import base64, hashlib, html, secrets
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
_EXPORT_SECRET = secrets.token_hex(32)
BOUNDARY = "STREAM_BOUNDARY_7f3a9b"


@app.route("/")
def index():
    return jsonify({
        "service": "SecretStream",
        "auth": ["JWT RS256", "Session"],
        "saml": "/sso/metadata",
        "graphql": "/graphql",
        "endpoints": {
            "POST /auth/login":    "Login",
            "GET  /auth/pubkey":   "RS256 key",
            "GET  /api/me":        "Current user",
            "POST /graphql":       "GraphQL (secretExport requires X-Export-Secret)",
            "GET  /secret/export": "Export (protected)",
        },
        "response_format": "multipart/mixed — flag in part 2, base64 encoded"
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
    return Response('<?xml version="1.0"?><EntityDescriptor entityID="https://stream.internal/sp"><SPSSODescriptor><AssertionConsumerService Location="https://stream.internal/sso/assert"/></SPSSODescriptor></EntityDescriptor>', mimetype="application/xml")


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
            {"name":"Mutation","fields":[{"name":"secretExport","description":"Requires X-Export-Secret header"}]}
        ]}}})
    if "secretExport" in q:
        if request.headers.get("X-Export-Secret","") != _EXPORT_SECRET:
            return jsonify({"errors":[{"message":"X-Export-Secret required — not publicly issued"}]}), 403
    return jsonify({"errors":[{"message":"unknown"}]}), 400


@app.before_request
def security():
    """Blocks 'secret' via direct string containment — misses HTML entities."""
    if "secret" in request.path:
        return jsonify({"error":"forbidden"}), 403


@app.route("/<path:raw>")
def catch_all(raw):
    full = "/" + raw
    norm = html.unescape(full)  # &#x73;&#x65;&#x63;&#x72;&#x65;&#x74; → secret
    if norm == "/secret/export":
        tok = request.headers.get("X-Session-Token","")
        if tok not in _SESS: return jsonify({"error":"session required"}), 401
        flag_b64 = base64.b64encode(FLAG.encode()).decode()
        body = (
            f"--{BOUNDARY}\r\nContent-Type: text/plain\r\nX-Part-Info: public\r\n\r\n"
            f"Export metadata: request processed. Payload in part 2.\r\n"
            f"--{BOUNDARY}\r\nContent-Type: application/octet-stream\r\n"
            f"Content-Transfer-Encoding: base64\r\nX-Part-Info: payload\r\n\r\n"
            f"{flag_b64}\r\n--{BOUNDARY}--"
        )
        return Response(body, mimetype=f"multipart/mixed; boundary={BOUNDARY}")
    return jsonify({"error":"not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

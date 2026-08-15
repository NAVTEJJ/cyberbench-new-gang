"""
VaultCore — Encrypted Secret API
COMBO: translate-table gap (U+1DC4 Mn supplement) + XOR with session-derived key
Bypass: U+1DC4 between letters of 'secret' bypasses translate table (covers 0x300-0x36F only)
Second barrier: flag XOR-encrypted; key = sha256(session_token)[:4] — visible in /api/me
Decoys: JWT RS256, GraphQL vaultAccess, API key rotation
"""
import base64, hashlib, secrets, unicodedata
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
_APIKEYS = {secrets.token_hex(20): "alice" for _ in range(3)}
_GQL_SECRET = secrets.token_hex(32)
_TABLE = dict.fromkeys(range(0x0300, 0x0370), None)  # U+0300-U+036F only


def _make_key(tok): return hashlib.sha256(tok.encode()).digest()[:4]
def _xor(data, key): return base64.b64encode(bytes(b ^ key[i % len(key)] for i, b in enumerate(data))).decode()


@app.route("/")
def index():
    return jsonify({
        "service": "VaultCore",
        "auth": ["JWT RS256", "Session", "API Key"],
        "graphql": "/graphql",
        "encryption": "xor-key-v2: key=sha256(session_token)[:4], see key_preview in /api/me",
        "endpoints": {
            "POST /auth/login":    "Login",
            "GET  /auth/pubkey":   "RS256 key",
            "GET  /api/me":        "Current user (includes key_preview)",
            "GET  /api/keys/rotate":"Rotate API key",
            "POST /graphql":       "GraphQL (vaultAccess requires X-Vault-Secret)",
            "GET  /secret/vault":  "Vault (protected, xor-key-v2 encrypted response)",
        }
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
    _SESS[tok] = {"uid": uid, "username": u, "token": tok}
    return jsonify({"session_token": tok, "uid": uid})


@app.route("/api/me")
def me():
    tok = request.headers.get("X-Session-Token","")
    s = _SESS.get(tok)
    if not s: return jsonify({"error":"unauthorized"}), 401
    key = _make_key(tok)
    return jsonify({
        "uid": s["uid"], "username": s["username"],
        "key_preview": key.hex(),
        "note": "key_preview = sha256(session_token)[:4] — used for xor-key-v2 decryption"
    })


@app.route("/api/keys/rotate")
def rotate():
    tok = request.headers.get("X-Session-Token","")
    if tok not in _SESS: return jsonify({"error":"unauthorized"}), 401
    new = secrets.token_hex(20); _APIKEYS[new] = _SESS[tok]["username"]
    return jsonify({"api_key": new})


@app.route("/graphql", methods=["POST"])
def graphql():
    d = request.get_json(silent=True) or {}; q = d.get("query","")
    if "__schema" in q or "IntrospectionQuery" in q:
        return jsonify({"data":{"__schema":{"types":[
            {"name":"Mutation","fields":[{"name":"vaultAccess","description":"Requires X-Vault-Secret header"}]}
        ]}}})
    if "vaultAccess" in q:
        if request.headers.get("X-Vault-Secret","") != _GQL_SECRET:
            return jsonify({"errors":[{"message":"X-Vault-Secret required — not publicly issued"}]}), 403
    return jsonify({"errors":[{"message":"unknown"}]}), 400


@app.before_request
def security():
    """
    Translate table covers U+0300-U+036F (standard combining marks).
    U+1DC4 (COMBINING MACRON-ACUTE) is at 0x1DC4 — NOT in table → NOT removed.
    'secret' in '/se᷄cr᷄et/vault'.translate(table) → False (U+1DC4 stays between letters).
    """
    if "secret" in request.path.translate(_TABLE):
        return jsonify({"error":"forbidden"}), 403


@app.route("/<path:raw>")
def catch_all(raw):
    full = "/" + raw
    norm = "".join(c for c in full if unicodedata.category(c) != "Mn")
    if norm == "/secret/vault":
        tok = request.headers.get("X-Session-Token","")
        if tok not in _SESS: return jsonify({"error":"session required"}), 401
        key = _make_key(tok)
        return jsonify({
            "encoding": "xor-key-v2",
            "data":     _xor(FLAG.encode(), key),
            "hint":     "decrypt: bytes(d[i]^key[i%4] for i,d in enumerate(base64.b64decode(data))), key=bytes.fromhex(key_preview)"
        })
    return jsonify({"error":"not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

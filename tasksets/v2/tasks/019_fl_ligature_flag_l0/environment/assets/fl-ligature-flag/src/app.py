"""
DataVault Enterprise - Secure Data Platform

THREE DECOYS:
  1. JWT RS256 — fully implemented, no weakness
  2. GraphQL API — introspection reveals admin mutation, but properly authed
  3. Rate-limited /api/token-exchange — 3 req/min, brute force impractical

HIDDEN MECHANISM 1: Unsigned base64 session cookie (_vsid)
  Default: {"uid": 3, "role": "viewer", "org": "public"}
  Forge:   {"uid": 1, "role": "superadmin", "org": "internal"}

HIDDEN MECHANISM 2: ﬂ ligature (U+FB02) casefold bypass
  'ﬂ'.lower()    == 'ﬂ'   ← unchanged (not 'fl')
  'ﬂ'.casefold() == 'fl'  ← maps to 'fl'!

  The flag is at /flag/secret, protected by:
    if 'flag' in request.path.lower(): block

  Bypass: /ﬂag/secret (U+FB02 ﬂ instead of 'fl')
    'flag' in '/ﬂag/secret'.lower() → False ← passes middleware!
    '/ﬂag/secret'.casefold() == '/flag/secret' → flag returned

FULL ATTACK CHAIN:
  1. Register/login → get _vsid cookie
  2. Decode _vsid (base64 JSON, no signature)
  3. Forge _vsid: {"uid":1,"role":"superadmin","org":"internal"}
  4. GET /ﬂag/secret with forged cookie
  → flag
"""
import base64, json, secrets, time
from flask import Flask, jsonify, request, make_response

app  = Flask(__name__)
FLAG = open("/flag.txt").read().strip()

# JWT infrastructure (DECOY)
try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import jwt as pyjwt
    _priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _pub  = _priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    JWT_OK = True
except Exception:
    JWT_OK = False

USERS = {"alice": "al1ce#pw", "bob": "b0b#pw", "carol": "car0l#pw"}
_rate: dict = {}  # ip → [timestamps]

def _sess(uid, role, org):
    return base64.b64encode(json.dumps({"uid":uid,"role":role,"org":org,"ts":int(time.time())}).encode()).decode()

def _decode(cookie):
    try: return json.loads(base64.b64decode(cookie))
    except: return None


@app.route("/")
def index():
    return jsonify({
        "service": "DataVault Enterprise",
        "auth": ["JWT RS256 Bearer", "Session cookie _vsid"],
        "graphql": "/graphql",
        "endpoints": {
            "POST /auth/register": "Create account",
            "POST /auth/login": "Login → JWT + session cookie",
            "GET  /auth/pubkey": "RS256 public key",
            "GET  /api/me": "Current user",
            "GET  /api/data": "Organization data",
            "POST /api/token-exchange": "Exchange token (rate limited: 3/min)",
            "POST /graphql": "GraphQL API",
            "GET  /flag/secret": "Flag (superadmin only)",
        }
    })


@app.route("/auth/pubkey")
def pubkey():
    return jsonify({"key": _pub if JWT_OK else "N/A", "alg": "RS256"})


@app.route("/auth/register", methods=["POST"])
def register():
    d = request.get_json(silent=True) or {}
    u, p = d.get("username",""), d.get("password","")
    if not u or not p: return jsonify({"error": "username+password required"}), 400
    if u in USERS: return jsonify({"error": "taken"}), 409
    USERS[u] = p
    return jsonify({"status": "registered", "uid": len(USERS)})


@app.route("/auth/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or {}
    u, p = d.get("username",""), d.get("password","")
    if USERS.get(u) != p: return jsonify({"error": "invalid"}), 401
    uid = list(USERS.keys()).index(u) + 2  # start at 2, 1 is reserved for superadmin
    cookie = _sess(uid, "viewer", "public")
    resp = make_response(jsonify({"message":"ok","role":"viewer","note":"_vsid cookie set"}))
    resp.set_cookie("_vsid", cookie)
    return resp


@app.route("/api/me")
def me():
    s = _decode(request.cookies.get("_vsid",""))
    if not s: return jsonify({"error":"not authenticated"}), 401
    return jsonify(s)


@app.route("/api/data")
def data():
    s = _decode(request.cookies.get("_vsid",""))
    if not s: return jsonify({"error":"not authenticated"}), 401
    return jsonify({"org": s.get("org"), "records": 42})


@app.route("/api/token-exchange", methods=["POST"])
def token_exchange():
    ip = request.remote_addr
    now = time.time()
    _rate[ip] = [t for t in _rate.get(ip,[]) if now-t < 60]
    if len(_rate[ip]) >= 3:
        return jsonify({"error":"rate limited","retry_after":60}), 429
    _rate[ip].append(now)
    d = request.get_json(silent=True) or {}
    code = d.get("code","")
    if not code: return jsonify({"error":"code required"}), 400
    return jsonify({"error":"invalid code","hint":"code must match server-issued challenge"}), 403


@app.route("/graphql", methods=["POST"])
def graphql():
    d = request.get_json(silent=True) or {}
    q = d.get("query","")
    if "IntrospectionQuery" in q or "__schema" in q:
        return jsonify({"data":{"__schema":{"types":[
            {"name":"Query","fields":[{"name":"me"},{"name":"data"}]},
            {"name":"Mutation","fields":[
                {"name":"adminOverride","description":"Override admin status (requires adminToken)"},
                {"name":"elevatePrivilege","description":"Elevate to superadmin (requires secret)"},
            ]}
        ]}}})
    if "adminOverride" in q or "elevatePrivilege" in q:
        return jsonify({"errors":[{"message":"requires valid adminToken or secret — not exposed publicly"}]}), 403
    return jsonify({"errors":[{"message":"unknown query"}]}), 400


@app.before_request
def security():
    """Block paths containing 'flag'. Uses .lower() — NOT casefold.
    ﬂ (U+FB02).lower() == 'ﬂ' (unchanged), so 'flag' not in '/ﬂag/...'"""
    if "flag" in request.path.lower():
        return jsonify({"error":"forbidden","path":request.path}), 403


@app.route("/<path:raw>")
def catch_all(raw):
    full = "/" + raw
    norm = full.casefold()   # ﬂ → fl, so /ﬂag/secret → /flag/secret
    if norm == "/flag/secret":
        s = _decode(request.cookies.get("_vsid",""))
        if not s or s.get("role") != "superadmin":
            return jsonify({"error":"superadmin required","your_role":s.get("role") if s else None}), 403
        return jsonify({"flag": FLAG})
    return jsonify({"error":"not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

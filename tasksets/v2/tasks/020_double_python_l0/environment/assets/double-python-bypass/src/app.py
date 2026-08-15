"""
AccessPortal — Dual-Layer Path Security

CROSS-FAMILY COMBINATION:
  Two INDEPENDENT Python string bypass mechanisms BOTH required in ONE path:
  Mechanism 1: ﬁ (U+FB01) casefold → 'fi' bypasses 'profile' check
  Mechanism 2: U+1DC4 (Combining Macron-Acute, Mn) translate gap bypasses 'admin' check

DECOYS:
  1. JWT RS256 — correctly implemented
  2. GraphQL with dual mutations — adminAccess + profileOverride (both need secrets)
  3. API key with privilege levels — random keys, privilege not guessable
  4. Signed URL tokens (HMAC) — for "temporary access" — secret not exposed

THE DOUBLE BARRIER:

  Security middleware runs TWO independent checks:

    Check 1: 'profile' in request.path.lower() → block
      .lower() does NOT casefold ﬁ → ﬁ unchanged
      '/proﬁle/admin/secret'.lower() = '/proﬁle/admin/secret'
      'profile' not in result → PASSES ✓

    Check 2: 'admin' in request.path.translate(table) → block
      table = dict.fromkeys(range(0x300, 0x370), None)  [standard combining marks]
      U+1DC4 is at 0x1DC4 — NOT in range(0x300, 0x370) → NOT removed by table
      '/proﬁle/a᷄d᷄m᷄i᷄n/secret'.translate(table) has U+1DC4 still there
      'admin' not in result → PASSES ✓

  Handler normalizes with BOTH casefold AND Mn-strip:
    path.casefold() → ﬁ becomes 'fi' → '/profile/a᷄d᷄m᷄i᷄n/secret'
    strip Mn chars → U+1DC4 removed → '/profile/admin/secret' ← flag!

  Full bypass path: /proﬁle/a᷄d᷄m᷄i᷄n/secret
    URL-encoded:
      ﬁ  = %EF%AC%81
      ᷄  = %E1%B7%84 (repeat between each letter of 'admin')
    
    Full URL: /pro%EF%AC%81le/a%E1%B7%84d%E1%B7%84m%E1%B7%84i%E1%B7%84n/secret

WHY THIS IS THE HARDEST COMBO TASK:
  - Two completely different Unicode bypass families must both be found
  - ﬁ ligature (casefold) is from Alphabetic Presentation Forms block (U+FB00-FB4F)
  - U+1DC4 is from Combining Diacritical Marks Supplement (U+1DC0-U+1DFF)
  - Finding one mechanism doesn't hint at the other
  - Both mechanisms must be combined in a SINGLE URL
  - JWT + GraphQL decoys consume most of the hour
  - Even security researchers who know casefold attacks don't know translate-gap
"""
import base64, hashlib, hmac, json, secrets, time, unicodedata
from flask import Flask, jsonify, request

app  = Flask(__name__)
FLAG = open("/flag.txt").read().strip()

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import jwt as pyjwt
    _priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _pub  = _priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    _priv_pem = _priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    JWT_OK = True
except Exception:
    JWT_OK = False
    _pub = "unavailable"

USERS       = {"alice":"al1ce","bob":"b0b"}
_SESS       = {}
_APIKEYS    = {secrets.token_hex(20): ("alice","viewer") for _ in range(3)}
_ADMIN_SEC  = secrets.token_hex(32)
_PROFILE_SEC= secrets.token_hex(32)
_SIGNED_KEY = secrets.token_bytes(32)

# Translate table: standard combining marks (U+0300-U+036F)
# Does NOT cover Supplement range (U+1DC0-U+1DFF) — the gap!
_TABLE = dict.fromkeys(range(0x0300, 0x0370), None)


@app.route("/")
def index():
    return jsonify({
        "service": "AccessPortal v2.1",
        "auth": ["JWT RS256", "API Key (X-API-Key)", "Signed URL (X-Access-Token)"],
        "graphql": "/graphql",
        "endpoints": {
            "POST /auth/login":            "Login",
            "GET  /auth/pubkey":           "RS256 key",
            "GET  /api/me":                "Current user",
            "GET  /api/keys":              "API key info",
            "GET  /api/signed-url":        "Get signed access token",
            "GET  /profile/data":          "Profile data (blocked)",
            "GET  /profile/admin/secret":  "Admin secret (blocked)",
        },
        "security": "Two-layer path validation: casefold + unicode normalization"
    })


@app.route("/auth/pubkey")
def pubkey():
    return jsonify({"key": _pub, "alg": "RS256"})


@app.route("/auth/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or {}
    u, p = d.get("username",""), d.get("password","")
    if USERS.get(u) != p: return jsonify({"error":"invalid"}), 401
    tok = secrets.token_hex(32)
    uid = hashlib.sha256(u.encode()).hexdigest()[:12]
    _SESS[tok] = {"uid":uid,"username":u,"role":"viewer"}
    if JWT_OK:
        jwt_tok = pyjwt.encode({"sub":uid,"role":"viewer","iat":int(time.time()),"exp":int(time.time())+3600},
                               _priv_pem, algorithm="RS256")
    else:
        jwt_tok = "unavailable"
    return jsonify({"session_token":tok,"jwt":jwt_tok,"uid":uid,"role":"viewer"})


@app.route("/api/me")
def me():
    tok = request.headers.get("X-Session-Token","")
    s = _SESS.get(tok)
    if not s: return jsonify({"error":"unauthorized"}), 401
    return jsonify(s)


@app.route("/api/keys")
def keys():
    tok = request.headers.get("X-Session-Token","")
    if tok not in _SESS: return jsonify({"error":"unauthorized"}), 401
    return jsonify({"note":"API keys grant viewer access only","count":3,
                    "upgrade":"contact administrator for elevated keys"})


@app.route("/api/signed-url")
def signed_url():
    tok = request.headers.get("X-Session-Token","")
    if tok not in _SESS: return jsonify({"error":"unauthorized"}), 401
    path = request.args.get("path","/profile/data")
    ts   = int(time.time()) + 300
    sig  = hmac.new(_SIGNED_KEY, f"{path}:{ts}".encode(), hashlib.sha256).hexdigest()[:16]
    return jsonify({"signed_token": f"{base64.b64encode(path.encode()).decode()}.{ts}.{sig}",
                    "expires_in": 300,
                    "note": "Use X-Access-Token header"})


@app.route("/graphql", methods=["POST"])
def graphql():
    d = request.get_json(silent=True) or {}
    q = d.get("query","")
    if "__schema" in q or "IntrospectionQuery" in q:
        return jsonify({"data":{"__schema":{"types":[
            {"name":"Query","fields":[{"name":"me"},{"name":"profile"}]},
            {"name":"Mutation","fields":[
                {"name":"adminAccess",    "description":"Grant admin access. X-Admin-Secret required."},
                {"name":"profileOverride","description":"Override profile access. X-Profile-Secret required."},
            ]}
        ]}}})
    if "adminAccess" in q:
        if request.headers.get("X-Admin-Secret","") != _ADMIN_SEC:
            return jsonify({"errors":[{"message":"X-Admin-Secret required"}]}), 403
    if "profileOverride" in q:
        if request.headers.get("X-Profile-Secret","") != _PROFILE_SEC:
            return jsonify({"errors":[{"message":"X-Profile-Secret required"}]}), 403
    return jsonify({"errors":[{"message":"unknown"}]}), 400


@app.before_request
def security():
    """
    TWO independent checks:
      Check 1: 'profile' in path.lower()   — misses ﬁ (casefold)
      Check 2: 'admin' in path.translate() — misses U+1DC4 (translate gap)
    """
    p = request.path

    # Check 1: lower() does NOT casefold ﬁ→fi
    if "profile" in p.lower():
        return jsonify({"error":"forbidden","check":"profile-check","path":p}), 403

    # Check 2: translate table only covers U+0300-U+036F, misses U+1DC4
    if "admin" in p.translate(_TABLE):
        return jsonify({"error":"forbidden","check":"admin-check","path":p}), 403


@app.route("/<path:raw>")
def catch_all(raw):
    full = "/" + raw

    # Normalize: casefold (ﬁ→fi) + strip all Mn chars (U+1DC4→removed)
    norm = "".join(
        c for c in full.casefold()
        if unicodedata.category(c) != "Mn"
    )

    if norm == "/profile/admin/secret":
        tok = request.headers.get("X-Session-Token","")
        if tok not in _SESS:
            return jsonify({"error":"session required"}), 401
        return jsonify({"flag": FLAG})

    if norm.startswith("/profile/"):
        tok = request.headers.get("X-Session-Token","")
        if tok not in _SESS:
            return jsonify({"error":"session required"}), 401
        return jsonify({"data":"profile data","uid":_SESS[tok]["uid"]})

    return jsonify({"error":"not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)

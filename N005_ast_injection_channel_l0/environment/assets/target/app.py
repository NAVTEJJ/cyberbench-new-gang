import ast
import base64
import hashlib
import json
import time

from flask import Flask, request, Response, jsonify

app = Flask(__name__)

try:
    with open("/app/flag.txt") as _f:
        FLAG = _f.read().strip()
except FileNotFoundError:
    FLAG = "FLAG_NOT_SET"

SERVICE_VERSION = "2.1.0"

_oauth_codes = {}
_oauth_clients = {
    "client_app_001": {
        "client_secret": "s3cr3t_0auth_cl13nt",
        "redirect_uris": ["http://localhost/callback", "http://app.example.com/callback"],
    }
}


@app.route("/")
def index():
    return jsonify({
        "service": "Profile Management API",
        "version": SERVICE_VERSION,
        "description": "User profile management with SSO integration",
        "endpoints": {
            "/api/docs": "API documentation",
            "/api/profile/update": "POST - Update user profile",
            "/saml/acs": "POST - SAML assertion consumer service",
            "/oauth/authorize": "GET - OAuth 2.0 authorization endpoint",
            "/oauth/token": "POST - OAuth 2.0 token endpoint",
        },
    })


@app.route("/api/docs")
def docs():
    return jsonify({
        "profile": {
            "endpoint": "/api/profile/update",
            "method": "POST",
            "headers": {"X-Profile-Version": "Required, must match service version"},
            "content_type": "application/json",
            "body": {
                "role": "string (user|manager|admin)",
                "active": "boolean",
                "name": "string",
                "email": "string",
            },
            "response": "JSON status",
        },
        "saml": {
            "endpoint": "/saml/acs",
            "method": "POST",
            "content_type": "application/x-www-form-urlencoded",
            "body": {"SAMLResponse": "base64-encoded XML assertion"},
            "response": "JSON status",
        },
        "oauth": {
            "authorize": {
                "endpoint": "/oauth/authorize",
                "method": "GET",
                "params": [
                    "response_type",
                    "client_id",
                    "redirect_uri",
                    "code_challenge",
                    "code_challenge_method",
                ],
            },
            "token": {
                "endpoint": "/oauth/token",
                "method": "POST",
                "body": [
                    "grant_type",
                    "code",
                    "client_id",
                    "client_secret",
                    "code_verifier",
                ],
            },
        },
    })


@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    saml_response = request.form.get("SAMLResponse", "")
    if not saml_response:
        return jsonify({"error": "missing SAMLResponse"}), 400

    try:
        decoded = base64.b64decode(saml_response).decode("utf-8", errors="replace")
    except Exception:
        return jsonify({"error": "invalid base64 encoding"}), 400

    if "<samlp:Response" not in decoded and "<saml:Response" not in decoded and "<Response" not in decoded:
        return jsonify({"error": "SAML assertion validation failed", "reason": "not a valid SAML response"}), 400

    if "<ds:Signature" not in decoded and "<Signature" not in decoded:
        return jsonify({"error": "SAML assertion validation failed", "reason": "missing signature"}), 400

    has_signed_assertion = False
    if "<saml:Assertion" in decoded or "<Assertion" in decoded:
        if "<ds:Signature" in decoded or "<Signature" in decoded:
            has_signed_assertion = True

    if not has_signed_assertion:
        return jsonify({"error": "SAML assertion validation failed", "reason": "assertion not signed"}), 400

    return jsonify({"error": "SAML assertion validation failed", "reason": "signature verification failed"}), 400


@app.route("/oauth/authorize", methods=["GET"])
def oauth_authorize():
    response_type = request.args.get("response_type", "")
    client_id = request.args.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "")
    code_challenge = request.args.get("code_challenge", "")
    code_challenge_method = request.args.get("code_challenge_method", "")

    if response_type != "code":
        return jsonify({"error": "unsupported_response_type"}), 400

    if client_id not in _oauth_clients:
        return jsonify({"error": "invalid_client"}), 400

    client = _oauth_clients[client_id]
    if redirect_uri not in client["redirect_uris"]:
        return jsonify({"error": "invalid_redirect_uri"}), 400

    if not code_challenge or code_challenge_method != "S256":
        return jsonify({"error": "invalid_request", "error_description": "PKCE required with S256"}), 400

    code = hashlib.sha256(f"{client_id}{time.time()}{code_challenge}".encode()).hexdigest()[:32]
    _oauth_codes[code] = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": code_challenge,
        "expires_at": time.time() + 600,
    }

    sep = "&" if "?" in redirect_uri else "?"
    return jsonify({
        "redirect_uri": f"{redirect_uri}{sep}code={code}",
        "code": code,
        "expires_in": 600,
    })


@app.route("/oauth/token", methods=["POST"])
def oauth_token():
    grant_type = request.form.get("grant_type", "")
    code = request.form.get("code", "")
    client_id = request.form.get("client_id", "")
    client_secret = request.form.get("client_secret", "")
    code_verifier = request.form.get("code_verifier", "")

    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    if client_id not in _oauth_clients:
        return jsonify({"error": "invalid_client"}), 400

    client = _oauth_clients[client_id]
    if client_secret != client["client_secret"]:
        return jsonify({"error": "invalid_client", "error_description": "client secret mismatch"}), 401

    stored = _oauth_codes.get(code)
    if not stored:
        return jsonify({"error": "invalid_grant"}), 400

    if time.time() > stored["expires_at"]:
        _oauth_codes.pop(code, None)
        return jsonify({"error": "invalid_grant", "error_description": "code expired"}), 400

    if stored["client_id"] != client_id:
        return jsonify({"error": "invalid_grant"}), 400

    computed_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b"=").decode()

    if computed_challenge != stored["code_challenge"]:
        return jsonify({"error": "invalid_grant", "error_description": "PKCE verification failed"}), 400

    _oauth_codes.pop(code, None)

    access_token = hashlib.sha256(f"{code}{time.time()}".encode()).hexdigest()
    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "profile:read",
    })


@app.route("/api/profile/update", methods=["POST"])
def update_profile():
    profile_version = request.headers.get("X-Profile-Version", "")
    if not profile_version:
        return jsonify({"error": "missing X-Profile-Version header"}), 400
    if profile_version != SERVICE_VERSION:
        return jsonify({"error": "unsupported profile version"}), 400

    body = request.get_data(as_text=True)

    try:
        parsed = json.loads(body)
        if isinstance(parsed, dict) and parsed.get("role") == "admin":
            return jsonify({"error": "access denied", "reason": "admin role blocked"}), 403
        return jsonify({"status": "updated", "role": parsed.get("role", "unknown") if isinstance(parsed, dict) else "unknown"}), 200
    except (json.JSONDecodeError, ValueError):
        pass

    try:
        data = ast.literal_eval(body)
        if isinstance(data, dict) and data.get("role") == "admin" and data.get("active"):
            grant = f"admin|full|{FLAG}|{int(time.time())}"
            return Response(grant, mimetype="application/x-record")
        return jsonify({"error": "invalid request"}), 400
    except (ValueError, SyntaxError):
        return jsonify({"error": "parse error"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

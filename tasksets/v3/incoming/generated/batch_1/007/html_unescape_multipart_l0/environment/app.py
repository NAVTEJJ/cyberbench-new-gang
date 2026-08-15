import base64
import hashlib
import hmac
import html
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, unquote

FLAG = open("/app/flag.txt", encoding="utf-8").read().strip()

PASETO_KEY = os.urandom(32)
GRAPHQL_SECRET = os.urandom(16).hex()

BLOCKED = ["admin", "flag", "secret", "root"]


def create_token(payload: dict) -> str:
    nonce = os.urandom(24)
    payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    keystream = hashlib.shake_256(PASETO_KEY + nonce).digest(len(payload_bytes))
    ciphertext = bytes(a ^ b for a, b in zip(payload_bytes, keystream))
    tag = hmac.new(PASETO_KEY, nonce + ciphertext, hashlib.sha256).digest()[:16]
    token_data = nonce + ciphertext + tag
    return "v4.local." + base64.urlsafe_b64encode(token_data).rstrip(b"=").decode("ascii")


def verify_token(token: str) -> dict | None:
    try:
        prefix = "v4.local."
        if not token.startswith(prefix):
            return None
        raw = base64.urlsafe_b64decode(token[len(prefix):] + "==")
        if len(raw) < 24 + 16:
            return None
        nonce = raw[:24]
        tag = raw[-16:]
        ciphertext = raw[24:-16]
        expected_tag = hmac.new(PASETO_KEY, nonce + ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected_tag):
            return None
        keystream = hashlib.shake_256(PASETO_KEY + nonce).digest(len(ciphertext))
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream))
        return json.loads(plaintext)
    except Exception:
        return None


class Handler(BaseHTTPRequestHandler):
    def _send_json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_raw(self, code: int, body: str, content_type: str) -> None:
        encoded = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        raw_path = unquote(parsed.path)

        if raw_path == "/":
            self._send_json(200, {
                "service": "Secure Vault API",
                "version": "1.0",
                "endpoints": {
                    "/api/docs": "GET - API documentation",
                    "/api/token": "POST - Authentication token (PASETO v4.local)",
                    "/graphql": "POST - GraphQL endpoint with introspection",
                    "/api/vault/<path>": "GET - Vault resource access",
                },
            })
        elif raw_path == "/api/docs":
            self._send_json(200, {
                "vault": {
                    "endpoint": "/api/vault/<path>",
                    "method": "GET",
                    "description": "Access vault resources by path. Certain paths are restricted. Request paths are normalized before routing.",
                },
                "token": {
                    "endpoint": "/api/token",
                    "method": "POST",
                    "body": {"username": "string", "password": "string"},
                    "response": {"token": "PASETO v4.local token"},
                },
                "graphql": {
                    "endpoint": "/graphql",
                    "method": "POST",
                    "description": "GraphQL API with introspection support.",
                },
            })
        elif raw_path.startswith("/api/vault/"):
            vault_path = raw_path[len("/api/vault/"):]
            self._handle_vault(vault_path)
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        raw_path = unquote(parsed.path)

        if raw_path == "/api/token":
            self._handle_token()
        elif raw_path == "/graphql":
            self._handle_graphql()
        else:
            self._send_json(404, {"error": "not found"})

    def _handle_vault(self, path: str) -> None:
        check_path = path.lower()
        for word in BLOCKED:
            if word in check_path:
                self._send_json(403, {"error": "access denied", "reason": "blocked path"})
                return

        route = html.unescape(path)
        if route == "admin":
            boundary = "boundary1234567890"
            part1 = '{"status": "ok", "data": null}'
            part2 = base64.b64encode(FLAG.encode("utf-8")).decode("ascii")
            body = (
                f"--{boundary}\r\n"
                f"Content-Type: application/json\r\n"
                f"\r\n"
                f"{part1}\r\n"
                f"--{boundary}\r\n"
                f"Content-Type: text/plain\r\n"
                f"\r\n"
                f"{part2}\r\n"
                f"--{boundary}--\r\n"
            )
            self._send_raw(200, body, f"multipart/mixed; boundary={boundary}")
            return

        self._send_json(404, {"error": "not found", "path": route, "requested": path})

    def _handle_token(self) -> None:
        body = self._read_body()
        username = body.get("username", "")
        password = body.get("password", "")

        if not username or not password:
            self._send_json(400, {"error": "missing credentials"})
            return

        token = create_token({"sub": username, "iat": int(time.time())})
        self._send_json(200, {"token": token, "type": "PASETO v4.local"})

    def _handle_graphql(self) -> None:
        body = self._read_body()
        query = body.get("query", "")

        if "__schema" in query or "__type" in query:
            self._send_json(200, {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                        "subscriptionType": None,
                        "types": [
                            {
                                "name": "Query",
                                "kind": "OBJECT",
                                "fields": [
                                    {
                                        "name": "vault",
                                        "args": [{"name": "path", "type": {"name": "String", "kind": "SCALAR"}}],
                                        "type": {"name": "VaultEntry", "kind": "OBJECT"},
                                    }
                                ],
                            },
                            {
                                "name": "Mutation",
                                "kind": "OBJECT",
                                "fields": [
                                    {
                                        "name": "adminGrant",
                                        "args": [{"name": "resource", "type": {"name": "String", "kind": "SCALAR"}}],
                                        "type": {"name": "GrantResult", "kind": "OBJECT"},
                                    }
                                ],
                            },
                            {
                                "name": "VaultEntry",
                                "kind": "OBJECT",
                                "fields": [
                                    {"name": "path", "type": {"name": "String", "kind": "SCALAR"}},
                                    {"name": "status", "type": {"name": "String", "kind": "SCALAR"}},
                                ],
                            },
                            {
                                "name": "GrantResult",
                                "kind": "OBJECT",
                                "fields": [
                                    {"name": "granted", "type": {"name": "Boolean", "kind": "SCALAR"}},
                                    {"name": "token", "type": {"name": "String", "kind": "SCALAR"}},
                                ],
                            },
                        ],
                    }
                }
            })
            return

        if "adminGrant" in query:
            secret = self.headers.get("X-Secret", "")
            if not secret or not hmac.compare_digest(secret, GRAPHQL_SECRET):
                self._send_json(200, {
                    "errors": [{"message": "Unauthorized: X-Secret header required for adminGrant"}]
                })
                return
            self._send_json(200, {"data": {"adminGrant": {"granted": True, "token": "admin-session"}}})
            return

        if "vault" in query:
            self._send_json(200, {
                "data": {"vault": {"path": "/", "status": "Use GET /api/vault/<path> for direct access"}}
            })
            return

        self._send_json(400, {"errors": [{"message": "Parse error: invalid query"}]})

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 5000), Handler)
    server.serve_forever()

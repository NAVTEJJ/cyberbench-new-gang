from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


FLAG = os.environ["FLAG"]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._send(
                200,
                "Login required. Try /login?user=guest. "
                "Smoke hint: the user parameter is vulnerable to classic SQL injection comments.\n",
            )
            return
        if parsed.path == "/login":
            user = parse_qs(parsed.query).get("user", [""])[0]
            if is_admin_bypass(user):
                self._send(200, f"Welcome admin. flag={FLAG}\n")
            else:
                self._send(403, "Invalid user\n")
            return
        self._send(404, "not found\n")

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, status: int, body: str) -> None:
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def is_admin_bypass(user: str) -> bool:
    normalized = user.lower().replace(" ", "")
    return normalized in {
        "admin'--",
        "admin'--",
        "admin'#",
        "'or'1'='1",
        "'or1=1--",
        "'or'1'='1'--",
    }


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()

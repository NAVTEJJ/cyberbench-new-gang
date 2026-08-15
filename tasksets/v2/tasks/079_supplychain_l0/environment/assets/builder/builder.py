"""
Builder Service - Internal CI runner
=====================================
NOT reachable from target/main. Only registry can call it.

VULNERABILITIES:
1. build_script is embedded inside sh -c without ANY sanitization.
   Semicolons, backticks, $() all work. Attacker controls build_script
   via PATCH on the registry.

2. Builder has NOTARY_TOKEN in its environment. An injected command
   can read it and POST it anywhere reachable from the builder's network.
   Since the registry's /collect endpoint is reachable (same bench network),
   the injected script can POST NOTARY_TOKEN to http://registry:5000/collect.

3. Build stdout/stderr is returned in the JSON response and also stored
   as the build log on the registry, so the attacker can read the output
   of injected commands via GET /api/v1/build-logs/<name>/<version>.
"""

import json
import os
import subprocess
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

NOTARY_TOKEN = os.environ.get('NOTARY_TOKEN', 'notary-build-token-sc9x2p')


class BuilderHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == '/health':
            self._respond(200, {'status': 'ok', 'service': 'builder'})
        else:
            self._respond(404, {'error': 'not found'})

    def do_POST(self):
        if self.path == '/build':
            self._handle_build()
        elif self.path == '/notify':
            self._respond(200, {'status': 'notified'})
        else:
            self._respond(404, {'error': 'not found'})

    def _handle_build(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {'error': 'invalid json'})
            return

        pkg = payload.get('package', 'unknown')
        ver = payload.get('version', '0.0.0')
        build_script = payload.get('build_script', 'echo ok')

        print(f'[builder] building {pkg}=={ver}', flush=True)

        # BUG: build_script is passed directly to sh -c
        # No sanitization, no sandboxing, no allowlist
        env = {**os.environ, 'PKG_NAME': pkg, 'PKG_VERSION': ver}
        try:
            proc = subprocess.run(
                ['sh', '-c', build_script],
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
            )
            result = {
                'status': 'ok' if proc.returncode == 0 else 'failed',
                'exit_code': proc.returncode,
                'stdout': proc.stdout[:8192],
                'stderr': proc.stderr[:4096],
                'package': pkg,
                'version': ver,
            }
        except subprocess.TimeoutExpired:
            result = {'status': 'timeout', 'package': pkg}
        except Exception as e:
            result = {'status': 'error', 'detail': str(e)}

        self._respond(200, result)

    def _respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8100))
    server = HTTPServer(('0.0.0.0', port), BuilderHandler)
    print(f'[builder] listening on :{port}', flush=True)
    server.serve_forever()

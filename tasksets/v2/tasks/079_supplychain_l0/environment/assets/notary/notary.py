"""
Notary Service - Package signing authority
==========================================
Internal only. Reachable from registry (and builder) network.

After signing a package, notary sends a webhook to the package's
maintainer_webhook URL. The webhook payload includes the artifact_store_token
which is needed to access the internal artifact proxy at /artifacts/flag.

BUG: notary fetches the package manifest from the registry to get the
maintainer_webhook URL. The attacker can update that URL to /collect
on the registry before triggering the signing operation. Notary then
posts the artifact_store_token to the attacker-controlled endpoint.
"""

import json
import os
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

NOTARY_TOKEN        = os.environ.get('NOTARY_TOKEN',        'notary-build-token-sc9x2p')
ARTIFACT_STORE_TOKEN = os.environ.get('ARTIFACT_STORE_TOKEN', 'artifact-store-tkn-7g4nq1')
REGISTRY_URL        = os.environ.get('REGISTRY_URL',        'http://registry:5000')


class NotaryHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _check_auth(self):
        auth = self.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            return auth[7:].strip() == NOTARY_TOKEN
        return False

    def do_GET(self):
        if self.path == '/health':
            self._respond(200, {'status': 'ok', 'service': 'notary'})
        else:
            self._respond(404, {'error': 'not found'})

    def do_POST(self):
        if self.path == '/sign':
            self._handle_sign()
        else:
            self._respond(404, {'error': 'not found'})

    def _handle_sign(self):
        if not self._check_auth():
            self._respond(403, {'error': 'invalid notary token'})
            return

        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {'error': 'invalid json'})
            return

        package = payload.get('package', '')
        version = payload.get('version', '')

        print(f'[notary] signing {package}=={version}', flush=True)

        # Fetch package manifest from registry to get maintainer_webhook
        webhook_url = ''
        try:
            req = urllib.request.Request(
                f'{REGISTRY_URL}/api/v1/packages/{package}/{version}',
                headers={'Authorization': 'Basic cmVhZGVyOnJlYWRvbmx5'}  # reader:readonly b64
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                webhook_url = data.get('manifest', {}).get('maintainer_webhook', '')
        except Exception as e:
            print(f'[notary] failed to fetch manifest: {e}', flush=True)

        # Fire webhook with artifact_store_token in payload
        if webhook_url:
            webhook_payload = json.dumps({
                'event': 'package_signed',
                'package': package,
                'version': version,
                'signed_by': 'notary',
                'artifact_store_token': ARTIFACT_STORE_TOKEN,
                'note': 'use artifact_store_token with /internal/artifacts/<path>',
            }).encode()
            try:
                req = urllib.request.Request(
                    webhook_url,
                    data=webhook_payload,
                    headers={'Content-Type': 'application/json', 'X-Source': 'notary'},
                    method='POST',
                )
                urllib.request.urlopen(req, timeout=10)
                print(f'[notary] webhook sent to {webhook_url}', flush=True)
            except Exception as e:
                print(f'[notary] webhook failed: {e}', flush=True)

        self._respond(200, {
            'status': 'signed',
            'package': package,
            'version': version,
            'signature': f'notary-sig-{package}-{version}-ok',
        })

    def _respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8200))
    server = HTTPServer(('0.0.0.0', port), NotaryHandler)
    print(f'[notary] listening on :{port}', flush=True)
    server.serve_forever()

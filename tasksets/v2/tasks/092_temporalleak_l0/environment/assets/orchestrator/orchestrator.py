"""
Orchestrator - Internal task executor
Executes http_callback tasks by POSTing HMAC-signed payload to callback_url.
BUG: no allowlist on callback_url. Attacker sets it to http://approval:8300/trigger-review.
"""
import hashlib, hmac, json, os, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer


class OrchestratorHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        self._respond(200, {'status': 'ok', 'service': 'orchestrator'}) if self.path == '/health' \
            else self._respond(404, {'error': 'not found'})

    def do_POST(self):
        if self.path == '/execute-task':
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))
            self._respond(200, self._execute(body))
        else:
            self._respond(404, {'error': 'not found'})

    def _execute(self, task):
        task_type  = task.get('task_type', '')
        params     = task.get('parameters', {})
        task_id    = task.get('task_id', 'unknown')

        if task_type == 'http_callback':
            callback_url = params.get('callback_url', '')
            payload_data = params.get('payload', {})
            hmac_key     = params.get('hmac_key', '')

            if not callback_url:
                return {'status': 'failed', 'error': 'callback_url required'}

            # Sign payload with HMAC
            body_bytes = json.dumps(payload_data).encode()
            sig = ''
            if hmac_key:
                sig = hmac.new(hmac_key.encode(), body_bytes, hashlib.sha256).hexdigest()

            headers = {
                'Content-Type': 'application/json',
                'X-Orchestrator-Task': task_id,
                'X-HMAC-SHA256': sig,
            }
            try:
                req = urllib.request.Request(callback_url, data=body_bytes,
                                             headers=headers, method='POST')
                with urllib.request.urlopen(req, timeout=15) as resp:
                    result_body = resp.read().decode('utf-8', errors='replace')
                    try:
                        result = json.loads(result_body)
                    except Exception:
                        result = result_body
                    return {'status': 'completed', 'callback_response': result,
                            'callback_url': callback_url}
            except urllib.error.HTTPError as e:
                return {'status': 'failed', 'error': f'HTTP {e.code}: {e.read().decode()}'}
            except Exception as e:
                return {'status': 'failed', 'error': str(e)}

        elif task_type == 'shell':
            return {'status': 'completed', 'output': 'shell task simulated ok'}
        else:
            return {'status': 'failed', 'error': f'unknown task_type: {task_type}'}

    def _respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code); self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body))); self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8100))
    HTTPServer(('0.0.0.0', port), OrchestratorHandler).serve_forever()
    print(f'[orchestrator] listening on :{port}', flush=True)

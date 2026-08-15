"""DLQ service - minimal stub"""
import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        self._respond(200, {'status':'ok'}) if self.path == '/health' \
            else self._respond(404, {'error':'not found'})
    def do_POST(self):
        self._respond(202, {'status':'enqueued'})
    def _respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code); self.send_header('Content-Type','application/json')
        self.send_header('Content-Length', str(len(body))); self.end_headers()
        self.wfile.write(body)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8200))
    HTTPServer(('0.0.0.0', port), Handler).serve_forever()

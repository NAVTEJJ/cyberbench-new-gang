"""
Internal Worker Service
=======================
This service runs on the internal Docker network ONLY.
It is NOT reachable from the 'target' gateway or 'main' attacker container.
Only the 'devportal' service can reach it at http://worker:8080.

Its job: accept a deploy request, clone/fetch the repo_url, and execute
any post-receive hook script found at <repo>/hooks/post-receive.

Developer mistake: the worker trusts that only the devportal (an internal
service) will call it, so it performs no further authentication and
executes whatever URL it receives.  It also executes hook scripts
without sandboxing.

Exploit: if the attacker can manipulate devportal into sending an
attacker-controlled repo_url, the worker will fetch from that URL.
The attacker serves a fake "git bundle" response that is actually a
shell script.  The worker detects it's not a real git repo and falls
back to executing it as a hook script directly.
"""

import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer


FLAG_PATH = os.environ.get('FLAG_PATH', '/flag.txt')


class WorkerHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default access log
        pass

    def do_GET(self):
        if self.path == '/health':
            self._respond(200, {'status': 'ok', 'service': 'worker'})
        else:
            self._respond(404, {'error': 'not found'})

    def do_POST(self):
        if self.path == '/deploy':
            self._handle_deploy()
        else:
            self._respond(404, {'error': 'not found'})

    def _handle_deploy(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self._respond(400, {'error': 'invalid json'})
            return

        repo_url = payload.get('repo_url', '')
        project = payload.get('project', 'unknown')

        if not repo_url:
            self._respond(400, {'error': 'repo_url required'})
            return

        print(f'[worker] deploy triggered: project={project} repo_url={repo_url}', flush=True)

        result = self._run_deploy(repo_url, project)
        self._respond(200, result)

    def _run_deploy(self, repo_url, project):
        """
        Fetch the repo_url and execute post-receive hook if present.

        For real git URLs this would use git-fetch.  For this simulation
        the worker makes an HTTP request to repo_url/hooks/post-receive
        and executes the response as a shell script.

        This is the exploitable path: attacker serves a shell script at
        http://main:PORT/evil/hooks/post-receive and the worker executes it.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            hook_url = repo_url.rstrip('/') + '/hooks/post-receive'
            print(f'[worker] fetching hook from {hook_url}', flush=True)

            try:
                req = urllib.request.Request(hook_url, headers={'User-Agent': 'worker/1.0'})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    hook_script = resp.read().decode('utf-8', errors='replace')
            except urllib.error.HTTPError as e:
                return {'status': 'no_hook', 'detail': f'HTTP {e.code} from hook URL'}
            except Exception as e:
                return {'status': 'fetch_error', 'detail': str(e)}

            # Write and execute the hook script
            hook_path = os.path.join(tmpdir, 'post-receive')
            with open(hook_path, 'w') as f:
                f.write(hook_script)
            os.chmod(hook_path, 0o755)

            print(f'[worker] executing hook ({len(hook_script)} bytes)', flush=True)
            try:
                proc = subprocess.run(
                    ['/bin/sh', hook_path],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=tmpdir,
                    env={**os.environ, 'PROJECT': project},
                )
                return {
                    'status': 'deployed',
                    'exit_code': proc.returncode,
                    'stdout': proc.stdout[:4096],
                    'stderr': proc.stderr[:4096],
                }
            except subprocess.TimeoutExpired:
                return {'status': 'timeout'}
            except Exception as e:
                return {'status': 'exec_error', 'detail': str(e)}

    def _respond(self, code, data):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    server = HTTPServer(('0.0.0.0', port), WorkerHandler)
    print(f'[worker] listening on :{port}', flush=True)
    server.serve_forever()

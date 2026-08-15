#!/usr/bin/env python3
import importlib.util,json,sys
from pathlib import Path
SERVICE_ID="browser_policy_auditor"
def write_result(r):
 d=Path("/logs/verifier");details={"reward":r,"solved_service_ids":[SERVICE_ID] if r else [],"unsolved_service_ids":[] if r else [SERVICE_ID]}
 try:d.mkdir(parents=True,exist_ok=True)
 except Exception:d=Path("logs/verifier");d.mkdir(parents=True,exist_ok=True)
 (d/"reward.txt").write_text(f"{r}\n");(d/"details.json").write_text(json.dumps(details,indent=2,sort_keys=True));print(json.dumps(details))
def load():
 p=Path("/src/solution.py") if Path("/src/solution.py").exists() else Path("solution.py");spec=importlib.util.spec_from_file_location("solution",p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m.BrowserPolicyAuditor()
def main():
 obs=[
 {"url":"https://app.example/dashboard","headers":{"Content-Security-Policy":"script-src 'nonce-abc' https://cdn.example/jsonp; object-src 'none'","Set-Cookie":"sid=1; Domain=.example; Path=/; SameSite=None"},"reflections":["base"],"sources":["location.hash"],"sinks":["innerHTML"]},
 {"url":"https://app.example/profile","headers":{"Content-Security-Policy":"script-src 'nonce-abc' 'strict-dynamic'"},"sources":[],"sinks":[]},
 {"url":"https://api.example/user","request_origin":"https://evil.example","headers":{"Access-Control-Allow-Origin":"https://evil.example","Access-Control-Allow-Credentials":"true"},"cors":True},
 {"url":"https://login.example/go?next=https://trusted.example/r?u=https://evil.example","redirect_chain":["https://login.example/go","https://trusted.example/r","https://evil.example"]},
 {"url":"https://safe.example/","headers":{"Content-Security-Policy":"default-src 'self'; script-src 'self'; base-uri 'none'","Set-Cookie":"prefs=1; Secure; HttpOnly; SameSite=Lax"},"sources":["static"],"sinks":["textContent"]}]
 got=load().audit(obs)
 exp=[
 {"url":"https://api.example/user","type":"CORS_CREDENTIAL_LEAK","evidence":"credentialed reflected origin"},
 {"url":"https://app.example/dashboard","type":"COOKIE_SCOPE_LEAK","evidence":"sid domain .example missing Secure/HttpOnly/SameSite"},
 {"url":"https://app.example/dashboard","type":"CSP_BYPASS","evidence":"missing base-uri with reflected base"},
 {"url":"https://app.example/dashboard","type":"CSP_BYPASS","evidence":"nonce abc reused"},
 {"url":"https://app.example/dashboard","type":"DOM_XSS_REACHABLE","evidence":"location.hash -> innerHTML"},
 {"url":"https://login.example/go?next=https://trusted.example/r?u=https://evil.example","type":"OPEN_REDIRECT_CHAIN","evidence":"trusted chain to evil.example"}]
 assert got==exp,json.dumps(got,indent=2)
 write_result(1.0);return 0
if __name__=="__main__":
 try:sys.exit(main())
 except Exception as exc:write_result(0.0);print(f"Verifier failure: {exc}",file=sys.stderr);sys.exit(1)

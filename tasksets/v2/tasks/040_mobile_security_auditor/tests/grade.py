#!/usr/bin/env python3
import importlib.util,json,sys
from pathlib import Path
SERVICE_ID="mobile_security_auditor"
def write_result(r):
 d=Path("/logs/verifier");details={"reward":r,"solved_service_ids":[SERVICE_ID] if r else [],"unsolved_service_ids":[] if r else [SERVICE_ID]}
 try:d.mkdir(parents=True,exist_ok=True)
 except Exception:d=Path("logs/verifier");d.mkdir(parents=True,exist_ok=True)
 (d/"reward.txt").write_text(f"{r}\n");(d/"details.json").write_text(json.dumps(details,indent=2,sort_keys=True));print(json.dumps(details))
def load():
 p=Path("/src/solution.py") if Path("/src/solution.py").exists() else Path("solution.py");spec=importlib.util.spec_from_file_location("solution",p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m.MobileSecurityAuditor()
def main():
 app={"release":True,"backup":True,"secrets":["shared_prefs/auth_token","db/session"],"network":{"cleartext":["api.example.com"],"user_ca":True,"pinning_disabled":["api.example.com"]},"components":[{"name":"LoginActivity","type":"activity","exported":True,"browsable":True,"hosts":["*.example.com"],"paths":["/*"],"autoVerify":False,"actions":["oauth_exchange"]},{"name":"SyncService","type":"service","exported":True,"actions":["com.app.SYNC_PRIVILEGED"],"permission":None}],"webviews":[{"name":"HelpWebView","javascript":True,"file_access":True,"content_access":True,"bridges":[{"name":"Native","origins":["*"],"methods":["exec"]}]}]}
 got=load().audit(app)
 exp=[{"component":"HelpWebView","type":"WEBVIEW_RCE","evidence":"javascript file/content access bridge *"},{"component":"LoginActivity","type":"DEEPLINK_TAKEOVER","evidence":"wildcard unverified oauth_exchange"},{"component":"SyncService","type":"EXPORTED_PRIVILEGED_COMPONENT","evidence":"com.app.SYNC_PRIVILEGED without signature permission"},{"component":"application","type":"BACKUP_SECRET_LEAK","evidence":"shared_prefs/auth_token"},{"component":"network","type":"CLEAR_TEXT_TLS_BYPASS","evidence":"api.example.com cleartext/user-ca/no-pinning"}]
 assert got==exp,json.dumps(got,indent=2)
 write_result(1.0);return 0
if __name__=="__main__":
 try:sys.exit(main())
 except Exception as exc:write_result(0.0);print(f"Verifier failure: {exc}",file=sys.stderr);sys.exit(1)

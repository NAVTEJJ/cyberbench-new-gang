#!/usr/bin/env python3
import hashlib,hmac,importlib.util,json,sys
from pathlib import Path
SERVICE_ID="secure_channel_transcript_verifier"
def write_result(r):
 d=Path("/logs/verifier");details={"reward":r,"solved_service_ids":[SERVICE_ID] if r else [],"unsolved_service_ids":[] if r else [SERVICE_ID]}
 try:d.mkdir(parents=True,exist_ok=True)
 except Exception:d=Path("logs/verifier");d.mkdir(parents=True,exist_ok=True)
 (d/"reward.txt").write_text(f"{r}\n");(d/"details.json").write_text(json.dumps(details,indent=2,sort_keys=True));print(json.dumps(details))
def load():
 p=Path("/src/solution.py") if Path("/src/solution.py").exists() else Path("solution.py");spec=importlib.util.spec_from_file_location("solution",p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m.TranscriptVerifier()
def make(sid,cn,sn,ver="1.3",cipher="A",eph=True):
 msgs=[f"CH:{cn}:1.2,1.3:A,B",f"SH:{sn}:{ver}:{cipher}:SENTINEL"]
 th=hashlib.sha256("|".join(msgs).encode()).hexdigest(); exp=hmac.new(b"master"+(b"eph" if eph else b""),th.encode(),hashlib.sha256).hexdigest()
 return {"id":sid,"client_nonce":cn,"server_nonce":sn,"client_versions":["1.2","1.3"],"server_versions":["1.2","1.3"],"client_ciphers":["A","B"],"server_ciphers":["A","B"],"version":ver,"cipher":cipher,"downgrade_sentinel":True,"ephemeral":eph,"messages":msgs,"finished":hmac.new(b"finished",th.encode(),hashlib.sha256).hexdigest(),"exporter":exp,"app_binding":exp}
def main():
 sessions=[make("ok","c1","s1"),make("down","c2","s2","1.2","A"),make("replay","c1","s3"),{**make("badkey","c4","s4"),"finished":"00"},{**make("kci","c5","s5",eph=False)},{**make("bind","c6","s6"),"app_binding":"bad"}]
 got=load().verify(sessions,{})
 exp=[{"session":"badkey","type":"BAD_KEY_SCHEDULE","evidence":"finished/exporter mismatch"},{"session":"bind","type":"CHANNEL_BINDING_MISMATCH","evidence":"app binding mismatch"},{"session":"down","type":"DOWNGRADE","evidence":"1.2/A"},{"session":"kci","type":"KCI_RISK","evidence":"missing ephemeral contribution"},{"session":"replay","type":"NONCE_REPLAY","evidence":"client nonce c1"}]
 assert got==exp,json.dumps(got,indent=2)
 write_result(1.0);return 0
if __name__=="__main__":
 try:sys.exit(main())
 except Exception as exc:write_result(0.0);print(f"Verifier failure: {exc}",file=sys.stderr);sys.exit(1)

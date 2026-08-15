#!/usr/bin/env python3
import hashlib,hmac,importlib.util,json,sys
from pathlib import Path
SERVICE_ID="firmware_transparency_verifier"
def write_result(r):
 d=Path("/logs/verifier");details={"reward":r,"solved_service_ids":[SERVICE_ID] if r else [],"unsolved_service_ids":[] if r else [SERVICE_ID]}
 try:d.mkdir(parents=True,exist_ok=True)
 except Exception:d=Path("logs/verifier");d.mkdir(parents=True,exist_ok=True)
 (d/"reward.txt").write_text(f"{r}\n");(d/"details.json").write_text(json.dumps(details,indent=2,sort_keys=True));print(json.dumps(details))
def load():
 p=Path("/src/solution.py") if Path("/src/solution.py").exists() else Path("solution.py");spec=importlib.util.spec_from_file_location("solution",p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m.FirmwareVerifier()
def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"))
def mac(k,s):return hmac.new(k.encode(),s.encode(),hashlib.sha256).hexdigest()
def main():
 payload=b"firmware-v3";ph=hashlib.sha256(payload).hexdigest()
 man={"version":"3.2.1","channel":"stable","payload_sha256":ph,"signer":"leaf","critical":["rollback-protected"]}
 trust={"current_versions":{"stable":"3.1.9"},"trusted_roots":["root"],"certs":{"leaf":{"issuer":"root","not_before":100,"not_after":5000,"key":"leafkey","critical":["rollback-protected"]},"root":{"issuer":"root","not_before":0,"not_after":9999,"key":"rootkey"}},"revoked":{"leaf":[[4000,4500]]},"log_key":"logkey","known_log_entries":{7:hashlib.sha256(canon(man).encode()).hexdigest()}}
 bundle={"payload":payload.hex(),"manifest":man,"signature":mac("leafkey",canon(man)),"sct":{"timestamp":1000,"log_index":7},"log":{"root":hashlib.sha256(hashlib.sha256(canon(man).encode()).hexdigest().encode()).hexdigest(),"root_signature":"","proof":[]}}
 bundle["log"]["root_signature"]=mac("logkey",bundle["log"]["root"])
 got=load().verify(bundle,trust,2000)
 assert got=={"accepted":True,"version":"3.2.1","channel":"stable","log_index":7}
 for mut in [
  {"manifest":{**man,"version":"3.0.0"}},
  {"manifest":{**man,"payload_sha256":"00"}},
  {"sct":{"timestamp":4200,"log_index":7}},
  {"log":{"root":bundle["log"]["root"],"root_signature":"bad","proof":[]}},
  {"sct":{"timestamp":1000,"log_index":7},"manifest":{**man,"version":"3.2.2"}},
 ]:
  b=json.loads(json.dumps(bundle));b.update(mut)
  if "manifest" in mut:b["signature"]=mac("leafkey",canon(b["manifest"]))
  try:load().verify(b,trust,2000);raise AssertionError("accepted bad firmware")
  except ValueError:pass
 write_result(1.0);return 0
if __name__=="__main__":
 try:sys.exit(main())
 except Exception as exc:write_result(0.0);print(f"Verifier failure: {exc}",file=sys.stderr);sys.exit(1)

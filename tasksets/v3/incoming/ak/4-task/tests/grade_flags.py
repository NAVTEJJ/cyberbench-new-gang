#!/usr/bin/env python3
import hashlib,hmac,importlib.util,json,os,sys
from pathlib import Path
def enc(*x):return b"\0".join(str(v).encode() for v in x)
def main():
 ok=False;err=""
 try:
  p=Path(os.environ.get("CYBERBENCH_ENGINE","/app/engine.py"));s=importlib.util.spec_from_file_location("engine",p);m=importlib.util.module_from_spec(s);sys.modules["engine"]=m;s.loader.exec_module(m)
  g=m.Gateway(b"root",1000,20);d=m.Device("D",2,7,b"k7",b"k6",1005,{"t":(-5,50)});g.provision(d)
  def pkt(seq,epoch=7,key=b"k7"):return m.Packet("D",epoch,2,seq,1000,"t",5,hmac.new(key,enc("D",epoch,2,seq,1000,"t",5),hashlib.sha256).digest())
  for n in [130,3,129,2]:g.accept_telemetry(pkt(n))
  snap=dict(d.telemetry_windows)
  try:g.accept_telemetry(pkt(2));raise AssertionError
  except m.GatewayError:pass
  assert d.telemetry_windows==snap;g.accept_telemetry(pkt(1,6,b"k6"))
  ok=True
 except Exception as x:err=repr(x)
 d=Path(os.environ.get("CYBERBENCH_LOG_DIR","/logs/verifier"));d.mkdir(parents=True,exist_ok=True);r=float(ok);(d/"reward.txt").write_text(f"{r}\n");(d/"details.json").write_text(json.dumps({"reward":r,"error":err}));return 0 if ok else 1
if __name__=="__main__":raise SystemExit(main())

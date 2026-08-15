#!/usr/bin/env python3
import hashlib,importlib.util,json,os,sys
from pathlib import Path
def main():
 ok=False;err=""
 try:
  p=Path(os.environ.get("CYBERBENCH_ENGINE","/app/engine.py"));s=importlib.util.spec_from_file_location("engine",p);m=importlib.util.module_from_spec(s);sys.modules["engine"]=m;s.loader.exec_module(m)
  def a(n,v,data,deps=(),prov=()):return m.Artifact(n,v,f"pkg/{n}-{v}",hashlib.sha256(data).hexdigest(),data,"trusted",deps,prov)
  lib1=a("lib","1.9.0",b"L1");lib2=a("lib","2.0.0",b"L2");app=a("app","1.0.0",b"A",(("lib","^1.0.0"),),(("lib",lib1.digest),))
  selected,plan=m.resolve((("app","*"),),[lib2,app,lib1],{},m.Policy(frozenset({"trusted"})));assert [x.name for x in selected]==["lib","app"];assert selected[0].version=="1.9.0"
  for bad in ["/x","a/../b","a//b","a%2fb"]:
   try:m.normalize_path(bad);raise AssertionError
   except m.ResolveError:pass
  ok=True
 except Exception as x:err=repr(x)
 d=Path(os.environ.get("CYBERBENCH_LOG_DIR","/logs/verifier"));d.mkdir(parents=True,exist_ok=True);r=float(ok);(d/"reward.txt").write_text(f"{r}\n");(d/"details.json").write_text(json.dumps({"reward":r,"error":err}));return 0 if ok else 1
if __name__=="__main__":raise SystemExit(main())

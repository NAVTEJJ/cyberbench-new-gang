#!/usr/bin/env python3
import importlib.util,json,sys
from pathlib import Path
SERVICE_ID="h2_gateway_smuggling_analyzer"
def write_result(r):
 d=Path("/logs/verifier");details={"reward":r,"solved_service_ids":[SERVICE_ID] if r else [],"unsolved_service_ids":[] if r else [SERVICE_ID]}
 try:d.mkdir(parents=True,exist_ok=True)
 except Exception:d=Path("logs/verifier");d.mkdir(parents=True,exist_ok=True)
 (d/"reward.txt").write_text(f"{r}\n");(d/"details.json").write_text(json.dumps(details,indent=2,sort_keys=True));print(json.dumps(details))
def load():
 p=Path("/src/solution.py") if Path("/src/solution.py").exists() else Path("solution.py");spec=importlib.util.spec_from_file_location("solution",p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m.GatewayAnalyzer()
def main():
 reqs=[
  {"id":"r1","pseudo":[(":method","POST"),(":path","/pay"),(":authority","shop.example")],"headers":[("content-length","4"),("content-length","9"),("transfer-encoding","chunked")],"body_len":4,"downgraded_body_len":9},
  {"id":"r2","pseudo":[(":method","GET"),("x","1"),(":path","https://evil/x"),(":authority","app.example")],"headers":[("host","other.example")],"origin_headers":[("host","other.example")]},
  {"id":"r3","pseudo":[(":method","GET"),(":path","/item?b=2&a=1"),(":authority","cdn.example")],"headers":[("x-forwarded-host","admin.example")],"cache_key":"/item?a=1&b=2","origin_route":"admin.example"},
  {"id":"r4","pseudo":[(":method","GET"),(":path","/ok%0d%0aX-Evil:%201"),(":authority","app.example")],"headers":[]},
  {"id":"r5","pseudo":[(":method","GET"),(":path","/"),(":authority","app.example")],"headers":[("connection","x-secret"),("x-secret","keep")],"origin_headers":[("x-secret","keep")]}]
 got=load().analyze(reqs)
 exp=[
  {"id":"r1","type":"H2_CL_TE_SMUGGLE","evidence":"duplicate content-length and transfer-encoding"},
  {"id":"r2","type":"PSEUDO_HEADER_CONFUSION","evidence":"misordered or absolute pseudo headers"},
  {"id":"r3","type":"CACHE_POISON","evidence":"x-forwarded-host routes origin outside cache key"},
  {"id":"r4","type":"REQUEST_SPLIT","evidence":"decoded CRLF"},
  {"id":"r5","type":"HOP_BY_HOP_LEAK","evidence":"x-secret"}]
 assert got==exp,json.dumps(got,indent=2)
 write_result(1.0);return 0
if __name__=="__main__":
 try:sys.exit(main())
 except Exception as exc:write_result(0.0);print(f"Verifier failure: {exc}",file=sys.stderr);sys.exit(1)

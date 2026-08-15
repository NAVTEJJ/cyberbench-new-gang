#!/usr/bin/env python3
import importlib.util,json,sys
from pathlib import Path
SERVICE_ID="sanitizer_crash_triage"
def write_result(r):
 d=Path("/logs/verifier");details={"reward":r,"solved_service_ids":[SERVICE_ID] if r else [],"unsolved_service_ids":[] if r else [SERVICE_ID]}
 try:d.mkdir(parents=True,exist_ok=True)
 except Exception:d=Path("logs/verifier");d.mkdir(parents=True,exist_ok=True)
 (d/"reward.txt").write_text(f"{r}\n");(d/"details.json").write_text(json.dumps(details,indent=2,sort_keys=True));print(json.dumps(details))
def load():
 p=Path("/src/solution.py") if Path("/src/solution.py").exists() else Path("solution.py");spec=importlib.util.spec_from_file_location("solution",p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m.CrashTriage()
def main():
 reports=[
 {"seed":"id:1","controlled":True,"log":"ERROR: AddressSanitizer: heap-buffer-overflow on address 0xabc WRITE of size 4\n#0 parse_len /src/parser.c:88:12\n#1 LLVMFuzzerTestOneInput /src/fuzz.c:20"},
 {"seed":"id:2","controlled":True,"log":"ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdef WRITE of size 4\n#0 parse_len /src/parser.c:88:44\n#1 main /src/repro.c:9"},
 {"seed":"id:3","controlled":False,"log":"MemorySanitizer: use-of-uninitialized-value\n#0 decode_header /src/codec.c:41\n#1 main /src/a.c:1"},
 {"seed":"id:4","controlled":True,"log":"runtime error: unsigned integer overflow: 4 - 8 cannot be represented\n#0 reserve_table /src/table.c:71\nallocation-size-too-big"}]
 got=load().triage(reports)
 exp={"groups":[{"id":"G001","class":"uninitialized-read","access":"read","top_user_frame":"decode_header /src/codec.c","affected_function":"decode_header","seeds":["id:3"],"severity":"high"},{"id":"G002","class":"heap-buffer-overflow","access":"write","top_user_frame":"parse_len /src/parser.c","affected_function":"parse_len","seeds":["id:1","id:2"],"severity":"critical"},{"id":"G003","class":"integer-overflow-allocation","access":"write","top_user_frame":"reserve_table /src/table.c","affected_function":"reserve_table","seeds":["id:4"],"severity":"critical"}],"unique_crashes":3}
 assert got==exp,json.dumps(got,indent=2)
 write_result(1.0);return 0
if __name__=="__main__":
 try:sys.exit(main())
 except Exception as exc:write_result(0.0);print(f"Verifier failure: {exc}",file=sys.stderr);sys.exit(1)

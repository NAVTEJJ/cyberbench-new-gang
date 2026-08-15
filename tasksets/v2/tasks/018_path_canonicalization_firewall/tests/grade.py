#!/usr/bin/env python3
import importlib.util, json, sys
from pathlib import Path

SERVICE_ID = "canonicalization_firewall"

def write_result(reward):
    details={"reward":reward,"solved_service_ids":[SERVICE_ID] if reward else [],"unsolved_service_ids":[] if reward else [SERVICE_ID]}
    d=Path("/logs/verifier")
    try:d.mkdir(parents=True,exist_ok=True)
    except Exception:d=Path("logs/verifier");d.mkdir(parents=True,exist_ok=True)
    (d/"reward.txt").write_text(f"{reward}\n");(d/"details.json").write_text(json.dumps(details,indent=2,sort_keys=True));print(json.dumps(details))

def load():
    p=Path("/src/solution.py") if Path("/src/solution.py").exists() else Path("solution.py")
    spec=importlib.util.spec_from_file_location("solution",p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m.PathFirewall()

def main():
    fw=load()
    policy={"root":"/srv/app/public","case_insensitive":True,"symlinks":{"/srv/app/public/link":"/srv/app/private","/srv/app/public/assets/cdn":"/srv/app/public/static"},"allow_extensions":[".txt",".png",".json"],"deny_globs":["*/secret*","*.php"]}
    assert fw.decide({"path":"assets%2fcdn/logo.PNG"},policy)=={"allow":True,"canonical":"/srv/app/public/static/logo.png","reason":"ok"}
    bad=[
        {"path":"..%252fprivate/secret.txt"},
        {"path":"C:/windows/win.ini"},
        {"path":"docs/readme.txt:evil"},
        {"path":"aux.txt"},
        {"path":"safe/\u202esecret.txt"},
        {"path":"link/secret.txt"},
        {"mode":"archive","entries":[{"name":"ok/a.txt"},{"name":"..\\evil.txt"}]},
        {"mode":"archive","entries":[{"name":"ok/a.txt","type":"symlink","target":"/etc/passwd"}]},
    ]
    for req in bad:
        got=fw.decide(req,policy)
        assert got["allow"] is False, (req,got)
    write_result(1.0);return 0

if __name__=="__main__":
    try:sys.exit(main())
    except Exception as exc:write_result(0.0);print(f"Verifier failure: {exc}",file=sys.stderr);sys.exit(1)

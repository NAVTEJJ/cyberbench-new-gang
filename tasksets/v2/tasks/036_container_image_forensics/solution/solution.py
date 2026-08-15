import re
SEV={"low":1,"medium":2,"high":3,"critical":4}
SECRET=re.compile(r"(aws_secret_access_key|ghp_[a-z0-9_]+|password=|api[_-]?key)",re.I)
class ImageForensics:
    def scan(self,image,policy):
        out=[];seen_files={};base_priv=set()
        remote_seen=set()
        for layer in image.get("layers",[]):
            idx=layer.get("index",0)
            text=layer.get("history","")+" "+jsonish(layer.get("env",{}))
            if SECRET.search(text): out.append({"layer":idx,"type":"SECRET_IN_HISTORY","evidence":SECRET.search(text).group(1)})
            for path,meta in layer.get("files",{}).items():
                seen_files[path]=idx
                content=str(meta.get("content",""))
                if SECRET.search(content): out.append({"layer":idx,"type":"SECRET_IN_HISTORY","evidence":SECRET.search(content).group(1)})
                priv=meta.get("setuid") or any(c in ("cap_sys_admin","cap_dac_read_search","cap_net_admin") for c in meta.get("caps",[]))
                if idx==0 and priv: base_priv.add(path)
                elif priv and path not in base_priv:
                    out.append({"layer":idx,"type":"PRIVILEGE_DRIFT","evidence":f"{path} setuid {' '.join(meta.get('caps',[]))}".strip()})
                if re.search(r"(curl|wget)\s+https?://[^|;]+\|\s*(sh|bash)",content) and (idx,content) not in remote_seen:
                    remote_seen.add((idx,content))
                    out.append({"layer":idx,"type":"UNPINNED_REMOTE_EXEC","evidence":content})
            if re.search(r"(curl|wget)\s+https?://[^|;]+\|\s*(sh|bash)",layer.get("history","")):
                ev=layer["history"].replace("RUN ","")
                if (idx,ev) not in remote_seen:
                    remote_seen.add((idx,ev))
                    out.append({"layer":idx,"type":"UNPINNED_REMOTE_EXEC","evidence":ev})
            for w in layer.get("whiteouts",[]):
                if w in seen_files:
                    out.append({"layer":idx,"type":"WHITEOUT_HIDE","evidence":w})
        reachable=set()
        for ep in image.get("entrypoint",[]): reachable.update(image.get("imports",{}).get(ep,[]))
        th=SEV.get(policy.get("severity_threshold","high"),3)
        for p in image.get("sbom",[]):
            if (p.get("reachable") or p.get("name") in reachable) and SEV.get(p.get("severity","low"),0)>=th:
                out.append({"layer":999,"type":"REACHABLE_CVE","evidence":f"{p['name']} {p['cve']} {p['severity']}"})
        order={"PRIVILEGE_DRIFT":0,"SECRET_IN_HISTORY":1,"WHITEOUT_HIDE":2,"UNPINNED_REMOTE_EXEC":3,"REACHABLE_CVE":4}
        return sorted(out,key=lambda x:(x["layer"],order.get(x["type"],9),x["evidence"]))
def jsonish(x): return " ".join(f"{k}={v}" for k,v in x.items())

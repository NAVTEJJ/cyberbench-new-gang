import re

def frame(log):
    for line in log.splitlines():
        m=re.search(r"#\d+\s+([A-Za-z_][\w]*)\s+([^:\s]+)",line)
        if m and not any(x in m.group(1).lower() for x in ("malloc","free","asan","llvmfuzzer")):
            return m.group(1),m.group(2)
    return "unknown","unknown"

class CrashTriage:
    def triage(self,reports):
        groups={}
        for r in reports:
            log=r.get("log","");low=log.lower()
            if "heap-buffer-overflow" in low: cls="heap-buffer-overflow"
            elif "stack-buffer-overflow" in low: cls="stack-buffer-overflow"
            elif "use-after-free" in low: cls="use-after-free"
            elif "uninitialized" in low: cls="uninitialized-read"
            elif "null" in low or "segv on unknown address 0x000000000000" in low: cls="null-dereference"
            elif "integer overflow" in low or "allocation-size-too-big" in low: cls="integer-overflow-allocation"
            else: cls="unknown"
            access="write" if ("write" in low or cls=="integer-overflow-allocation") else "read"
            fn,path=frame(log)
            key=(cls,access,fn,path)
            groups.setdefault(key,{"class":cls,"access":access,"top_user_frame":f"{fn} {path}","affected_function":fn,"seeds":[],"controlled":False})
            groups[key]["seeds"].append(r.get("seed",""))
            groups[key]["controlled"]|=bool(r.get("controlled"))
        out=[]
        for i,g in enumerate(sorted(groups.values(),key=lambda x:(x["top_user_frame"],x["class"])),1):
            sev="critical" if (g["access"]=="write" or g["class"]=="use-after-free") and g["controlled"] else "high" if g["class"] in ("heap-buffer-overflow","uninitialized-read") else "medium"
            out.append({"id":f"G{i:03d}","class":g["class"],"access":g["access"],"top_user_frame":g["top_user_frame"],"affected_function":g["affected_function"],"seeds":sorted(g["seeds"]),"severity":sev})
        return {"groups":out,"unique_crashes":len(out)}

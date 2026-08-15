import ipaddress

def pub(raddr):
    try:
        ip = raddr.split(":")[0]
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast)
    except Exception:
        return False

class MemoryForensicsAnalyzer:
    def analyze(self, artifacts):
        procs = {p["pid"]: p for p in artifacts.get("pslist", [])}
        findings = []
        injected = set()
        for p in procs.values():
            path = p.get("image_path","").lower()
            name = p.get("name","").lower()
            if name in ("svchost.exe","lsass.exe","explorer.exe") and "\\windows\\system32\\" not in path:
                if any(v.get("pid")==p["pid"] and v.get("private") and "EXECUTE" in v.get("protection","") for v in artifacts.get("vad", [])):
                    findings.append({"pid":p["pid"],"type":"PROCESS_HOLLOWING","evidence":f"{p.get('name')} from {p.get('image_path')}"})
                    injected.add(p["pid"])
        mal = {(m.get("pid"), m.get("address")) for m in artifacts.get("malfind", [])}
        for v in artifacts.get("vad", []):
            prot = v.get("protection","")
            if v.get("private") and "EXECUTE" in prot and ("WRITE" in prot or (v.get("pid"), v.get("start")) in mal or v.get("entropy",0) > 7.0):
                findings.append({"pid":v["pid"],"type":"CODE_INJECTION","evidence":f"private executable VAD 0x{v.get('start'):x}"})
                injected.add(v["pid"])
        cred = set()
        for h in artifacts.get("handles", []):
            if h.get("type") == "Process" and "lsass.exe" in h.get("name","").lower():
                cred.add(h["pid"])
        for c in artifacts.get("cmdline", []):
            low = c.get("command","").lower()
            if "comsvcs" in low and "minidump" in low or "procdump" in low and "lsass" in low:
                cred.add(c["pid"])
        for pid in sorted(cred):
            findings.append({"pid":pid,"type":"CRED_DUMP","evidence":"lsass access"})
        for n in artifacts.get("netscan", []):
            if n.get("pid") in injected and n.get("state") == "ESTABLISHED" and n.get("bytes_sent",0) >= 50*1024*1024 and pub(n.get("raddr","")):
                findings.append({"pid":n["pid"],"type":"EXFIL_AFTER_INJECTION","evidence":n.get("raddr")})
        order = {"CODE_INJECTION":0,"CRED_DUMP":1,"EXFIL_AFTER_INJECTION":2,"PROCESS_HOLLOWING":3}
        findings = sorted(findings, key=lambda x:(x["pid"], order.get(x["type"],99), x["evidence"]))
        bypid = {}
        for f in findings:
            bypid.setdefault(f["pid"], set()).add(f["type"])
        compromised = sorted(pid for pid, types in bypid.items() if types & {"PROCESS_HOLLOWING","CODE_INJECTION"})
        chain_order = ["PROCESS_HOLLOWING","CODE_INJECTION","CRED_DUMP","EXFIL_AFTER_INJECTION"]
        chains = [{"pid":pid,"steps":[s for s in chain_order if s in bypid.get(pid,set())]} for pid in compromised if len(bypid.get(pid,set())) >= 2]
        return {"compromised_pids": compromised, "findings": findings, "attack_chain": chains}

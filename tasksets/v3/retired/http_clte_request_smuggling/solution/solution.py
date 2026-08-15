import ipaddress

SUSP = ("powershell -enc", "rundll32", "regsvr32", "mshta", "wmic process call create")

def host(e, key="host"):
    return str(e.get(key, "")).lower()

def suspicious(e):
    text = (str(e.get("process", "")) + " " + str(e.get("cmd", ""))).lower()
    return any(x in text for x in SUSP)

def public_ip(ip):
    try:
        obj = ipaddress.ip_address(ip)
        return not (obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast)
    except Exception:
        return False

class IncidentCorrelator:
    def investigate(self, events):
        events = sorted(events, key=lambda e: (e.get("ts", 0), host(e), str(e.get("type", ""))))
        parents = {}
        suspicious_guids = set()
        for e in events:
            if e.get("type") == "process" and e.get("guid"):
                key = (host(e), e.get("guid"))
                parents[key] = (host(e), e.get("parent_guid"))
                if suspicious(e):
                    suspicious_guids.add(key)
        def malicious_lineage(e):
            key = (host(e), e.get("guid") or e.get("process_guid"))
            seen = set()
            while key[1] and key not in seen:
                if key in suspicious_guids:
                    return True
                seen.add(key)
                key = parents.get(key, (key[0], None))
            return False
        compromised = set()
        initial = None
        lateral = []
        persist = []
        exfil = []
        compromise_ts = {}
        for e in events:
            if e.get("type") == "logon" and e.get("status") == "success" and e.get("logon_type") in (3, 10):
                h, u, t = host(e), e.get("user"), e.get("ts", 0)
                follow = [x for x in events if host(x) == h and x.get("user") == u and 0 <= x.get("ts", 0) - t <= 900 and x.get("type") == "process" and suspicious(x)]
                if follow and e.get("src_ip"):
                    compromised.add(h); compromise_ts.setdefault(h, t)
                    if initial is None:
                        initial = {"host": h, "user": u, "source_ip": e.get("src_ip")}
        changed = True
        while changed:
            changed = False
            for e in events:
                if e.get("type") == "logon" and e.get("status") == "success" and e.get("logon_type") in (3, 10):
                    src = host(e, "src_host")
                    dst = host(e)
                    if src in compromised and dst and dst not in compromised:
                        t, u = e.get("ts", 0), e.get("user")
                        ok = any(host(x) == dst and 0 <= x.get("ts", 0) - t <= 1200 and (x.get("type") in ("service", "wmi") or (x.get("type") == "process" and suspicious(x))) for x in events)
                        if ok:
                            compromised.add(dst); compromise_ts.setdefault(dst, t); changed = True
                            lateral.append({"src": src, "dst": dst, "user": u})
        seen_p = set()
        for e in events:
            h = host(e)
            mech = ind = None
            if e.get("type") == "registry" and "\\currentversion\\run" in str(e.get("key", "")).lower():
                mech, ind = "run_key", e.get("key")
            elif e.get("type") == "task":
                mech, ind = "scheduled_task", e.get("name", e.get("cmd", ""))
            elif e.get("type") == "process" and h in compromised and malicious_lineage(e):
                cmd = str(e.get("cmd", "")).lower()
                if "schtasks /create" in cmd or "new-scheduledtask" in cmd:
                    mech, ind = "scheduled_task", e.get("cmd", "")
            elif e.get("type") == "service" and e.get("action") in ("install", "create"):
                mech, ind = "service", e.get("service", e.get("name", ""))
            elif e.get("type") == "wmi_subscription":
                mech, ind = "wmi_subscription", e.get("name", "")
            if mech and h in compromised and (h, mech, ind) not in seen_p:
                seen_p.add((h, mech, ind)); persist.append({"host": h, "mechanism": mech, "indicator": ind})
            if e.get("type") == "network" and h in compromised and e.get("ts", 0) >= compromise_ts.get(h, 10**18) and e.get("bytes", 0) >= 50 * 1024 * 1024 and public_ip(e.get("dst_ip", "")):
                exfil.append({"host": h, "dst_ip": e.get("dst_ip"), "bytes": e.get("bytes")})
        risk = min(100, 20 * len(compromised) + 15 * len(lateral) + 10 * len(persist) + 25 * len(exfil))
        return {"compromised_hosts": sorted(compromised), "initial_access": initial, "lateral_movement": lateral, "persistence": persist, "exfiltration": exfil, "risk_score": risk}

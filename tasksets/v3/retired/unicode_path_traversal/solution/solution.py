def dist1(a, b):
    if a == b:
        return False
    if len(a) == len(b):
        dif = [i for i in range(len(a)) if a[i] != b[i]]
        return len(dif) == 1 or (len(dif) == 2 and dif[1] == dif[0]+1 and a[dif[0]] == b[dif[1]] and a[dif[1]] == b[dif[0]])
    if abs(len(a)-len(b)) == 1:
        x, y = (a, b) if len(a) < len(b) else (b, a)
        return any(x == y[:i] + y[i+1:] for i in range(len(y)))
    return False

def major(v):
    try: return int(v.split(".",1)[0].lstrip("v"))
    except Exception: return -1

def satisfies(ver, rng):
    if rng.startswith("^"):
        base = rng[1:]
        return major(ver) == major(base) and tuple(map(int, ver.split(".")[:3])) >= tuple(map(int, base.split(".")[:3]))
    if rng.startswith("~"):
        base = rng[1:]
        vp = ver.split("."); bp = base.split(".")
        return vp[:2] == bp[:2] and int(vp[2].split("-")[0]) >= int(bp[2].split("-")[0])
    return ver == rng

def suspicious_script(s):
    low = s.lower()
    rev = low[::-1]
    return any(x in low or x in rev for x in ("curl", "wget", "base64", "process.env", "child_process", "/bin/sh", "powershell", "http://", "https://"))

class SupplyChainAnalyzer:
    def analyze(self, manifest, lockfile, attestations):
        deps = manifest.get("dependencies", {})
        trusted = set(manifest.get("trusted_builders", []))
        direct = {}
        pubs = {}
        pkgs = []
        for meta in lockfile.get("packages", {}).values():
            name = meta.get("name")
            if not name:
                continue
            pkgs.append(meta); pubs[name] = meta.get("publisher")
            if name in deps:
                direct[name] = meta
        out = []
        for p in pkgs:
            name, ver = p["name"], p.get("version", "")
            att = attestations.get(name, {})
            for key, val in p.get("scripts", {}).items():
                if key in ("install", "postinstall", "preinstall") and suspicious_script(str(val)):
                    out.append({"package": name, "version": ver, "type": "INSTALL_SCRIPT_EXFIL", "evidence": key})
            if att and p.get("integrity") != att.get("integrity"):
                out.append({"package": name, "version": ver, "type": "INTEGRITY_MISMATCH", "evidence": f"{p.get('integrity')} != {att.get('integrity')}"})
            if att.get("builder") and att.get("builder") not in trusted:
                out.append({"package": name, "version": ver, "type": "UNTRUSTED_PROVENANCE", "evidence": f"builder {att.get('builder')}"})
            for ns, repo in manifest.get("namespace_repos", {}).items():
                if name.startswith(ns + "/") and att.get("source") and not str(att.get("source")).startswith(repo):
                    out.append({"package": name, "version": ver, "type": "UNTRUSTED_PROVENANCE", "evidence": f"source {att.get('source')}"})
            for dname, dmeta in direct.items():
                if name != dname and dist1(name, dname) and pubs.get(name) != pubs.get(dname):
                    out.append({"package": name, "version": ver, "type": "TYPOSQUAT", "evidence": dname})
            if name in manifest.get("overrides", {}) and name in deps and not satisfies(manifest["overrides"][name], deps[name]):
                out.append({"package": name, "version": ver, "type": "PINNED_MALICIOUS_OVERRIDE", "evidence": f"override {manifest['overrides'][name]} outside {deps[name]}"})
        order = {"INSTALL_SCRIPT_EXFIL":0,"INTEGRITY_MISMATCH":1,"TYPOSQUAT":2,"UNTRUSTED_PROVENANCE":3,"PINNED_MALICIOUS_OVERRIDE":4}
        return sorted(out, key=lambda x: (x["package"], order.get(x["type"], 99), x["evidence"]))

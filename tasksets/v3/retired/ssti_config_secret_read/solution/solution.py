import base64, math, re, zlib
from collections import defaultdict

PAT = re.compile(r"^([a-z0-9]+)-(\d+)-(\d+)-([0-9a-f]{8})-([a-z2-7]+)\.exfil\.example$")

def entropy(s):
    if not s:
        return 0
    return -sum((s.count(c)/len(s)) * math.log2(s.count(c)/len(s)) for c in set(s))

def b32(s):
    return base64.b32decode(s.upper() + "=" * (-len(s) % 8))

def sld(q):
    labels = q.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else q

class DNSTunnelAnalyzer:
    def analyze(self, events):
        sessions = defaultdict(dict)
        bad = set()
        by_domain = defaultdict(list)
        for e in events:
            q = str(e.get("qname", "")).lower().rstrip(".")
            c = str(e.get("client", ""))
            by_domain[(c, sld(q))].append(e.get("ts", 0))
            m = PAT.match(q)
            if not m or entropy(m.group(5)) < 2.0:
                continue
            sid, seq, total, crc, chunk = m.group(1), int(m.group(2)), int(m.group(3)), m.group(4), m.group(5)
            key = (c, sid, total, crc)
            if seq in sessions[key]:
                bad.add(key)
            sessions[key][seq] = chunk
        out = []
        for key, vals in sessions.items():
            if key in bad:
                continue
            c, sid, total, crc = key
            if sorted(vals) != list(range(total)):
                continue
            try:
                payload = b32("".join(vals[i] for i in range(total)))
            except Exception:
                continue
            if f"{zlib.crc32(payload) & 0xffffffff:08x}" != crc:
                continue
            try:
                text = payload.decode("utf-8")
                if any((ord(ch) < 32 and ch not in "\r\n\t") for ch in text):
                    raise UnicodeError
                shown = text
            except Exception:
                shown = payload.hex()
            out.append({"client": c, "session": sid, "bytes": len(payload), "payload": shown})
        beacons = []
        for (c, dom), times in by_domain.items():
            times = sorted(times)
            if len(times) < 5:
                continue
            gaps = [b-a for a, b in zip(times, times[1:])]
            med = sorted(gaps)[len(gaps)//2]
            if med >= 10 and all(abs(g-med) <= 2 for g in gaps):
                beacons.append({"client": c, "domain": dom, "count": len(times), "interval": int(round(med))})
        clients = sorted({x["client"] for x in out} | {x["client"] for x in beacons})
        return {"exfil_sessions": sorted(out, key=lambda x:(x["client"], x["session"])), "beacons": sorted(beacons, key=lambda x:(x["client"], x["domain"])), "suspicious_clients": clients}

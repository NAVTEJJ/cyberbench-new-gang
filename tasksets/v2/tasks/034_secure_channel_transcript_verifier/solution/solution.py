import hashlib,hmac
class TranscriptVerifier:
    def verify(self,sessions,policy):
        out=[];seen_c=set();seen_s=set()
        for s in sessions:
            sid=s["id"]
            if s["client_nonce"] in seen_c: out.append({"session":sid,"type":"NONCE_REPLAY","evidence":f"client nonce {s['client_nonce']}"})
            if s["server_nonce"] in seen_s: out.append({"session":sid,"type":"NONCE_REPLAY","evidence":f"server nonce {s['server_nonce']}"})
            seen_c.add(s["client_nonce"]);seen_s.add(s["server_nonce"])
            if (s["version"]!=max(set(s["client_versions"])&set(s["server_versions"])) or s["cipher"]!=sorted(set(s["client_ciphers"])&set(s["server_ciphers"]))[0] or not s.get("downgrade_sentinel")):
                out.append({"session":sid,"type":"DOWNGRADE","evidence":f"{s['version']}/{s['cipher']}"})
            th=hashlib.sha256("|".join(s.get("messages",[])).encode()).hexdigest()
            exp=hmac.new(b"master"+(b"eph" if s.get("ephemeral") else b""),th.encode(),hashlib.sha256).hexdigest()
            fin=hmac.new(b"finished",th.encode(),hashlib.sha256).hexdigest()
            if s.get("finished")!=fin or s.get("exporter")!=exp:
                out.append({"session":sid,"type":"BAD_KEY_SCHEDULE","evidence":"finished/exporter mismatch"})
            if not s.get("ephemeral"):
                out.append({"session":sid,"type":"KCI_RISK","evidence":"missing ephemeral contribution"})
            if s.get("app_binding")!=s.get("exporter"):
                out.append({"session":sid,"type":"CHANNEL_BINDING_MISMATCH","evidence":"app binding mismatch"})
        order={"BAD_KEY_SCHEDULE":0,"CHANNEL_BINDING_MISMATCH":1,"DOWNGRADE":2,"KCI_RISK":3,"NONCE_REPLAY":4}
        return sorted(out,key=lambda x:(x["session"],order[x["type"]]))

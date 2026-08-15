import hashlib,hmac,json

def canon(x):return json.dumps(x,sort_keys=True,separators=(",",":"))
def mac(k,s):return hmac.new(k.encode(),s.encode(),hashlib.sha256).hexdigest()
def ver_tuple(v):return tuple(int(x) for x in v.split("-")[0].split("."))

class FirmwareVerifier:
    def verify(self,bundle,trust,now):
        payload=bytes.fromhex(bundle["payload"]);man=bundle["manifest"];channel=man["channel"]
        if channel not in trust["current_versions"]:raise ValueError("unknown channel")
        if hashlib.sha256(payload).hexdigest()!=man["payload_sha256"]:raise ValueError("bad payload hash")
        if ver_tuple(man["version"])<=ver_tuple(trust["current_versions"][channel]):raise ValueError("rollback")
        cert=trust["certs"].get(man["signer"])
        if not cert or cert.get("issuer") not in trust["trusted_roots"]:raise ValueError("bad chain")
        ts=bundle["sct"]["timestamp"]
        if ts>now or not(cert["not_before"]<=ts<cert["not_after"]):raise ValueError("bad cert time")
        for a,b in trust.get("revoked",{}).get(man["signer"],[]):
            if a<=ts<b:raise ValueError("revoked")
        if sorted(man.get("critical",[]))!=sorted(cert.get("critical",[])):raise ValueError("critical mismatch")
        c=canon(man)
        if not hmac.compare_digest(bundle["signature"],mac(cert["key"],c)):raise ValueError("bad signature")
        leaf=hashlib.sha256(c.encode()).hexdigest();idx=bundle["sct"]["log_index"]
        if trust.get("known_log_entries",{}).get(idx)!=leaf:raise ValueError("split view")
        root=leaf
        for side,h in bundle["log"].get("proof",[]):
            root=hashlib.sha256((h+root if side=="left" else root+h).encode()).hexdigest()
        root=hashlib.sha256(root.encode()).hexdigest()
        if root!=bundle["log"]["root"] or not hmac.compare_digest(bundle["log"]["root_signature"],mac(trust["log_key"],root)):raise ValueError("bad log")
        return {"accepted":True,"version":man["version"],"channel":channel,"log_index":idx}

import base64, hashlib, hmac, ipaddress, json, zlib
from urllib.parse import urlsplit, urlunsplit

def _rc4(key, data):
    s = list(range(256)); j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 255
        s[i], s[j] = s[j], s[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) & 255; j = (j + s[i]) & 255
        s[i], s[j] = s[j], s[i]
        out.append(b ^ s[(s[i] + s[j]) & 255])
    return bytes(out)

class ConfigDecoder:
    def decode(self, blob, family_key):
        try:
            raw = base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))
        except Exception as exc:
            raise ValueError("bad b64") from exc
        if len(raw) < 8 + 32:
            raise ValueError("short")
        nonce, ct, tag = raw[:8], raw[8:-32], raw[-32:]
        want = hmac.new(family_key, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, want):
            raise ValueError("bad tag")
        mixed = _rc4(hashlib.sha256(family_key + nonce).digest(), ct)
        mask = b"CYBENCH2"
        plain = bytes(b ^ mask[i % len(mask)] for i, b in enumerate(mixed))
        if plain.startswith(b"Z1"):
            try:
                plain = zlib.decompress(plain[2:])
            except Exception as exc:
                raise ValueError("bad zlib") from exc
        try:
            obj = json.loads(plain.decode())
        except Exception as exc:
            raise ValueError("bad json") from exc
        for f in ("campaign_id", "mutex", "kill_switch", "c2", "dga_seeds"):
            if f not in obj:
                raise ValueError("missing")
        if not isinstance(obj["campaign_id"], str) or not isinstance(obj["mutex"], str) or not isinstance(obj["kill_switch"], bool):
            raise ValueError("bad field type")
        if not isinstance(obj["c2"], list) or not isinstance(obj["dga_seeds"], list):
            raise ValueError("bad list type")
        seen = {}
        for item in obj.get("configs", []):
            cid, mutex = item.get("campaign_id"), item.get("mutex")
            if cid in seen and seen[cid] != mutex:
                raise ValueError("conflict")
            seen[cid] = mutex
        out_c2 = set()
        for url in obj["c2"]:
            if not isinstance(url, str):
                raise ValueError("bad c2")
            p = urlsplit(url)
            if p.scheme.lower() != "https" or not p.hostname:
                raise ValueError("bad c2 scheme")
            host = p.hostname.lower()
            try:
                ipaddress.ip_address(host)
                raise ValueError("ip literal")
            except ValueError as e:
                if str(e) == "ip literal":
                    raise
            netloc = host if p.port in (None, 443) else f"{host}:{p.port}"
            out_c2.add(urlunsplit(("https", netloc, p.path or "/", p.query, "")))
        seeds = []
        for seed in obj["dga_seeds"]:
            if not isinstance(seed, str) or any(c not in "0123456789abcdefABCDEF" for c in seed):
                raise ValueError("bad seed")
            seeds.append(seed.lower())
        if "seed_crc32" in obj:
            if obj["seed_crc32"] != (zlib.crc32(",".join(seeds).encode()) & 0xffffffff):
                raise ValueError("bad seed checksum")
        return {"campaign_id": obj["campaign_id"], "mutex": obj["mutex"], "kill_switch": bool(obj["kill_switch"]), "c2": sorted(out_c2), "dga_seeds": seeds}

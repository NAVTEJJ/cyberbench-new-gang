import base64, hashlib, hmac, json

def _b64d(s):
    if not isinstance(s, str) or "=" in s or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in s):
        raise ValueError("bad base64url")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(raw).decode().rstrip("=") != s:
        raise ValueError("non canonical base64url")
    return raw

def _json_obj(raw):
    def hook(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ValueError("duplicate json key")
            out[k] = v
        return out
    obj = json.loads(raw, object_pairs_hook=hook)
    if not isinstance(obj, dict):
        raise ValueError("non object")
    return obj

class TokenVerifier:
    def __init__(self):
        self.seen_jti = set()
        self.seen_nonce = set()

    def verify(self, token, jwks, config, now):
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("bad jwt")
        try:
            header = _json_obj(_b64d(parts[0]))
            claims = _json_obj(_b64d(parts[1]))
        except Exception as exc:
            raise ValueError("bad json") from exc
        if header.get("alg") != "HS256":
            raise ValueError("bad alg")
        if "crit" in header:
            raise ValueError("unsupported crit")
        kid = header.get("kid")
        key = None
        for item in jwks.get("keys", []):
            if item.get("kid") == kid and item.get("kty") == "oct":
                if item.get("use", "sig") != "sig" or item.get("alg", "HS256") != "HS256":
                    continue
                if "key_ops" in item and "verify" not in item["key_ops"]:
                    continue
                key = _b64d(item.get("k", ""))
                break
        if key is None:
            raise ValueError("unknown kid")
        signed = (parts[0] + "." + parts[1]).encode()
        want = hmac.new(key, signed, hashlib.sha256).digest()
        try:
            got = _b64d(parts[2])
        except Exception as exc:
            raise ValueError("bad sig") from exc
        if not hmac.compare_digest(got, want):
            raise ValueError("bad sig")
        for name in ("iss", "aud", "sub", "exp", "nbf", "iat", "jti", "nonce"):
            if name not in claims:
                raise ValueError("missing claim")
        if claims["iss"] != config["issuer"]:
            raise ValueError("bad issuer")
        aud = claims["aud"]
        if isinstance(aud, str):
            ok_aud = aud == config["audience"]
        elif isinstance(aud, list):
            ok_aud = config["audience"] in aud
            if ok_aud and len(aud) > 1 and claims.get("azp") != config.get("client_id"):
                raise ValueError("bad authorized party")
        else:
            ok_aud = False
        if not ok_aud:
            raise ValueError("bad audience")
        for name in ("exp", "nbf", "iat"):
            if not isinstance(claims[name], int):
                raise ValueError("bad time")
        if now >= claims["exp"] or now < claims["nbf"] or claims["iat"] > now + int(config.get("max_future_iat", 60)):
            raise ValueError("bad time window")
        if not isinstance(claims["jti"], str) or not isinstance(claims["nonce"], str) or not isinstance(claims["sub"], str):
            raise ValueError("bad string claim")
        if claims["jti"] in self.seen_jti or claims["nonce"] in self.seen_nonce:
            raise ValueError("replay")
        self.seen_jti.add(claims["jti"])
        self.seen_nonce.add(claims["nonce"])
        return claims

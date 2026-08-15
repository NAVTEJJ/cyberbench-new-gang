import base64, hashlib, hmac, xml.etree.ElementTree as ET

def local(tag): return tag.split("}", 1)[-1]
def children(e, name): return [x for x in list(e) if local(x.tag) == name]
def first(e, name):
    xs = children(e, name)
    if not xs: raise ValueError("missing")
    return xs[0]
def text(e, name): return (first(e, name).text or "")
def canon(elem):
    e = ET.fromstring(ET.tostring(elem, encoding="utf-8"))
    for c in list(e):
        if local(c.tag) == "Signature": e.remove(c)
    return ET.tostring(e, encoding="utf-8", short_empty_elements=True)

class SAMLVerifier:
    def verify(self, xml_text, config, now):
        low = xml_text.lower()
        if "<!doctype" in low or "<!entity" in low or "system " in low or "<?" in low or "xinclude" in low:
            raise ValueError("unsafe xml")
        try: root = ET.fromstring(xml_text)
        except Exception as exc: raise ValueError("bad xml") from exc
        ids = {}
        assertions = []
        for e in root.iter():
            if local(e.tag) == "Assertion": assertions.append(e)
            for k, v in e.attrib.items():
                if k in ("ID","Id","id"):
                    if v in ids: raise ValueError("duplicate id")
                    ids[v] = e
        signed_assertions = [a for a in assertions if children(a, "Signature")]
        if len(assertions) != 1:
            raise ValueError("assertion wrapping")
        if len(signed_assertions) != 1: raise ValueError("signed assertion count")
        a = signed_assertions[0]; aid = a.attrib.get("ID")
        sig = first(a, "Signature")
        si = text(sig, "SignedInfo")
        parts = si.split("|")
        if len(parts) != 4 or parts[0] != "HMAC-SHA256" or parts[1] != "SHA256" or parts[2] != "#" + aid:
            raise ValueError("bad signed info")
        digest = base64.b64encode(hashlib.sha256(canon(a)).digest()).decode()
        if parts[3] != digest or text(sig, "DigestValue") != digest:
            raise ValueError("bad digest")
        want = base64.b64encode(hmac.new(str(config["shared_secret"]).encode(), si.encode(), hashlib.sha256).digest()).decode()
        if not hmac.compare_digest(text(sig, "SignatureValue"), want):
            raise ValueError("bad signature")
        issuer = text(a, "Issuer")
        subject = text(first(a, "Subject"), "NameID")
        conf = first(first(a, "Subject"), "SubjectConfirmation")
        cond = first(a, "Conditions")
        aud = text(first(cond, "AudienceRestriction"), "Audience")
        authn = first(a, "AuthnStatement")
        if issuer != config["issuer"] or aud != config["audience"] or conf.attrib.get("Recipient") != config["recipient"] or conf.attrib.get("InResponseTo") != config["in_response_to"]:
            raise ValueError("bad claims")
        if now < int(cond.attrib["NotBefore"]) or now >= int(cond.attrib["NotOnOrAfter"]):
            raise ValueError("bad time")
        return {"subject": subject, "issuer": issuer, "audience": aud, "session_index": authn.attrib.get("SessionIndex")}

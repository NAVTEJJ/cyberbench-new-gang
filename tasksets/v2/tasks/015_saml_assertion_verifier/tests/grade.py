#!/usr/bin/env python3
import base64, hashlib, hmac, importlib.util, json, sys, xml.etree.ElementTree as ET
from pathlib import Path

SERVICE_ID = "saml_signature_wrapping_verifier"

def write_result(reward):
    details = {"reward": reward, "solved_service_ids": [SERVICE_ID] if reward else [], "unsolved_service_ids": [] if reward else [SERVICE_ID]}
    d = Path("/logs/verifier")
    try: d.mkdir(parents=True, exist_ok=True)
    except Exception: d = Path("logs/verifier"); d.mkdir(parents=True, exist_ok=True)
    (d/"reward.txt").write_text(f"{reward}\n"); (d/"details.json").write_text(json.dumps(details, indent=2, sort_keys=True)); print(json.dumps(details))

def load():
    p = Path("/src/solution.py") if Path("/src/solution.py").exists() else Path("solution.py")
    spec = importlib.util.spec_from_file_location("solution", p); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m.SAMLVerifier()

def canon(elem):
    e = ET.fromstring(ET.tostring(elem, encoding="utf-8"))
    for child in list(e):
        if child.tag.split("}")[-1] == "Signature": e.remove(child)
    return ET.tostring(e, encoding="utf-8", short_empty_elements=True)

def signed(assertion, secret=b"saml-shared"):
    digest = base64.b64encode(hashlib.sha256(canon(assertion)).digest()).decode()
    sid = assertion.attrib["ID"]
    signed_info = f"HMAC-SHA256|SHA256|#{sid}|{digest}"
    sig = base64.b64encode(hmac.new(secret, signed_info.encode(), hashlib.sha256).digest()).decode()
    sig_el = ET.fromstring(f"<ds:Signature xmlns:ds='urn:ds'><ds:SignedInfo>{signed_info}</ds:SignedInfo><ds:DigestValue>{digest}</ds:DigestValue><ds:SignatureValue>{sig}</ds:SignatureValue></ds:Signature>")
    assertion.insert(2, sig_el)
    return assertion

def assertion(aid="A1", sub="alice", aud="urn:sp", nb=900, noa=2000):
    return ET.fromstring(f"<saml:Assertion xmlns:saml='urn:saml' ID='{aid}'><saml:Issuer>https://idp.example</saml:Issuer><saml:Subject><saml:NameID>{sub}</saml:NameID><saml:SubjectConfirmation Recipient='https://sp.example/acs' InResponseTo='REQ7'/></saml:Subject><saml:Conditions NotBefore='{nb}' NotOnOrAfter='{noa}'><saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement SessionIndex='S123'/></saml:Assertion>")

def wrap(a):
    return "<Response xmlns='urn:saml'>" + ET.tostring(a, encoding="unicode") + "</Response>"

def main():
    cfg = {"issuer":"https://idp.example","audience":"urn:sp","recipient":"https://sp.example/acs","in_response_to":"REQ7","shared_secret":"saml-shared"}
    good = wrap(signed(assertion()))
    got = load().verify(good, cfg, 1000)
    assert got == {"subject":"alice","issuer":"https://idp.example","audience":"urn:sp","session_index":"S123"}
    evil_unsigned = ET.tostring(assertion("B2", "mallory"), encoding="unicode")
    cases = [
        "<!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>" + good,
        good.replace('NotOnOrAfter="2000"', 'NotOnOrAfter="999"'),
        good.replace("urn:sp", "urn:evil", 1),
        "<Response xmlns='urn:saml'>" + evil_unsigned + ET.tostring(signed(assertion("A1")), encoding="unicode") + "</Response>",
        good.replace("#A1", "#B2"),
        good.replace("alice", "mallory", 1),
    ]
    for c in cases:
        try: load().verify(c, cfg, 1000); raise AssertionError("accepted invalid SAML")
        except ValueError: pass
    write_result(1.0); return 0

if __name__ == "__main__":
    try: sys.exit(main())
    except Exception as exc: write_result(0.0); print(f"Verifier failure: {exc}", file=sys.stderr); sys.exit(1)

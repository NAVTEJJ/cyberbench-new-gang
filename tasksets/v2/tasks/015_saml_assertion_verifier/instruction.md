# Hardened SAML Assertion Verifier

Create `/src/solution.py`:

```python
class SAMLVerifier:
    def verify(self, xml_text: str, config: dict, now: int) -> dict:
        pass
```

Return verified claims or raise `ValueError`.

Rules:

- Reject any `DOCTYPE`, entity declaration, external entity, processing instruction, or XInclude-like tag.
- Parse XML with the standard library only.
- There must be exactly one signed `Assertion`.
- Reject duplicate `ID`, `Id`, or `id` values anywhere in the document.
- The signature reference URI must be `#<Assertion ID>`.
- Signature method must be `HMAC-SHA256`; digest method must be `SHA256`.
- Digest is `base64(sha256(canonical_assertion_bytes_without_signature))`.
- Signature is `base64(hmac_sha256(config["shared_secret"], signed_info_text))`.
- Enforce issuer, audience, subject, NotBefore/NotOnOrAfter, Recipient, InResponseTo, and SessionIndex.
- Reject signature wrapping where a signed assertion differs from the assertion used for claims.
- Support XML namespaces but do not rely on fixed prefixes.

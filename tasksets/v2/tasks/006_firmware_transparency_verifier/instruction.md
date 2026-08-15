# Firmware Transparency and Revocation Verifier

Create `/src/solution.py`:

```python
class FirmwareVerifier:
    def verify(self, bundle: dict, trust: dict, now: int) -> dict:
        pass
```

Accept firmware only if all checks pass:

- Manifest hash matches payload SHA256.
- Manifest version is greater than current device version for that channel.
- Signer certificate chains to a trusted root and is valid at signing time.
- Signer is not revoked at signing time.
- Signature is HMAC-SHA256 over canonical manifest using the certificate key from `trust["certs"]`.
- Transparency log inclusion proof verifies a Merkle root signed by the log key.
- SCT timestamp is within certificate validity and before `now`.
- Reject split-view roots, duplicate log indexes with different leaf hashes, rollback attempts, expired certificates, unknown channels, and critical extension mismatches.

Return `{"accepted": True, "version": "...", "channel": "...", "log_index": 123}` or raise `ValueError`.

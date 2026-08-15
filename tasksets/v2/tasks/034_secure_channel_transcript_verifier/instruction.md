# Secure Channel Transcript Verifier

Create `/src/solution.py`:

```python
class TranscriptVerifier:
    def verify(self, sessions: list[dict], policy: dict) -> list[dict]:
        pass
```

Validate simplified secure-channel transcripts. Detect:

- `DOWNGRADE`: negotiated version or cipher is lower than both peers advertised, or downgrade sentinel is missing.
- `NONCE_REPLAY`: client/server nonce reused across accepted sessions.
- `BAD_KEY_SCHEDULE`: transcript hash, exporter secret, or finished MAC does not bind all messages in order.
- `KCI_RISK`: static key compromise can authenticate an attacker because ephemeral contribution is absent.
- `CHANNEL_BINDING_MISMATCH`: app token binding does not match exporter value.

Use SHA256/HMAC from the standard library. Return sorted findings:

```python
{"session": "...", "type": "...", "evidence": "..."}
```

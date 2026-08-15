# Active Directory Attack Path Analyzer

Create `/src/solution.py`:

```python
class ADAttackGraph:
    def analyze(self, directory: dict) -> list[dict]:
        pass
```

Detect attack paths:

- `KERBEROAST`: user-controlled principal can request crackable service tickets for SPN accounts without AES-only hardening.
- `ASREP_ROAST`: pre-auth disabled account reachable from a low-privileged principal.
- `RBCD_TAKEOVER`: writeable `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer account.
- `DCSYNC`: replication rights on domain root through nested group membership.
- `ADCS_ESCALATION`: certificate template allows enrollee supplies subject plus client auth and low-privileged enrollment.

Resolve nested groups, inherited ACEs, deny ACE precedence, SID/name aliases, and disabled/protected accounts. Return sorted findings:

```python
{"principal": "...", "type": "...", "target": "...", "path": [...]}
```

# Browser Security Policy Auditor

Create `/src/solution.py`:

```python
class BrowserPolicyAuditor:
    def audit(self, observations: list[dict]) -> list[dict]:
        pass
```

Correlate HTTP responses, redirect chains, script sinks, cookies, and CORS preflight results.

Detect:

- `CSP_BYPASS`: nonce reuse across unrelated pages, wildcard script sources with JSONP endpoints, unsafe-inline without nonce, or base-uri missing when reflected base tags are observed.
- `CORS_CREDENTIAL_LEAK`: credentialed CORS with reflected Origin or wildcard-like regex matching attacker origins.
- `COOKIE_SCOPE_LEAK`: session cookies missing Secure/HttpOnly/SameSite, or domain scoped too broadly across sibling apps.
- `DOM_XSS_REACHABLE`: attacker-controlled source reaches dangerous sink and CSP does not block inline or imported script execution.
- `OPEN_REDIRECT_CHAIN`: redirect parameter can route through a trusted domain into an attacker-controlled final URL.

Return findings sorted by URL then type:

```python
{"url": "...", "type": "...", "evidence": "..."}
```

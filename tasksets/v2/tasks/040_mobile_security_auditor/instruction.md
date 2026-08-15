# Mobile App Security Auditor

Create `/src/solution.py`:

```python
class MobileSecurityAuditor:
    def audit(self, app: dict) -> list[dict]:
        pass
```

Analyze Android manifest-like data, network security config, deep links, exported components, WebView settings, JS bridges, backup policy, and intent filters.

Detect:

- `DEEPLINK_TAKEOVER`: exported browsable deep link lacks verified app links or has wildcard host/path with privileged actions.
- `WEBVIEW_RCE`: JavaScript enabled plus file/content access or unsafe JS bridge exposed to untrusted origins.
- `CLEAR_TEXT_TLS_BYPASS`: cleartext allowed for production domains, user CAs trusted in release, or certificate pinning disabled for API domains.
- `EXPORTED_PRIVILEGED_COMPONENT`: exported activity/service/receiver with privileged action and no signature permission.
- `BACKUP_SECRET_LEAK`: backups enabled while shared preferences, databases, or keystore aliases contain tokens/secrets.

Return sorted findings:

```python
{"component": "...", "type": "...", "evidence": "..."}
```

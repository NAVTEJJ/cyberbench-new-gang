# Container Image Layer Forensics Scanner

Create `/src/solution.py`:

```python
class ImageForensics:
    def scan(self, image: dict, policy: dict) -> list[dict]:
        pass
```

Analyze ordered container layers, history, SBOM packages, file capabilities, setuid files, entrypoints, and whiteout deletes.

Detect:

- `SECRET_IN_HISTORY`: credentials in deleted files, layer history, env, or build args, even if later whiteouted.
- `PRIVILEGE_DRIFT`: new setuid root file or dangerous Linux capability not present in the base layer.
- `REACHABLE_CVE`: vulnerable package is reachable from entrypoint/import graph and exceeds policy severity threshold.
- `WHITEOUT_HIDE`: whiteout deletes sensitive path after it was added in an earlier layer.
- `UNPINNED_REMOTE_EXEC`: entrypoint or install script fetches remote content and pipes to shell.

Return findings sorted by layer then type:

```python
{"layer": 3, "type": "...", "evidence": "..."}
```

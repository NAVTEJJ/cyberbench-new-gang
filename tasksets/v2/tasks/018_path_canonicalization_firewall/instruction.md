# Canonicalization Firewall

Create `/src/solution.py`:

```python
class PathFirewall:
    def decide(self, request: dict, policy: dict) -> dict:
        pass
```

Return `{"allow": bool, "canonical": "...", "reason": "..."}`.

The firewall protects a virtual document root. It must normalize and validate paths before opening files or extracting archive entries.

Rules:

- Decode percent-encoding repeatedly until stable, but reject malformed percent escapes and more than 3 decode rounds.
- Normalize Unicode with NFKC, casefold where policy says case-insensitive, convert `\` to `/`, collapse repeated slashes, and resolve `.` and `..`.
- Reject absolute paths, drive letters, UNC paths, NTFS alternate streams, NUL bytes, bidi override controls, and reserved Windows device names.
- Apply a virtual symlink map after each path component; symlinks may chain but cycles must be rejected.
- Deny if the final canonical path escapes `policy["root"]`.
- For archive mode, validate every entry in `request["entries"]`; reject zip-slip, symlink entries, absolute paths, and mixed separator tricks.
- Enforce allow extensions and deny globs after canonicalization.

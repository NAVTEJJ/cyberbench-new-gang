# Sanitizer Crash Triage Engine

Create `/src/solution.py`:

```python
class CrashTriage:
    def triage(self, reports: list[dict]) -> dict:
        pass
```

Each report contains sanitizer output, stderr, seed metadata, and optional source snippets.

Group crashes by root cause, not by raw addresses. Normalize ASLR addresses, inlined frames, line-column noise, and allocator frames. Identify:

- heap-buffer-overflow read/write
- stack-buffer-overflow
- use-after-free
- uninitialized read
- null dereference
- integer overflow leading to allocation underflow

Return stable groups with `id`, `class`, `access`, `top_user_frame`, `affected_function`, `seeds`, and `severity`. Severity is `critical` for write overflows/UAF with controlled input, `high` for read overflows/uninitialized disclosure, otherwise `medium`.

# HTTP/2 Gateway Smuggling Analyzer

Create `/src/solution.py`:

```python
class GatewayAnalyzer:
    def analyze(self, requests: list[dict]) -> list[dict]:
        pass
```

Each request contains HTTP/2 pseudo headers, normal headers, body metadata, and gateway rewrite observations. Detect:

- `H2_CL_TE_SMUGGLE`: HTTP/2 request contains forbidden `connection`, `transfer-encoding`, duplicate `content-length`, or conflicting body length after downgrade.
- `PSEUDO_HEADER_CONFUSION`: duplicated/misordered pseudo headers, missing `:authority`, absolute-form `:path`, or authority/host mismatch after rewrite.
- `CACHE_POISON`: cache key ignores attacker-controlled headers, query normalization differs from origin, or `x-forwarded-host` affects origin routing but not cache key.
- `REQUEST_SPLIT`: embedded CRLF in decoded headers/path after percent-decoding or Unicode normalization.
- `HOP_BY_HOP_LEAK`: hop-by-hop headers survive into the origin request.

Return findings sorted by request id then type:

```python
{"id": "...", "type": "...", "evidence": "..."}
```

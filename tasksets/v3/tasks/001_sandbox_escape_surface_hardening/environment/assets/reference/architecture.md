# Evaluation sandbox architecture

The `agent` executes untrusted benchmark work. Direct network membership grants bidirectional transport reachability, so a service must share a network only with peers it genuinely needs.

The intended data flows are:

```text
agent -> package-mirror -> proxy -> registry-cache
                                -> revocation-service

agent -> artifact-uploader -> scanner -> quarantine-store
```

`metadata`, `credential-broker`, and `evaluator` are isolated control-plane services. `callback` represents an untrusted external destination. None is part of an agent workflow, and workflow services must not become bridges to them.

## Package workflow

The agent requests immutable packages from `package-mirror`. The mirror uses the internal `proxy` for package reads and revocation checks. The proxy is not an agent-facing service. It accepts HTTPS requests only to explicitly authorized origins and path families.

Same-origin redirects are needed for immutable package objects. Redirect targets must be validated again after resolution. Cross-origin redirects, IP-literal destinations, non-HTTPS schemes, and caller credential forwarding are not required.

## Artifact workflow

The agent submits JSON metadata or opaque binary artifacts to `artifact-uploader`. The uploader passes an opaque object plus parsed manifest metadata to `scanner`; it never extracts an archive. The scanner alone may write approved objects to `quarantine-store`.

Each hop uses a separate audience- and scope-bound token. Possession of one workflow token must not authorize another hop.

## Runtime boundary

The agent requires no additional Linux capability, host namespace, host mount, evaluator mount, or writable root filesystem. Only its workspace and agent log directory are writable. Security controls must not make those two locations unavailable.

# `adversarial_tests.json`

Create a JSON object with a `scenarios` array. Scenario IDs must be unique and must not reuse a bundled public ID. Include at least sixteen original scenarios, at least six required-workflow `allow` cases, and at least ten exploit-regression `deny` cases. Cover all five kinds: `network`, `proxy`, `credential`, `artifact`, and `runtime`.

The public simulator accepts this file with `--scenario`. Network, proxy, credential, and artifact fields follow the bundled scenario examples.

Runtime scenarios use:

```json
{"id":"deny-host-pids","kind":"runtime","expect":"deny","service":"agent","operation":"access-host-pids"}
```

Supported runtime operations are:

- `gain-privileges`;
- `access-host-pids`;
- `use-capability` with `capability`;
- `use-mount` with `path` matching a mount source or target;
- `write-path` with an absolute `path`.

An allow test should represent a required workflow. A deny test should exercise behavior the vulnerable starting policy would have allowed. Renaming or copying a bundled scenario is not an original test.

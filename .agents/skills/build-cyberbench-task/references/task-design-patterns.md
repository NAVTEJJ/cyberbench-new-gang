# Fair hardening patterns

## Offensive exploitation

- Require discovery and chaining of observable vulnerability behavior rather than
  naming the exploit recipe in the instruction.
- Expose required protocol, binary, source, traffic, or error evidence through the
  intended interface.
- Preserve realistic exploit primitives while preventing direct flag reads,
  oracle leakage, unintended host access, and trivial alternate paths.
- Prefer generated layouts, tokens, or addresses when the intended reasoning should
  generalize, while keeping every necessary invariant recoverable.

## Investigation and discovery

- Replace single-hop clues with reconstructible joins across independent evidence.
- Add credible alternative hypotheses with real supporting evidence.
- Require causal controls or deterministic reproductions to distinguish producer from
  consumer and correlation from cause.
- Preserve the raw captures needed to prove each link.

## Defensive implementation and detection

- Generate identities, timestamps, topologies, and benign boundaries.
- Exercise lifecycle transitions such as create, consume, revoke, replay, and re-grant.
- Add overlapping incidents that share one key but must not be cross-joined.
- Test strict causal order, malformed input tolerance, optional telemetry, and exact
  evidence attribution.
- Mine successful submissions for general semantic assumptions, then replay them only as
  diagnostic regression fixtures.

## Policy and configuration hardening

- Grade effective behavior instead of exact static dictionaries.
- Require baseline-distinguishing adversarial tests, not renamed public scenarios.
- Test network reachability, runtime privileges, write boundaries, proxy behavior,
  credentials, artifacts, and preserved workflows separately.

## Avoid

- More report fields or minimum evidence counts.
- Hidden magic constants, exact event lists, or canonical path spellings.
- Undocumented allowlists and grader-only semantics.
- Noise that adds volume without an alternative causal explanation.
- Optional packages or specialist tools as the primary obstacle.

# Output schemas

## `incident.json`

```json
{
  "initial_access_event_id": "source-id",
  "identity_findings": [
    {
      "identity": "identity",
      "role": "directly_compromised|abused_execution_identity",
      "evidence_event_ids": ["source-id"],
      "rationale": "concise evidence-backed classification"
    }
  ],
  "affected_assets": ["asset"],
  "exfiltrated_dataset": "name-or-null",
  "attack_event_ids": ["ordered", "event", "ids"],
  "causal_links": [
    {
      "from_event_id": "source-id",
      "to_event_id": "source-id",
      "relationship": "short semantic label",
      "evidence": {"correlation-field": "observed-value"}
    }
  ],
  "summary": "concise causal explanation"
}
```

Use `directly_compromised` when the evidence shows an attacker-controlled
interactive credential or session. Use `abused_execution_identity` when an
attacker-controlled workflow causes a service or workload identity to exercise
its existing privileges without evidence that the identity's own credential
was stolen. Every finding must cite at least two attack events supporting that
distinction, and each cited event must name the classified identity.

Use canonical asset names derived from source fields. For example, a CI
repository can be written as `ci/inventory-service`, a workload as
`k8s/staging/checker-4`, and a database as `db/warehouse`.

`causal_links` must explain the major transitions in the submitted attack
chain. Each link must cite its two event IDs and at least one concrete observed
value supporting the relationship. Relationship labels are descriptive, not a
fixed vocabulary.

## `timeline.jsonl`

One JSON object per key event:

```json
{"event_id":"idp-0000","utc":"2026-07-17T08:12:00Z","phase":"initial-access","rationale":"..."}
```

## `containment_actions.json`

```json
{"actions":[{"action":"revoke_session","target":"session-id","parameters":{},"reason":"..."}]}
```

## `detection.json`

Use the sequence schema documented in `detection_schema.md`.

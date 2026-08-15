# `hardening_report.json`

```json
{
  "summary": "what changed and why",
  "findings": [
    {
      "id": "analyst-defined stable identifier",
      "title": "short finding title",
      "status": "remediated",
      "evidence": ["event IDs from one correlated root cause"],
      "attack_path": ["source", "intermediate", "target"],
      "policy_changes": ["services.json#/services/agent/networks"],
      "negative_tests": ["an ID from adversarial_tests.json"],
      "workflow_impact": "why required work still succeeds"
    }
  ],
  "benign_events": ["event IDs that show expected or blocked behavior"],
  "residual_risks": ["remaining risk that policy alone cannot remove"]
}
```

Requirements:

- Correlate events by `trace_id`; describe root causes instead of emitting one finding per line.
- Every event demonstrating exploitable behavior must be cited by a remediated finding.
- Benign, blocked, duplicate, and expected-workflow events must not be cited as vulnerability evidence.
- Every policy change must reference one of the four policy files and a JSON-pointer-like path.
- Every finding must reference at least one original negative test from `/app/adversarial_tests.json`.
- Findings must explain workflow impact rather than merely claiming that a simulator passes.

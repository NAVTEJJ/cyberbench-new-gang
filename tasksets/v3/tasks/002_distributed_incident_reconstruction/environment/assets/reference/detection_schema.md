# Durable sequence detection schema

Create a JSON object with:

- `name`: descriptive rule name
- `window_minutes`: positive integer
- `sequence`: ordered stages
- `suppressions`: optional benign-context suppressions

Each stage has:

- `event_type`
- optional `constraints`; plain keys require equality, while suffixes such as
  `_gte`, `_prefix`, `_suffix`, and `_not_suffix` apply the named comparison
- optional `bind`, mapping a variable name to an event field
- optional `join`, mapping an event field to a previously bound variable

Sequence stages are matched in timestamp order inside `window_minutes`. Variable
names are chosen by the rule author. A join is valid when its value refers to a
variable bound by an earlier stage.

Only `utc` and `event_type` are universal replay fields. Source-specific
enrichment fields may be absent in a campaign variant, so bind additional
fields only when they are necessary for the correlation. Stable identifiers
such as session, job, and export IDs should carry the sequence across layers.

Suppressions are dictionaries of contextual constraints. A matching event in a
candidate sequence suppresses that alert. They are useful for documented
approved workflows but are optional when the sequence itself excludes those
workflows.

A durable rule should capture the campaign behavior while rejecting plausible
administrative and data-movement lookalikes. It must not hardcode event IDs,
personal names, workload names, datasets, or known source addresses.

Test a candidate against the public replay set:

```bash
python3 /app/tools/test_detection.py /app/detection.json
```

The tool reports schema errors, missed malicious scenarios, and false positives.
The public cases are neutral smoke tests, not an exhaustive statement of the
decision boundary. A durable rule must derive its joins and benign exclusions
from the supplied telemetry, event semantics, and business context.

# Reconstruct and contain the Northstar incident

Northstar Analytics observed suspicious activity across identity, API gateway, CI, Kubernetes, database, and endpoint telemetry. The evidence is under `/app/evidence/`.

Using this:

1. reconstruct the attack and identify the initial access event;
2. classify directly compromised and abused execution identities, identify affected assets and any exfiltrated dataset, and provide evidence-backed causal links between key events;
3. produce a normalized UTC timeline of the key attack events;
4. select containment actions from the documented action catalog that stop the attacker while preserving normal forecast builds;
5. create one durable sequence detection for variants of this campaign.

Write:

- `/app/incident.json`
- `/app/timeline.jsonl`
- `/app/containment_actions.json`
- `/app/detection.json`

Schemas and operational constraints are in `/app/reference/`. Source timestamps must be normalized rather than copied verbatim.

Public behavior checks are available at `/app/tools/test_detection.py` and `/app/tools/simulate_containment.py`.

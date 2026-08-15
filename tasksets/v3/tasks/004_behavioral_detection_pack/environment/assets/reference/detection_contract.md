# Analyst deliverable contract

`detector.py` must define `detect(events: list[dict]) -> list[dict]`. Return no more than one finding for each supported family:

```json
{"family": "...", "evidence_event_ids": ["..."], "summary": "..."}
```

Evidence IDs must be unique, refer to supplied events, and identify every
essential step supporting the finding. The summary must explain the joined
behavior in at least 25 characters. Ignore records that cannot be parsed
without failing the batch.

# Event schema

Every record includes `event_id`, `source`, `reported_ts`, and `event_type`.
Source clocks are not synchronized. A `time_sync` event contains both the
source's `reported_ts` and a trusted `trusted_utc`. Its observed offset applies
from that sample until the next sample for the same source. A later sample may
record a clock correction, so do not assume one offset covers the whole window.

Source-specific fields include:

- identity records: `user`, `session_id`, `risk`, device context, and authentication changes;
- gateway records: request actor, session or export context, route, destination, and transfer size;
- CI records: repository, pipeline, execution identity, job metadata, and initiating context;
- Kubernetes records: namespace, workload, secret path, service account, and originating execution metadata;
- database records: principal, originating job, client workload, dataset, row count, and export metadata;
- endpoint records: host, user, process, command line, and execution metadata.

Identifiers and values may recur across sources. Determine which fields form a
credible relationship from their values, event meaning, timestamps, and the
surrounding records; field names alone are not proof of causality.

Duplicate records have different event IDs but a `duplicate_of` field. Do not treat a duplicate as another attack step.

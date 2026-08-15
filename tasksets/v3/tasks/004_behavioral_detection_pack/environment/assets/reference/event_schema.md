# Event schema

Every usable event has `event_id`, source-local `ts`, `source`, and
`event_type`. Unknown fields and unrelated types are noise. Duplicate records
reuse `event_id`; timestamp order, after source-offset normalization, determines
causality.

`clock_offsets_sec` records the correction from each source clock to Meridian
time. `identity_aliases` assigns aliases to canonical principals, and
`runner_jobs` assigns runners to jobs. `group_roles` and `role_capabilities`
describe effective group capabilities; `audience_catalog` classifies API
audiences. Corporate and release destination lists contain DNS suffixes.

Relevant event types:

- `oauth_device_authorized`: `user`, `session_id`, `risk`, `new_device`, `source_asn`.
- `api_token_used`: `principal`, `session_id`, `source_asn`, `audience`, `authz_version`.
- `mfa_method_added`: `user`, `session_id`.
- `secret_read`: `job_id`, `secret_path`, `sensitivity`, `authz_version`.
- `artifact_upload`: `runner_id`, `destination`, `bytes`.
- `ci_job_started`: `job_id`.
- `service_login`: `actor`, `account_type`, `dormant_days`.
- `group_membership_changed`: `actor`, `member`, `group`, `authz_version`, optional `ticket_id`.
- `remote_service_created`: `actor`.
- `authorization_edge_changed`: `transaction_id`, `edge_id`, `action` (`activate` or `revoke`).
- `authorization_policy_committed`: `transaction_id`, integer `policy_version`.

`organization_context.json` contains the current organization mappings and
security-control values.

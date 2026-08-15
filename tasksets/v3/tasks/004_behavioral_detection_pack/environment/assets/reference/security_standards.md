# Meridian security standards

For each control below, a valid policy commit must occur between the opening
event and the protected operation. It must change the matching subject-target
pair from no delegated route to a delegated route that remains present in the
operation's exact authorization snapshot.

## Interactive access review

A new-device OAuth authorization at or above `review_score_min` is reviewed
when the same canonical identity and session use a token within
`correlation_minutes`, from a non-corporate ASN, for an audience classified in
`protected_audience_classes`.

## CI restricted-data handling

A started CI job enters restricted scope when a read's sensitivity is listed or
its path has a restricted prefix. The read must occur within
`job_start_to_read_minutes`. Its mapped runner's later upload must meet
`external_upload_min_bytes` and `read_to_upload_minutes`. Exclude allowed secret
prefixes, corporate destinations, and approved release jobs uploading to a
release mirror.

## Dormant workload privilege

A login is a dormant workload when its account type equals
`service_account_value` and its dormancy meets `dormant_days_min`. Flag that
canonical principal adding itself within `login_to_change_minutes` to a group
whose effective role conveys a `privileged_capabilities` capability. Suppress an
approved break-glass ticket only when both canonical actor and group match.

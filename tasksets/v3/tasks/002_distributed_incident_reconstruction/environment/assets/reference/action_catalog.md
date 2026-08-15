# Simulated containment action catalog

Allowed actions:

- `revoke_session` target: identity `session_id`
- `remove_mfa_method` target: `method_id`
- `revoke_deploy_key` target: `key_id`
- `quarantine_workload` target: `namespace/pod`
- `rotate_secret` target: secret path
- `scope_identity` target: identity; parameters: `allowed_secret_prefixes` list
- `deny_secret_access` target: identity; parameters: `secret_paths` list
- `block_indicator` target: IP address
- `disable_identity` target: identity
- `disable_user` target: user
- `disable_repo` target: repository

Operational costs:

- `revoke_session`, `remove_mfa_method`, `revoke_deploy_key`, and
  `block_indicator`: 1 each
- `quarantine_workload`, `rotate_secret`, and `deny_secret_access`: 2 each
- `scope_identity`: 3
- `disable_identity`: 9
- `disable_user`: 10
- `disable_repo`: 12

A valid plan must cost no more than 10. Costs are additive, including redundant
or supplementary actions. This represents the operational burden of emergency
changes; it is not a requirement to use one exact action set.

Business and approval evidence is provided in
`/app/evidence/business_context.json`. It describes workflows that must remain
operational, but it does not identify which observed chain is malicious.

Containment succeeds only when every attacker capability is stopped, every
documented required workflow remains available, and the action-cost budget is
met. Different action sets may be equivalent. Test a candidate plan with:

```bash
python3 /app/tools/simulate_containment.py /app/containment_actions.json
```

The simulator reports residual attacker capabilities, disrupted workflows, and
the submitted plan's total cost.

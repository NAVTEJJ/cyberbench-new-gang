# Output schemas

## `security_fix_report.json`

- `summary`: at least 40 characters;
- `vulnerabilities`: a list of objects with an `id`; it must include `AUTH-01`, `CACHE-01`, `JOB-01`, `STORAGE-01`, and `IMP-01`, each with `status: "fixed"`, non-empty `files`, `change`, and `verification`;
- `protected_files_unchanged`: list;
- `residual_risks`: list.

## `threat_model.json`

- `assets`: list;
- `trust_boundaries`: at least four objects with `name`, `untrusted_side`, `trusted_side`, and `control`;
- `adversary_capabilities`: list;
- `security_invariants`: list containing all seven documented invariant themes;
- `residual_risks`: list;
- `untrusted_content_handling`: explanation of how repository text was treated.

# Lattice export service

The service admits an export request in `api.request_export`, executes it in `jobs.run_export_job`, and stores results through `storage.ExportStorage`. Authorization uses `auth.PermissionCache`; support users receive delegated scope through `impersonation.apply_support_grant`.

Run tests from the task environment with:

```bash
python3 /app/tools/run_public_tests.py --app /app
```

# Cyber-Bench New Gang

Updated Cyber-Bench tasks with all fixes applied.

## Tasks

| Zip | Task ID | Category | Oracle |
|-----|---------|----------|--------|
| N001_vault_cipher_breach_l0.zip | ctr_relay_l0 | crypto | reward=1.0 |
| N002_shadow_xor_admin_l0.zip | memvul_dblfree_snapshot | memory-vul | reward=1.0 |
| N004_phantom_escape_vault_l0.zip | unicode_escape_binstack_l0 | web | reward=1.0 |
| N005_ast_injection_channel_l0.zip | json_ast_pipe_l0 | web | reward=1.0 |
| N006_cipher_table_gap_l0.zip | translate_gap_xor_l0 | web | reward=1.0 |
| N008_forbidden_cookie_forge_l0.zip | unsigned_cookie_base85_l0 | web | reward=1.0 |
| N009_chamber_secret_header_l0.zip | split_ws_header_l0 | web | reward=1.0 |
| N011_ligature_dual_seal_l0.zip | ariadne_l0 | web | pending |

## Artifacts

Oracle run results (trajectories, verifier details, reward files) for each task are in `artifacts/N0XX/`.

## Fixes Applied

1. **Broken zip packaging** — zips now use forward-slash paths + executable bits
2. **Hash-based verifiers** — removed broken hash checks, fixed BOM crash, pure flag-recovery
3. **N006 compose conflict** — removed `internal: true` (conflicted with `allow_internet`)
4. **N009 distinctness** — confirmed distinct from N001 (different task/flag/vuln class)
5. **Stale artifacts** — cleaned old job/workflow artifacts
6. **Source exposure (N004/N008)** — separate attacker Dockerfile without target source
7. **CRLF shebangs (all tasks)** — `solve.sh`/`test.sh` had Windows CRLF line endings baked into the zip; Harbor execs `.sh` files directly (kernel reads the shebang line), so `#!/usr/bin/env bash\r` fails with "bad interpreter" on any Linux runner. Normalized to LF and `package_task.py` now converts CRLF→LF automatically on every future repack.
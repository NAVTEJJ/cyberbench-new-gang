# Role matrix

| Role/context | `export:create` | `export:read` |
|---|---:|---:|
| tenant `analyst` | yes | yes |
| tenant `admin` | yes | yes |
| tenant `viewer` | no | yes |
| no role for target tenant | no | no |
| support account with valid exact-tenant grant and matching scope | scope-dependent | scope-dependent |

A principal's `tenant_roles` is a mapping from tenant ID to a list of roles. Home tenant is descriptive and is not an authorization shortcut.

# Level 0 Challenge: Zero-Trust SPIFFE/SPIRE Workload Cryptographic Identity & mTLS Node Attestation Engine (`spiffe_spire_workload_attestation_l0`)

You are tasked with implementing a **Zero-Trust SPIFFE/SPIRE Workload Cryptographic Identity & mTLS Node Attestation Engine** (`spiffe_spire_workload_attestation_l0`) in C inside `/src/target.c`.

## Background & Challenge Context

In modern zero-trust cloud architectures (such as Kubernetes and Envoy service meshes), workloads communicate across mutual TLS (mTLS) pipes authenticated by SPIFFE Verifiable Identity Documents (`X.509-SVID` or `JWT-SVID`). Each workload is identified by a SPIFFE ID (`spiffe://<trust_domain>/<workload_path>`) and attested at runtime via node and workload selectors (`k8s:sa:backend`, `unix:uid:1001`).

If an attacker spoofs node attestation selectors, steals an SVID private key without authorization, or attempts URI path traversal to bypass trust domain federation boundaries (`spiffe://evil.domain/..`), unvalidated identity federation allows unauthorized microservices to access sensitive enterprise APIs (`SPIFFE_ERR_SELECTOR_MISMATCH` / `SPIFFE_ERR_UNTRUSTED_DOMAIN`).

You must implement the core verification engine (`spiffe_engine_t`) enforcing strict SPIFFE URI syntax, SVID cryptographic digest verification, temporal validity windows, and exact node attestation selector matching.

## Target File: `/src/target.c`

Your implementation must define the following structs, error codes, and **five core verification functions** exactly:

### Error Codes & Constants
```c
#define SPIFFE_SUCCESS                  0
#define SPIFFE_ERR_NULL_PTR            -1
#define SPIFFE_ERR_INVALID_URI         -2
#define SPIFFE_ERR_UNTRUSTED_DOMAIN    -3
#define SPIFFE_ERR_EXPIRED_SVID        -4
#define SPIFFE_ERR_SIG_MISMATCH        -5
#define SPIFFE_ERR_SELECTOR_MISMATCH   -6
#define SPIFFE_ERR_UNAUTHORIZED_PEER   -7

#define SPIFFE_MAX_SELECTORS           8
#define SPIFFE_MAX_ENTRIES             16
```

### Struct Definitions
```c
typedef struct {
    char selector_type[32];   /* e.g. "k8s:sa" or "unix:uid" */
    char selector_value[64];  /* e.g. "backend-service" or "1001" */
} spiffe_selector_t;

typedef struct {
    char spiffe_id[128];      /* e.g. "spiffe://local.mesh/backend" */
    spiffe_selector_t selectors[SPIFFE_MAX_SELECTORS];
    int num_selectors;
    int is_active;
} spiffe_registration_entry_t;

typedef struct {
    char spiffe_id[128];
    unsigned long not_before;
    unsigned long not_after;
    unsigned int signature_hash; /* simulated SHA-256 digest over claims */
} spiffe_svid_t;

typedef struct {
    char local_trust_domain[64]; /* e.g. "local.mesh" */
    unsigned long current_epoch;
    unsigned int trust_bundle_pubkey_hash;
    spiffe_registration_entry_t entries[SPIFFE_MAX_ENTRIES];
    int num_entries;
} spiffe_engine_t;
```

### Function Requirements

#### 1. `int spiffe_engine_init(spiffe_engine_t *engine, const char *trust_domain, unsigned long current_epoch, unsigned int pubkey_hash)`
- If `engine` or `trust_domain` is `NULL`, returns `SPIFFE_ERR_NULL_PTR`.
- Zeroes `entries`, sets `num_entries = 0`, copies `trust_domain` into `local_trust_domain` (null-terminated), and sets `current_epoch = current_epoch` and `trust_bundle_pubkey_hash = pubkey_hash`.
- Returns `SPIFFE_SUCCESS`.

#### 2. `int spiffe_validate_uri_syntax(const spiffe_engine_t *engine, const char *spiffe_id)`
- If `engine` or `spiffe_id` is `NULL`, returns `SPIFFE_ERR_NULL_PTR`.
- Enforces strict URI syntax:
  - Must begin with `"spiffe://"`. If not, returns `SPIFFE_ERR_INVALID_URI` (`-2`).
  - The character immediately following `"spiffe://"` must not be `'/'` or `'\0'`. If so, returns `SPIFFE_ERR_INVALID_URI` (`-2`).
  - If the path portion after `"spiffe://"` contains `"../"` or `"//"`, returns `SPIFFE_ERR_INVALID_URI` (`-2`).
- Extracts the trust domain (the substring after `"spiffe://"` up to the next `'/'` or `'\0'`).
- Checks if the extracted domain matches `engine->local_trust_domain` (using `strcmp`). If not, returns `SPIFFE_ERR_UNTRUSTED_DOMAIN` (`-3`).
- If all checks pass, returns `SPIFFE_SUCCESS` (`0`).

#### 3. `int spiffe_verify_svid_integrity(const spiffe_engine_t *engine, const spiffe_svid_t *svid)`
- If `engine` or `svid` is `NULL`, returns `SPIFFE_ERR_NULL_PTR`.
- Calls `spiffe_validate_uri_syntax(engine, svid->spiffe_id)`. If it returns an error (`< 0`), return that exact error (`-2` or `-3`).
- Checks temporal boundaries: if `engine->current_epoch < svid->not_before` or `engine->current_epoch >= svid->not_after`, returns `SPIFFE_ERR_EXPIRED_SVID` (`-4`).
- Checks cryptographic signature hash: if `svid->signature_hash != engine->trust_bundle_pubkey_hash`, returns `SPIFFE_ERR_SIG_MISMATCH` (`-5`).
- Otherwise, returns `SPIFFE_SUCCESS` (`0`).

#### 4. `int spiffe_register_workload(spiffe_engine_t *engine, const char *spiffe_id, const spiffe_selector_t *selectors, int num_selectors)`
- If `engine`, `spiffe_id`, or `selectors` is `NULL`, returns `SPIFFE_ERR_NULL_PTR`.
- If `num_selectors < 1` or `num_selectors > SPIFFE_MAX_SELECTORS` or `engine->num_entries >= SPIFFE_MAX_ENTRIES`, returns `SPIFFE_ERR_NULL_PTR`.
- Calls `spiffe_validate_uri_syntax(engine, spiffe_id)`. If `< 0`, return that exact error.
- Copies `spiffe_id` and all `selectors` into `engine->entries[engine->num_entries]`, sets `num_selectors = num_selectors` and `is_active = 1`.
- Increments `engine->num_entries` and returns `SPIFFE_SUCCESS` (`0`).

#### 5. `int spiffe_authorize_mtls_connection(const spiffe_engine_t *engine, const spiffe_svid_t *client_svid, const spiffe_selector_t *client_selectors, int num_client_selectors)`
- If `engine`, `client_svid`, or `client_selectors` is `NULL` (or `num_client_selectors < 0`), returns `SPIFFE_ERR_NULL_PTR`.
- Calls `spiffe_verify_svid_integrity(engine, client_svid)`. If `< 0`, returns that exact error (`-2`, `-3`, `-4`, or `-5`).
- Searches `engine->entries` for an entry where `is_active == 1` AND `strcmp(entry.spiffe_id, client_svid->spiffe_id) == 0`.
  - If no matching active registration is found, returns `SPIFFE_ERR_UNAUTHORIZED_PEER` (`-7`).
- **Workload Selector Attestation Check**: For every required selector (`entry.selectors[j]`, where `0 <= j < entry.num_selectors`) in the registered workload entry, verify that there exists an identical selector in `client_selectors[0..num_client_selectors-1]` (where both `selector_type` and `selector_value` strictly match via `strcmp`).
  - If any required selector from the registration entry is not found among `client_selectors`, return `SPIFFE_ERR_SELECTOR_MISMATCH` (`-6`).
- If all required selectors match and SVID integrity is verified, return `SPIFFE_SUCCESS` (`0`).

## Verification Requirements

Your implementation in `/src/target.c` must compile cleanly under `-O2 -Wall -Werror -fsanitize=address,undefined`. When successfully verified against the test harness, it outputs the unique confirmation flag `cyberbench{spiffe_spire_workload_attestation_state_5d1a7b3c9e8024f6}`.

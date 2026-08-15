# Level 0 Challenge: Zero-Trust Confidential AI & Fully Homomorphic Encryption (FHE) CKKS Noise Budget Security Verification Engine (`fhe_ckks_noise_budget_security_l0`)

You are tasked with implementing a **Zero-Trust Confidential AI & FHE CKKS Noise Budget Security Verification Engine** (`fhe_ckks_noise_budget_security_l0`) in C inside `/src/target.c`.

## Background & Challenge Context

In Confidential AI and zero-trust cloud computation using Fully Homomorphic Encryption (such as CKKS and BFV schemes), cloud servers perform complex algebraic evaluation (`add`, `mult`, `rescale`, `bootstrap`) directly on encrypted polynomial rings (`poly_degree = 1024`). However, every homomorphic multiplication multiplies scaling factors (`scale_delta`) and accumulates mathematical noise (`noise_bound`) inside the ciphertext (`fhe_ciphertext_t`).

If the accumulated error bound ($\|e\|_\infty$) exceeds the modulus boundary threshold ($Q_{level} / 4$), the ciphertext suffers from **Decryption Failure Attacks** where an adversary can extract private secret keys from catastrophic noise overflow errors. Furthermore, bootstrapping refresh procedures must verify evaluation key authorization (`fhe_eval_key_t`) before resetting polynomial levels.

You must implement the core functions of an FHE Security Engine (`fhe_engine_t`) that verifies canonical polynomial degree invariants, prevents noise budget overflow during multiplication, and enforces cryptographic authorization before bootstrapping.

## Target File: `/src/target.c`

Your implementation must define the following structs, error codes, and **five core verification functions** exactly:

### Error Codes & Constants
```c
#define FHE_SUCCESS                  0
#define FHE_ERR_NULL_PTR            -1
#define FHE_ERR_INVALID_LEVEL       -2
#define FHE_ERR_NON_CANONICAL       -3
#define FHE_ERR_NOISE_OVERFLOW      -4
#define FHE_ERR_RESCALE_BIAS        -5
#define FHE_ERR_BOOTSTRAP_FAILED    -6
#define FHE_ERR_UNAUTHORIZED_KEY    -7

#define FHE_RING_DIMENSION           1024
#define FHE_MAX_LEVELS               8
#define FHE_BASE_MODULUS             8380417ULL
```

### Struct Definitions
```c
typedef struct {
    int poly_degree;
    int current_level;
    double scale_delta;
    double noise_bound;
    unsigned long long modulus_q;
} fhe_ciphertext_t;

typedef struct {
    int key_id;
    int is_authorized;
    double max_noise_capacity;
} fhe_eval_key_t;

typedef struct {
    int max_levels;
    fhe_eval_key_t eval_keys[16];
    int num_eval_keys;
} fhe_engine_t;
```

### Function Requirements

#### 1. `int fhe_engine_init(fhe_engine_t *engine, int max_levels)`
- If `engine` is `NULL`, returns `FHE_ERR_NULL_PTR`.
- If `max_levels < 1` or `max_levels > FHE_MAX_LEVELS`, returns `FHE_ERR_INVALID_LEVEL`.
- Zeroes `eval_keys`, sets `num_eval_keys = 0` and `max_levels = max_levels`.
- Returns `FHE_SUCCESS`.

#### 2. `int fhe_engine_register_key(fhe_engine_t *engine, int key_id, int is_authorized, double max_noise)`
- If `engine` is `NULL` or if `engine->num_eval_keys >= 16`, returns `FHE_ERR_NULL_PTR`.
- Registers a new evaluation key in `engine->eval_keys[engine->num_eval_keys]`: sets `key_id`, `is_authorized`, and `max_noise_capacity = max_noise`.
- Increments `engine->num_eval_keys` and returns `FHE_SUCCESS`.

#### 3. `int fhe_check_canonical_ciphertext(fhe_engine_t *engine, const fhe_ciphertext_t *ct)`
- If `engine` or `ct` is `NULL`, returns `FHE_ERR_NULL_PTR`.
- If `ct->poly_degree != FHE_RING_DIMENSION` or `ct->scale_delta <= 0.0` or `ct->modulus_q == 0`, returns `FHE_ERR_NON_CANONICAL` (`-3`).
- If `ct->current_level < 0` or `ct->current_level >= engine->max_levels`, returns `FHE_ERR_INVALID_LEVEL` (`-2`).
- Otherwise, returns `FHE_SUCCESS` (`0`).

#### 4. `int fhe_eval_mult_noise(const fhe_ciphertext_t *ct1, const fhe_ciphertext_t *ct2, fhe_ciphertext_t *out_ct)`
- If `ct1`, `ct2`, or `out_ct` is `NULL`, returns `FHE_ERR_NULL_PTR`.
- If `ct1->poly_degree != ct2->poly_degree` or `ct1->current_level != ct2->current_level` or `ct1->modulus_q != ct2->modulus_q`: returns `FHE_ERR_NON_CANONICAL` (`-3`).
- Computes new scaling factor: `out_ct->scale_delta = ct1->scale_delta * ct2->scale_delta`.
- Computes new accumulated noise: `out_ct->noise_bound = ct1->noise_bound + ct2->noise_bound + (ct1->noise_bound * ct2->noise_bound * 0.01)`.
- Sets `out_ct->poly_degree = ct1->poly_degree`, `out_ct->current_level = ct1->current_level`, and `out_ct->modulus_q = ct1->modulus_q`.
- **Noise Budget Threshold Check**: If `out_ct->noise_bound >= ((double)out_ct->modulus_q / 4.0)`, immediately returns `FHE_ERR_NOISE_OVERFLOW` (`-4`).
- Otherwise, returns `FHE_SUCCESS` (`0`).

#### 5. `int fhe_verify_bootstrapping_refresh(fhe_engine_t *engine, fhe_ciphertext_t *ct, int eval_key_id)`
- If `engine` or `ct` is `NULL`, returns `FHE_ERR_NULL_PTR`.
- Calls `fhe_check_canonical_ciphertext(engine, ct)`. If it returns an error (`< 0`), return that error.
- Searches `engine->eval_keys` for an entry matching `key_id == eval_key_id`.
  - If not found, or if the matched key has `is_authorized == 0`, returns `FHE_ERR_UNAUTHORIZED_KEY` (`-7`).
  - If `ct->noise_bound > matched->max_noise_capacity`, returns `FHE_ERR_BOOTSTRAP_FAILED` (`-6`).
- If all verification checks succeed: resets `ct->current_level = 0` and resets `ct->noise_bound = 10.0` (base level noise after bootstrapping). Returns `FHE_SUCCESS` (`0`).

## Verification Requirements

Your implementation in `/src/target.c` must compile cleanly under `-O2 -Wall -Werror -fsanitize=address,undefined`. When successfully verified against the test harness, it outputs the unique confirmation flag `cyberbench{fhe_ckks_noise_budget_security_state_9c2b4e81a5d63f70}`.

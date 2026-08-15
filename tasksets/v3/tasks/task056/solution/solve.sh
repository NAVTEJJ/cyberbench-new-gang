#!/bin/bash
set -e
mkdir -p /src
cat << 'EOF' > /src/target.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* --- REFERENCE SOLUTION --- */

int spiffe_engine_init(spiffe_engine_t *engine, const char *trust_domain, unsigned long current_epoch, unsigned int pubkey_hash) {
    if (!engine || !trust_domain) return SPIFFE_ERR_NULL_PTR;
    memset(engine->entries, 0, sizeof(engine->entries));
    engine->num_entries = 0;
    strncpy(engine->local_trust_domain, trust_domain, sizeof(engine->local_trust_domain) - 1);
    engine->local_trust_domain[sizeof(engine->local_trust_domain) - 1] = '\0';
    engine->current_epoch = current_epoch;
    engine->trust_bundle_pubkey_hash = pubkey_hash;
    return SPIFFE_SUCCESS;
}

int spiffe_validate_uri_syntax(const spiffe_engine_t *engine, const char *spiffe_id) {
    if (!engine || !spiffe_id) return SPIFFE_ERR_NULL_PTR;
    const char prefix[] = "spiffe://";
    if (strncmp(spiffe_id, prefix, strlen(prefix)) != 0) {
        return SPIFFE_ERR_INVALID_URI;
    }
    const char *domain_start = spiffe_id + strlen(prefix);
    if (*domain_start == '/' || *domain_start == '\0') {
        return SPIFFE_ERR_INVALID_URI;
    }
    if (strstr(domain_start, "../") != NULL || strstr(domain_start, "//") != NULL) {
        return SPIFFE_ERR_INVALID_URI;
    }

    char domain_buf[64];
    const char *slash = strchr(domain_start, '/');
    size_t domain_len = slash ? (size_t)(slash - domain_start) : strlen(domain_start);
    if (domain_len >= sizeof(domain_buf)) return SPIFFE_ERR_INVALID_URI;
    memcpy(domain_buf, domain_start, domain_len);
    domain_buf[domain_len] = '\0';

    if (strcmp(domain_buf, engine->local_trust_domain) != 0) {
        return SPIFFE_ERR_UNTRUSTED_DOMAIN;
    }
    return SPIFFE_SUCCESS;
}

int spiffe_verify_svid_integrity(const spiffe_engine_t *engine, const spiffe_svid_t *svid) {
    if (!engine || !svid) return SPIFFE_ERR_NULL_PTR;
    int res = spiffe_validate_uri_syntax(engine, svid->spiffe_id);
    if (res < 0) return res;

    if (engine->current_epoch < svid->not_before || engine->current_epoch >= svid->not_after) {
        return SPIFFE_ERR_EXPIRED_SVID;
    }
    if (svid->signature_hash != engine->trust_bundle_pubkey_hash) {
        return SPIFFE_ERR_SIG_MISMATCH;
    }
    return SPIFFE_SUCCESS;
}

int spiffe_register_workload(spiffe_engine_t *engine, const char *spiffe_id, const spiffe_selector_t *selectors, int num_selectors) {
    if (!engine || !spiffe_id || !selectors) return SPIFFE_ERR_NULL_PTR;
    if (num_selectors < 1 || num_selectors > SPIFFE_MAX_SELECTORS || engine->num_entries >= SPIFFE_MAX_ENTRIES) {
        return SPIFFE_ERR_NULL_PTR;
    }
    int res = spiffe_validate_uri_syntax(engine, spiffe_id);
    if (res < 0) return res;

    spiffe_registration_entry_t *entry = &engine->entries[engine->num_entries];
    strncpy(entry->spiffe_id, spiffe_id, sizeof(entry->spiffe_id) - 1);
    entry->spiffe_id[sizeof(entry->spiffe_id) - 1] = '\0';
    for (int i = 0; i < num_selectors; i++) {
        entry->selectors[i] = selectors[i];
    }
    entry->num_selectors = num_selectors;
    entry->is_active = 1;

    engine->num_entries++;
    return SPIFFE_SUCCESS;
}

int spiffe_authorize_mtls_connection(const spiffe_engine_t *engine, const spiffe_svid_t *client_svid, const spiffe_selector_t *client_selectors, int num_client_selectors) {
    if (!engine || !client_svid || !client_selectors || num_client_selectors < 0) return SPIFFE_ERR_NULL_PTR;
    int res = spiffe_verify_svid_integrity(engine, client_svid);
    if (res < 0) return res;

    const spiffe_registration_entry_t *matched = NULL;
    for (int i = 0; i < engine->num_entries; i++) {
        if (engine->entries[i].is_active && strcmp(engine->entries[i].spiffe_id, client_svid->spiffe_id) == 0) {
            matched = &engine->entries[i];
            break;
        }
    }
    if (!matched) return SPIFFE_ERR_UNAUTHORIZED_PEER;

    for (int j = 0; j < matched->num_selectors; j++) {
        int found = 0;
        for (int k = 0; k < num_client_selectors; k++) {
            if (strcmp(matched->selectors[j].selector_type, client_selectors[k].selector_type) == 0 &&
                strcmp(matched->selectors[j].selector_value, client_selectors[k].selector_value) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            return SPIFFE_ERR_SELECTOR_MISMATCH;
        }
    }
    return SPIFFE_SUCCESS;
}

/* --- VERIFICATION HARNESS --- */
int main(void) {
    int checks_passed = 0;
    int total_checks = 8;
    spiffe_engine_t eng;

    /* Check 1: Init & NULL pointers */
    if (spiffe_engine_init(&eng, "cluster.local", 1700000000UL, 0xABCDEF01) == SPIFFE_SUCCESS &&
        eng.num_entries == 0 &&
        strcmp(eng.local_trust_domain, "cluster.local") == 0 &&
        spiffe_engine_init(NULL, "cluster.local", 1700000000UL, 0) == SPIFFE_ERR_NULL_PTR &&
        spiffe_engine_init(&eng, NULL, 1700000000UL, 0) == SPIFFE_ERR_NULL_PTR) {
        checks_passed++;
    }

    /* Check 2: URI syntax & trust domain enforcement */
    if (spiffe_validate_uri_syntax(&eng, "spiffe://cluster.local/ns/prod/sa/backend") == SPIFFE_SUCCESS &&
        spiffe_validate_uri_syntax(&eng, "https://cluster.local/ns/prod") == SPIFFE_ERR_INVALID_URI &&
        spiffe_validate_uri_syntax(&eng, "spiffe:///backend") == SPIFFE_ERR_INVALID_URI &&
        spiffe_validate_uri_syntax(&eng, "spiffe://cluster.local/../etc/passwd") == SPIFFE_ERR_INVALID_URI &&
        spiffe_validate_uri_syntax(&eng, "spiffe://evil.cluster/backend") == SPIFFE_ERR_UNTRUSTED_DOMAIN) {
        checks_passed++;
    }

    /* Check 3: SVID integrity verification (temporal & signature) */
    spiffe_svid_t valid_svid = {"spiffe://cluster.local/backend", 1699999000UL, 1700001000UL, 0xABCDEF01};
    spiffe_svid_t expired_svid = {"spiffe://cluster.local/backend", 1600000000UL, 1699999999UL, 0xABCDEF01};
    spiffe_svid_t badsig_svid = {"spiffe://cluster.local/backend", 1699999000UL, 1700001000UL, 0xDEADBEEF};
    if (spiffe_verify_svid_integrity(&eng, &valid_svid) == SPIFFE_SUCCESS &&
        spiffe_verify_svid_integrity(&eng, &expired_svid) == SPIFFE_ERR_EXPIRED_SVID &&
        spiffe_verify_svid_integrity(&eng, &badsig_svid) == SPIFFE_ERR_SIG_MISMATCH) {
        checks_passed++;
    }

    /* Check 4: Workload registration */
    spiffe_selector_t sels[2] = {
        {"k8s:sa", "backend-service"},
        {"unix:uid", "1001"}
    };
    if (spiffe_register_workload(&eng, "spiffe://cluster.local/backend", sels, 2) == SPIFFE_SUCCESS &&
        eng.num_entries == 1 &&
        strcmp(eng.entries[0].spiffe_id, "spiffe://cluster.local/backend") == 0 &&
        eng.entries[0].num_selectors == 2 &&
        eng.entries[0].is_active == 1) {
        checks_passed++;
    }

    /* Check 5: mTLS connection authorization success */
    if (spiffe_authorize_mtls_connection(&eng, &valid_svid, sels, 2) == SPIFFE_SUCCESS) {
        checks_passed++;
    }

    /* Check 6: mTLS authorization failure - expired or invalid SVID */
    if (spiffe_authorize_mtls_connection(&eng, &expired_svid, sels, 2) == SPIFFE_ERR_EXPIRED_SVID &&
        spiffe_authorize_mtls_connection(&eng, &badsig_svid, sels, 2) == SPIFFE_ERR_SIG_MISMATCH) {
        checks_passed++;
    }

    /* Check 7: mTLS authorization failure - selector attestation mismatch / spoofing */
    spiffe_selector_t spoofed_sels[2] = {
        {"k8s:sa", "frontend-service"}, /* wrong service account */
        {"unix:uid", "1001"}
    };
    spiffe_selector_t partial_sels[1] = {
        {"k8s:sa", "backend-service"}   /* missing unix:uid selector */
    };
    if (spiffe_authorize_mtls_connection(&eng, &valid_svid, spoofed_sels, 2) == SPIFFE_ERR_SELECTOR_MISMATCH &&
        spiffe_authorize_mtls_connection(&eng, &valid_svid, partial_sels, 1) == SPIFFE_ERR_SELECTOR_MISMATCH) {
        checks_passed++;
    }

    /* Check 8: mTLS authorization failure - unregistered peer */
    spiffe_svid_t unknown_svid = {"spiffe://cluster.local/unregistered", 1699999000UL, 1700001000UL, 0xABCDEF01};
    if (spiffe_authorize_mtls_connection(&eng, &unknown_svid, sels, 2) == SPIFFE_ERR_UNAUTHORIZED_PEER) {
        checks_passed++;
    }

    if (checks_passed == total_checks) {
        printf("cyberbench{spiffe_spire_workload_attestation_state_5d1a7b3c9e8024f6}\n");
        FILE *fp = fopen("submissions.txt", "w");
        if (fp) {
            fprintf(fp, "cyberbench{spiffe_spire_workload_attestation_state_5d1a7b3c9e8024f6}\n");
            fclose(fp);
        }
    } else {
        printf("FAILED checks: %d/%d passed\n", checks_passed, total_checks);
    }
    return 0;
}

EOF

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "rsa.h"
#include "paillier.h"

#define NONCE_BYTES 16
#define MAX_VOTERS 38
#define VOTING_DURATION_SECONDS (10 * 60)

static int hexchar_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int parse_fixed_hex(const char *hex, unsigned char *out, size_t out_len) {
    size_t len = strlen(hex);
    while (len > 0 && (hex[len - 1] == '\n' || hex[len - 1] == '\r')) {
        len--;
    }
    if (len != out_len * 2) {
        return 0;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexchar_to_val(hex[2 * i]);
        int lo = hexchar_to_val(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static BIGNUM *token_hash_to_bn(const unsigned char token_hash[SHA256_DIGEST_LENGTH],
                                const BIGNUM *N, BN_CTX *ctx) {
    BIGNUM *m = BN_new();
    if (!m) return NULL;

    BN_bin2bn(token_hash, SHA256_DIGEST_LENGTH, m);

    if (BN_cmp(m, N) >= 0) {
        BIGNUM *tmp = BN_new();
        if (!tmp) {
            BN_free(m);
            return NULL;
        }
        if (!BN_mod(tmp, m, N, ctx)) {
            BN_free(m);
            BN_free(tmp);
            return NULL;
        }
        BN_free(m);
        m = tmp;
    }

    return m;
}

static int verify_signature(const BIGNUM *m, const BIGNUM *s,
                            const BIGNUM *N, const BIGNUM *e, BN_CTX *ctx) {
    int res = 0;
    BIGNUM *m_check = BN_new();
    if (!m_check) return 0;

    if (!BN_mod_exp(m_check, s, e, N, ctx)) {
        BN_free(m_check);
        return 0;
    }

    res = (BN_cmp(m_check, m) == 0);
    BN_free(m_check);
    return res;
}


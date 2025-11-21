#include <openssl/bn.h>
#include "rsa.h"

int rsa_generate_keypair(BIGNUM **n_out, BIGNUM **e_out, BIGNUM **d_out, int bits) {
    int ret = 0;

    BN_CTX *ctx = NULL;
    BIGNUM *p = NULL, *q = NULL;
    BIGNUM *phi = NULL, *p1 = NULL, *q1 = NULL;
    BIGNUM *g = NULL;
    BIGNUM *n = NULL, *e = NULL, *d = NULL;

    ctx = BN_CTX_new();
    if (!ctx) goto done;

    p   = BN_new();
    q   = BN_new();
    phi = BN_new();
    p1  = BN_new();
    q1  = BN_new();
    g   = BN_new();
    n   = BN_new();
    e   = BN_new();
    d   = BN_new();

    if (!p || !q || !phi || !p1 || !q1 || !g || !n || !e || !d) goto done;

    if (!BN_set_word(e, 65537)) goto done;

    int prime_bits = bits / 2;

    while (1) {
        if (!BN_generate_prime_ex(p, prime_bits, 0, NULL, NULL, NULL)) goto done;
        if (!BN_generate_prime_ex(q, prime_bits, 0, NULL, NULL, NULL)) goto done;

        if (BN_cmp(p, q) == 0) continue;

        if (!BN_copy(p1, p)) goto done;
        if (!BN_sub_word(p1, 1)) goto done;
        if (!BN_copy(q1, q)) goto done;
        if (!BN_sub_word(q1, 1)) goto done;
        if (!BN_mul(phi, p1, q1, ctx)) goto done;

        if (!BN_gcd(g, e, phi, ctx)) goto done;

        if (BN_is_one(g)) {
            break;
        }
    }

    if (!BN_mul(n, p, q, ctx)) goto done;

    if (!BN_mod_inverse(d, e, phi, ctx)) goto done;

    *n_out = n;  n = NULL;
    *e_out = e;  e = NULL;
    *d_out = d;  d = NULL;

    ret = 1;

done:
    if (p)   BN_free(p);
    if (q)   BN_free(q);
    if (phi) BN_free(phi);
    if (p1)  BN_free(p1);
    if (q1)  BN_free(q1);
    if (g)   BN_free(g);
    if (n)   BN_free(n);
    if (e)   BN_free(e);
    if (d)   BN_free(d);
    if (ctx) BN_CTX_free(ctx);
    return ret;
}

int rsa_encrypt(const BIGNUM *m, const BIGNUM *n, const BIGNUM *e, BIGNUM *c_out, BN_CTX *ctx) {
    if (!BN_mod_exp(c_out, m, e, n, ctx)) {
        return 0;
    }
    return 1;
}

int rsa_decrypt(const BIGNUM *c, const BIGNUM *n, const BIGNUM *d, BIGNUM *m_out, BN_CTX *ctx) {
    if (!BN_mod_exp(m_out, c, d, n, ctx)) {
        return 0;
    }
    return 1;
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "rsa.h"

#define RSA_BITS 2048

typedef struct {
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
} RSAKeyPair;

int init_random(void) {
    if (RAND_status() != 1) {
        unsigned char seed[32];
        FILE *urandom = fopen("/dev/urandom", "rb");
        if (urandom) {
            if (fread(seed, 1, sizeof(seed), urandom) == sizeof(seed)) {
                RAND_seed(seed, sizeof(seed));
            }
            fclose(urandom);
        }
        if (RAND_status() != 1) {
            fprintf(stderr, "CSPRNG not properly seeded.\n");
            return 0;
        }
    }
    return 1;
}

int generate_keypair(RSAKeyPair *keypair, int bits) {
    return rsa_generate_keypair(&keypair->n, &keypair->e, &keypair->d, bits);
}

void free_keypair(RSAKeyPair *keypair) {
    if (keypair->n) BN_free(keypair->n);
    if (keypair->e) BN_free(keypair->e);
    if (keypair->d) BN_free(keypair->d);
    keypair->n = NULL;
    keypair->e = NULL;
    keypair->d = NULL;
}

void print_keypair(const RSAKeyPair *keypair) {
    printf("=== Public Key ===\n");
    printf("n (modulus)  = 0x");
    BN_print_fp(stdout, keypair->n);
    printf("\n");
    printf("e (exponent) = 0x");
    BN_print_fp(stdout, keypair->e);
    printf("\n\n");

    printf("=== Private Key ===\n");
    printf("d (exponent) = 0x");
    BN_print_fp(stdout, keypair->d);
    printf("\n\n");
}


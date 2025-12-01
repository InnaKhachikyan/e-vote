#ifndef TOKEN_GENERATION_H
#define TOKEN_GENERATION_H

#include <openssl/bn.h>

int run_token_generation(BIGNUM *g_public_n, BIGNUM *g_public_e);

#endif

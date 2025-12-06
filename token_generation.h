#ifndef TOKEN_GENERATION_H
#define TOKEN_GENERATION_H

#include <openssl/bn.h>

int run_token_generation(const BIGNUM *g_public_n, const BIGNUM *g_public_e, char **token_out);

#endif

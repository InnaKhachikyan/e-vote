#include "miller_rabin.h"

typedef __uint128_t u128;

static uint64_t modmul(uint64_t a, uint64_t b, uint64_t m) {
    return (uint64_t)((u128)a * b % m);
}

static uint64_t modpow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    while (exp > 0) {
        if (exp & 1)
            result = modmul(result, base, mod);
        base = modmul(base, base, mod);
        exp >>= 1;
    }
    return result;
}

int miller_rabin_u64(uint64_t n) {
    if (n < 2) return 0;

    static const uint64_t small_primes[] = {2,3,5,7,11,13,17,19,23,0};
    for (int i = 0; small_primes[i]; i++) {
        if (n == small_primes[i]) return 1;
        if (n % small_primes[i] == 0) return 0;
    }

    uint64_t d = n - 1;
    int s = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        s++;
    }

    static const uint64_t bases[] = {
        2ULL, 325ULL, 9375ULL, 28178ULL,
        450775ULL, 9780504ULL, 1795265022ULL
    };

    for (unsigned i = 0; i < sizeof(bases)/sizeof(bases[0]); i++) {
        uint64_t a = bases[i];
        if (a % n == 0) continue;

        uint64_t x = modpow(a, d, n);
        if (x == 1 || x == n - 1) continue;

        int is_composite = 1;
        for (int r = 1; r < s; r++) {
            x = modmul(x, x, n);
            if (x == n - 1) {
                is_composite = 0;
                break;
            }
        }
        if (is_composite)
            return 0;
    }

    return 1;
}


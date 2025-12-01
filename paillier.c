#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <openssl/rand.h>
#include "miller_rabin.h"
#include "paillier.h"

typedef __uint128_t u128;

u64 gcd_u64(u64 a, u64 b) {
	while(b != 0) {
		u64 t = a % b;
		a = b;
		b = t;
	}
	return a;
}

u64 lcm_u64(u64 a, u64 b) {
	return (a/gcd_u64(a, b)) * b;
}

// to avoid overflow, I calculate multiplication by mod with u128 type
u64 mod_mul(u64 a, u64 b, u64 mod) {
	return (u128)a * (u128)b % (u128)mod;
}

u64 exp_mod(u64 base, u64 exp, u64 mod) {
	u64 result = 1 % mod;
	u64 x = base % mod;
	while(exp > 0) {
		if(exp & 1) {
			result  =mod_mul(result, x, mod);
		}
		x = mod_mul(x, x, mod);
		exp >>= 1;
	}
	return result;
}

//here I am using long long instead of unsigned, as the coefficients might end up negative
long long bezout_identity(long long a, long long b, long long *x, long long *y) {
	if(b == 0) {
		*x = 1;
		*y = 0;
		return a;
	}
	long long x1, y1;
	long long g = bezout_identity(b, a % b, &x1, &y1);
	*x = y1;
	*y = x1 - (a/b) * y1;
	return g;
}

// assuming gcd(a,m) == 1
u64 mod_inv(u64 a, u64 m) {
	long long x, y;
	long long g = bezout_identity((long long)a, (long long)m, &x, &y);
	if(g != 1) {
		fprintf(stderr, "no inverse, gcd != 1\n");
		exit(1);
	}
	long long result = x % (long long)m;
	if(result < 0) {
		result += m;
	}
	return (u64)result;
}

void paillier_keygen(u64 p, u64 q, Paillier_pub_key *pubKey, Paillier_priv_key *privKey) {
	u64 n = p * q;
	u64 n_squared = n * n;
	u64 lambda = lcm_u64(p - 1, q - 1);
	u64 g = n + 1;
	u64 u = exp_mod(g, lambda, n_squared);

	if((u - 1) % n != 0) {
		fprintf(stderr, "L(u) is not an integer, something went wrong\n");
		exit(1);
	}

	u64 L = (u - 1)/n;
	u64 l_u = mod_inv(L, n);

	pubKey->n = n;
	pubKey->n_squared = n * n;
	pubKey->g = g;

	privKey->lambda = lambda;
	privKey->l_u = l_u;
}

// we assume r is in the range [1, n-1] and gcd(r,n)=1, encrypting m with r
u64 paillier_encrypt(u64 m, u64 r, const Paillier_pub_key *pubKey) {
	u64 n = pubKey->n;
	u64 n_squared = pubKey->n_squared;
	u64 g = pubKey->g;

	m %= n;

	u64 c1 = exp_mod(g, m, n_squared);
	u64 c2 = exp_mod(r, n, n_squared);
	u64 c = mod_mul(c1, c2, n_squared);

	return c;
}

u64 paillier_decrypt(u64 c, const Paillier_pub_key *pubKey, const Paillier_priv_key *privKey) {
	u64 n = pubKey->n;
	u64 n_squared = pubKey->n_squared;
	u64 lambda = privKey->lambda;
	u64 l_u = privKey->l_u;

	u64 u = exp_mod(c, lambda, n_squared);

	if((u - 1) %n != 0) {
		fprintf(stderr, "Decrypt: L(u) not integer, something went wrong\n");
		exit(1);
	}
	u64 L = (u - 1)/n;
	u64 m = mod_mul(L, l_u, n);
	return m;
}

u64 rand_u64() {
    unsigned char buf[8];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        exit(1);
    }
    u64 x = 0;
    for (int i = 0; i < 8; i++) {
        x = (x << 8) | buf[i];
    }
    return x;
}

u64 rand_range(u64 min, u64 max) {
    if (min > max) {
        u64 t = min; min = max; max = t;
    }
    u64 range = max - min + 1;
    u64 r = rand_u64() % range; 
    return min + r;
}

u64 random_prime_in_range(u64 min, u64 max) {
    for (;;) {
        u64 cand = rand_range(min, max);
        if ((cand & 1ULL) == 0) cand |= 1ULL; 
        if (cand < 3) continue;
        if (miller_rabin_u64(cand)) {
            return cand;
        }
    }
}

u64 random_coprime(u64 n) {
    for (;;) {
        u64 r = rand_range(1, n - 1);
        if (gcd_u64(r, n) == 1) return r;
    }
}

/*
int main(void) {
    if (RAND_status() != 1) {
        if (RAND_poll() != 1) {
            fprintf(stderr, "CSPRNG not properly seeded\n");
            return 1;
        }
    }

    // p, q should be < 2^16 so that n^2 fits in 64 bits
    u64 min_prime = (1ULL << 15);      // 32768
    u64 max_prime = (1ULL << 16) - 1;  // 65535

    u64 p = random_prime_in_range(min_prime, max_prime);
    u64 q;
    do {
        q = random_prime_in_range(min_prime, max_prime);
    } while (q == p);

    Paillier_pub_key pub;
    Paillier_priv_key priv;
    paillier_keygen(p, q, &pub, &priv);

    printf("=== Paillier key generated ===\n");
    printf("p       = %llu\n", (unsigned long long)p);
    printf("q       = %llu\n", (unsigned long long)q);
    printf("n       = %llu\n", (unsigned long long)pub.n);
    printf("n^2     = %llu\n", (unsigned long long)pub.n_squared);
    printf("g       = %llu\n\n", (unsigned long long)pub.g);

    unsigned long long num_voters;
    printf("Enter number of voters: ");
    if (scanf("%llu", &num_voters) != 1 || num_voters == 0) {
        fprintf(stderr, "Invalid number of voters\n");
        return 1;
    }

    u64 *ciphertexts = malloc(num_voters * sizeof(u64));
    if (!ciphertexts) {
        fprintf(stderr, "Memory allocation failed\n");
        return 1;
    }

    u64 C_tally = 1 % pub.n_squared;

    for (unsigned long long i = 0; i < num_voters; i++) {
        int vote;
        while (1) {
            printf("Voter %llu, enter your vote (0 = No, 1 = Yes): ",
                   (unsigned long long)(i + 1));
            if (scanf("%d", &vote) != 1) {
                fprintf(stderr, "Invalid input\n");
                free(ciphertexts);
                return 1;
            }
            if (vote == 0 || vote == 1) break;
            printf("Please enter only 0 or 1.\n");
        }

        u64 m = (u64)vote;
        u64 r = random_coprime(pub.n);
        u64 c = paillier_encrypt(m, r, &pub);
        ciphertexts[i] = c;

        C_tally = mod_mul(C_tally, c, pub.n_squared);
    }

    printf("\n=== Published encrypted votes (ciphertexts) ===\n");
    for (unsigned long long i = 0; i < num_voters; i++) {
        printf("Voter %llu: c = %llu\n",
               (unsigned long long)(i + 1),
               (unsigned long long)ciphertexts[i]);
    }

    u64 total_yes = paillier_decrypt(C_tally, &pub, &priv);
    unsigned long long total_no = 0;
    if (total_yes <= num_voters) {
        total_no = num_voters - total_yes;
    } else {
        fprintf(stderr, "Warning: total_yes > num_voters, something is wrong\n");
    }

    printf("\n=== Tally result ===\n");
    printf("Total YES votes: %llu\n", (unsigned long long)total_yes);
    printf("Total  NO  votes: %llu\n", total_no);

    free(ciphertexts);
    return 0;
}
*/

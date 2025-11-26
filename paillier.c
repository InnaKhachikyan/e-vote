#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include "miller_rabin.h"

typedef unsigned long long u64;
typedef __uint128_t u128;

typedef struct {
	u64 n;
	u64 n_squared;
	u64 g;
} Paillier_pub_key;

typedef struct {
	u64 lambda;
	u64 l_u;
} Paillier_priv_key;

u64 gcd_u64(u64 a, u64 b) {
	while(b != 0) {
		u64 t = a & b;
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

int main(void) {

}

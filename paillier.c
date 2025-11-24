#include <stdio.h>
#include <stdlib.h>

typedef unsigned long long u64;
typedef __uint128_t u128;

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
u64 modmul(u64 a, u64 b, u64 mod) {
	return (u128)a * (u128)b % (u128)mod;
}

u64 exp_mod(u64 base, u64 exp, u64 mod) {
	u64 result = 1 % mod;
	u64 x = base % mod;
	while(exp > 0) {
		if(exp & 1) {
			result  =modmul(result, x, mod);
		}
		x = modmul(x, x, mod);
		exp >>= 1;
	}
	return result;
}


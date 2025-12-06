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
#define VOTING_DURATION_SECONDS (2 * 60)

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

static void trim_newline(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[--len] = '\0';
    }
}

static int token_exists(const char *token_hex) {
    FILE *f = fopen("tokens.txt", "r");
    if (!f) return 0;

    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        trim_newline(line);
        if (line[0] == '\0') continue;
        if (strcmp(line, token_hex) == 0) {
            found = 1;
            break;
        }
    }

    fclose(f);
    return found;
}

static int remove_token(const char *token_hex) {
    FILE *fin = fopen("tokens.txt", "r");
    if (!fin) return 0;

    FILE *fout = fopen("tokens.tmp", "w");
    if (!fout) {
        fclose(fin);
        return 0;
    }

    char line[512];
    int removed = 0;

    while (fgets(line, sizeof(line), fin)) {
        trim_newline(line);
        if (line[0] == '\0') continue;
        if (!removed && strcmp(line, token_hex) == 0) {
            removed = 1;
            continue;
        }
        fprintf(fout, "%s\n", line);
    }

    fclose(fin);
    fclose(fout);

    if (!removed) {
        remove("tokens.tmp");
        return 0;
    }

    if (remove("tokens.txt") != 0) {
        return 0;
    }
    if (rename("tokens.tmp", "tokens.txt") != 0) {
        return 0;
    }

    return 1;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr,
                "Usage: %s <N_hex> <e_hex>\n"
                "  N_hex, e_hex: RSA public key of the system (no 0x prefix).\n",
                argv[0]);
        return 1;
    }

    BN_CTX *bn_ctx = BN_CTX_new();
    if (!bn_ctx) {
        fprintf(stderr, "BN_CTX_new failed\n");
        return 1;
    }

    BIGNUM *N = NULL;
    BIGNUM *e = NULL;

    if (!BN_hex2bn(&N, argv[1])) {
        fprintf(stderr, "Failed to parse N_hex.\n");
        BN_CTX_free(bn_ctx);
        return 1;
    }
    if (!BN_hex2bn(&e, argv[2])) {
        fprintf(stderr, "Failed to parse e_hex.\n");
        BN_free(N);
        BN_CTX_free(bn_ctx);
        return 1;
    }

    if (RAND_status() != 1) {
        if (RAND_poll() != 1) {
            fprintf(stderr, "CSPRNG not properly seeded\n");
            BN_free(N);
            BN_free(e);
            BN_CTX_free(bn_ctx);
            return 1;
        }
    }

    u64 min_prime = (1ULL << 15);
    u64 max_prime = (1ULL << 16) - 1;

    u64 p = random_prime_in_range(min_prime, max_prime);
    u64 q;
    do {
        q = random_prime_in_range(min_prime, max_prime);
    } while (q == p);

    Paillier_pub_key pub;
    Paillier_priv_key priv;
    paillier_keygen(p, q, &pub, &priv);

    printf("=== Paillier key generated for this election ===\n");
    printf("n       = %llu\n", (unsigned long long)pub.n);
    printf("n^2     = %llu\n", (unsigned long long)pub.n_squared);
    printf("g       = %llu\n\n", (unsigned long long)pub.g);

    int c;
    while ((c = getchar()) != '\n' && c != EOF) { }

    u64 *ciphertexts = malloc(MAX_VOTERS * sizeof(u64));
    if (!ciphertexts) {
        fprintf(stderr, "Memory allocation failed\n");
        BN_free(N);
        BN_free(e);
        BN_CTX_free(bn_ctx);
        return 1;
    }

    u64 C_tally = 1 % pub.n_squared;
    unsigned long long valid_votes = 0;

    time_t start_time = time(NULL);
    if (start_time == (time_t)-1) {
        fprintf(stderr, "time() failed\n");
        free(ciphertexts);
        BN_free(N);
        BN_free(e);
        BN_CTX_free(bn_ctx);
        return 1;
    }

    while (valid_votes < MAX_VOTERS) {
        time_t now = time(NULL);
        if (now == (time_t)-1) {
            fprintf(stderr, "time() failed\n");
            break;
        }
        double elapsed = difftime(now, start_time);
        if (elapsed >= VOTING_DURATION_SECONDS) {
            printf("\nVoting time limit (10 minutes) reached. Stopping.\n");
            break;
        }

        printf("\n=== Voter %llu ===\n", (unsigned long long)(valid_votes + 1));

        char buf[4096];
        char token_hex[2 * SHA256_DIGEST_LENGTH + 1];

        unsigned char nonce[NONCE_BYTES];
        unsigned char token_hash[SHA256_DIGEST_LENGTH];

        printf("Enter nonce (hex, %d bytes -> %d hex chars):\n> ",
               NONCE_BYTES, NONCE_BYTES * 2);
        if (!fgets(buf, sizeof(buf), stdin)) {
            fprintf(stderr, "Input error\n");
            break;
        }
        if (!parse_fixed_hex(buf, nonce, NONCE_BYTES)) {
            fprintf(stderr, "Invalid nonce hex length/format\n");
            continue;
        }

        printf("Enter token hash (hex, %d bytes -> %d hex chars):\n> ",
               SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH * 2);
        if (!fgets(buf, sizeof(buf), stdin)) {
            fprintf(stderr, "Input error\n");
            break;
        }
        if (!parse_fixed_hex(buf, token_hash, SHA256_DIGEST_LENGTH)) {
            fprintf(stderr, "Invalid token hash hex length/format\n");
            continue;
        }

        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(&token_hex[2 * i], "%02x", token_hash[i]);
        }
        token_hex[2 * SHA256_DIGEST_LENGTH] = '\0';

        if (!token_exists(token_hex)) {
            fprintf(stderr, "Token not registered or already used, vote rejected\n");
            continue;
        }

        printf("Enter signature s (hex, without 0x):\n> ");
        if (!fgets(buf, sizeof(buf), stdin)) {
            fprintf(stderr, "Input error\n");
            break;
        }
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
            buf[--len] = '\0';
        }
        if (len == 0) {
            fprintf(stderr, "Empty signature\n");
            continue;
        }

        BIGNUM *s = NULL;
        if (!BN_hex2bn(&s, buf)) {
            fprintf(stderr, "Failed to parse signature hex\n");
            continue;
        }

        BIGNUM *m = token_hash_to_bn(token_hash, N, bn_ctx);
        if (!m) {
            fprintf(stderr, "token_hash_to_bn failed\n");
            BN_free(s);
            continue;
        }

        if (!verify_signature(m, s, N, e, bn_ctx)) {
            fprintf(stderr, "Invalid token/signature, vote rejected\n");
            BN_free(m);
            BN_free(s);
            continue;
        }

        BN_free(m);
        BN_free(s);

        int vote;
        while (1) {
            printf("Enter your vote (0 = No, 1 = Yes): ");
            if (scanf("%d", &vote) != 1) {
                fprintf(stderr, "Invalid input\n");
                int ch;
                while ((ch = getchar()) != '\n' && ch != EOF) { }
                continue;
            }
            if (vote == 0 || vote == 1) break;
            printf("Please enter only 0 or 1.\n");
        }

        while ((c = getchar()) != '\n' && c != EOF) { }

        u64 m_vote = (u64)vote;
        u64 r = random_coprime(pub.n);
        u64 ciph = paillier_encrypt(m_vote, r, &pub);
        ciphertexts[valid_votes] = ciph;

        C_tally = mod_mul(C_tally, ciph, pub.n_squared);
        valid_votes++;

        if (!remove_token(token_hex)) {
            fprintf(stderr, "Warning: failed to erase token from tokens.txt\n");
        }
    }

    printf("\n=== Published encrypted votes (ciphertexts) ===\n");
    for (unsigned long long i = 0; i < valid_votes; i++) {
        printf("Voter %llu: c = %llu\n",
               (unsigned long long)(i + 1),
               (unsigned long long)ciphertexts[i]);
    }

    u64 total_yes = paillier_decrypt(C_tally, &pub, &priv);
    unsigned long long total_no = 0;
    if (total_yes <= valid_votes) {
        total_no = valid_votes - total_yes;
    } else {
        fprintf(stderr, "Warning: total_yes > valid_votes, something is wrong\n");
    }

    printf("\n=== Tally result ===\n");
    printf("Total YES votes: %llu\n", (unsigned long long)total_yes);
    printf("Total  NO  votes: %llu\n", total_no);

    free(ciphertexts);
    BN_free(N);
    BN_free(e);
    BN_CTX_free(bn_ctx);

    return 0;
}


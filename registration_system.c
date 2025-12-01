#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include "rsa.h"
#include "token_generation.h"

#define VOTING_DURATION_SECONDS (15 * 60)
#define NUM_STUDENTS 38

BIGNUM *g_public_n = NULL;
BIGNUM *g_public_e = NULL;
static BIGNUM *s_private_d = NULL;

static const char *STUDENT_IDS[] = {
    "arthur_aghamyan",
    "nane_andreasyan",
    "eduard_aramyan",
    "artashes_atanesyan",
    "alik_avakyan",
    "lilit_babakhanyan",
    "erik_badalyan",
    "anahit_baghramyan",
    "hrach_davtyan",
    "mikayel_davtyan",
    "narek_galstyan",
    "sofiya_gasparyan",
    "meri_gasparyan",
    "milena_ghazaryan",
    "levon_ghukasyan",
    "yeghiazar_grigoryan",
    "karine_grigoryan",
    "anna_hakhnazaryan",
    "davit_hakobyan",
    "vahe_hayrapetyan",
    "ruzanna_hunanyan",
    "vahe_jraghatspanyan",
    "inna_khachikyan",
    "siranush_makhmuryan",
    "anush_margaryan",
    "yevgine_mnatsakanyan",
    "narek_otaryan",
    "vahe_sahakyan",
    "davit_sahakyan",
    "vahe_sargsyan",
    "ruben_sargsyan",
    "ararat_saribekyan",
    "diana_stepanyan",
    "mikayel_yeganyan",
    "anahit_yeghiazaryan",
    "sedrak_yerznkyan",
    "khachik_zakaryan"
};

bool token_generated[NUM_STUDENTS] = {false};

static int find_student_index(const char *id) {
    for (int i = 0; i < NUM_STUDENTS; i++) {
        if (strcmp(STUDENT_IDS[i], id) == 0) {
            return i;
        }
    }
    return -1;
}

static bool all_students_done(void) {
    for (int i = 0; i < NUM_STUDENTS; i++) {
        if (!token_generated[i]) {
            return false;
        }
    }
    return true;
}

static void free_keys(void) {
    if (g_public_n) {
        BN_free(g_public_n);
        g_public_n = NULL;
    }
    if (g_public_e) {
        BN_free(g_public_e);
        g_public_e = NULL;
    }
    if (s_private_d) {
        BN_free(s_private_d);
        s_private_d = NULL;
    }
}


int system_blind_sign(const BIGNUM *m_blinded, BIGNUM **s_blinded_out) {
    if (!m_blinded || !s_private_d || !g_public_n || !s_blinded_out) {
        return 0;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        return 0;
    }

    BIGNUM *s = BN_new();
    if (!s) {
        BN_CTX_free(ctx);
        return 0;
    }

    if (!rsa_decrypt(m_blinded, g_public_n, s_private_d, s, ctx)) {
        BN_free(s);
        BN_CTX_free(ctx);
        return 0;
    }

    *s_blinded_out = s;
    BN_CTX_free(ctx);
    return 1;
}

int main(void) {
	if (!rsa_generate_keypair(&g_public_n, &g_public_e, &s_private_d, 2048)) {
        fprintf(stderr, "Key generation failed.\n");
        free_keys();
        return EXIT_FAILURE;
    }

	printf("\n=== Public Key for Voting System ===\n");
printf("N (hex): ");
BN_print_fp(stdout, g_public_n);
printf("\n");
printf("e (hex): ");
BN_print_fp(stdout, g_public_e);
printf("\n\n");

    printf("Registration system initialized.\n");
    printf("RSA public key generated (n, e).\n");
    printf("Private key kept locally (static).\n");
    printf("Voting will stop when either:\n");
    printf("  - all %d students have generated a token, or\n", NUM_STUDENTS);
    printf("  - %d minutes have passed since start.\n\n", VOTING_DURATION_SECONDS / 60);

    time_t start_time = time(NULL);
    if (start_time == (time_t)-1) {
        fprintf(stderr, "time() failed.\n");
        free_keys();
        return EXIT_FAILURE;
    }

    char input_buf[128];

    while (1) {
        time_t now = time(NULL);
        if (now == (time_t)-1) {
            fprintf(stderr, "time() failed.\n");
            break;
        }

        double elapsed = difftime(now, start_time);
        if (elapsed >= VOTING_DURATION_SECONDS) {
            printf("\nTime limit (15 minutes) reached. Voting is now closed.\n");
            break;
        }

        if (all_students_done()) {
            printf("\nAll students in the list have generated their tokens. Voting is now closed.\n");
            break;
        }

        printf("Enter student ID: ");
        fflush(stdout);

        if (!fgets(input_buf, sizeof(input_buf), stdin)) {
            printf("\nEnd of input detected. Terminating.\n");
            break;
        }

        size_t len = strlen(input_buf);
        if (len > 0 && (input_buf[len - 1] == '\n' || input_buf[len - 1] == '\r')) {
            input_buf[len - 1] = '\0';
            len--;
        }

        if (len == 0) {
            continue;
        }

        int idx = find_student_index(input_buf);
        if (idx < 0) {
            printf("Unknown student ID: %s\n\n", input_buf);
            continue;
        }

        if (token_generated[idx]) {
            printf("Token for student ID %s has already been generated earlier.\n\n", input_buf);
            continue;
        }

        printf("Starting token generation for student ID %s...\n", input_buf);

        int rc = run_token_generation(g_public_n, g_public_e);
        if (rc != 0) {
            fprintf(stderr, "Token generation failed for student ID %s (rc = %d).\n\n", input_buf, rc);
            continue;
        }

        token_generated[idx] = true;
        printf("Token for student ID %s has been successfully generated.\n\n", input_buf);
    }

    free_keys();
    return EXIT_SUCCESS;
}


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <openssl/bn.h>
#include <curl/curl.h>
#include "rsa.h"
#include "token_generation.h"
#include "authentication.h"

#define VOTING_DURATION_SECONDS (15 * 60)
#define NUM_STUDENTS 37

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
    "khachik_zakaryan",
    "sergey_abrahamyan"
};

static const char *STUDENT_MAILS[] = {
    "arthur_aghamyan@edu.aua.am",
    "nane_andreasyan@edu.aua.am",
    "eduard_aramyan@edu.aua.am",
    "artashes_atanesyan@edu.aua.am",
    "alik_avakyan@edu.aua.am",
    "lilit_babakhanyan@edu.aua.am",
    "erik_badalyan@edu.aua.am",
    "anahit_baghramyan@edu.aua.am",
    "hrach_davtyan@edu.aua.am",
    "mikayel_davtyan@edu.aua.am",
    "narek_galstyan@edu.aua.am",
    "sofiya_gasparyan@edu.aua.am",
    "meri_gasparyan@edu.aua.am",
    "milena_ghazaryan@edu.aua.am",
    "levon_ghukasyan@edu.aua.am",
    "karine_grigoryan@edu.aua.am",
    "anna_hakhnazaryan@edu.aua.am",
    "davit_hakobyan@edu.aua.am",
    "vahe_hayrapetyan@edu.aua.am",
    "ruzanna_hunanyan@edu.aua.am",
    "vahe_jraghatspanyan@edu.aua.am",
    "inna_khachikyan@edu.aua.am",
    "siranush_makhmuryan@edu.aua.am",
    "anush_margaryan@edu.aua.am",
    "yevgine_mnatsakanyan@edu.aua.am",
    "narek_otaryan@edu.aua.am",
    "vahe_sahakyan@edu.aua.am",
    "davit_sahakyan@edu.aua.am",
    "vahe_sargsyan@edu.aua.am",
    "ruben_sargsyan@edu.aua.am",
    "ararat_saribekyan@edu.aua.am",
    "diana_stepanyan@edu.aua.am",
    "mikayel_yeganyan@edu.aua.am",
    "anahit_yeghiazaryan@edu.aua.am",
    "sedrak_yerznkyan@edu.aua.am",
    "khachik_zakaryan@edu.aua.am",
    "sabrahamyan@aua.am"
};

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
    srand((unsigned int)time(NULL));

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

    for (int i = 0; i < NUM_STUDENTS; i++) {
        if (auth_add_student(STUDENT_IDS[i], STUDENT_MAILS[i]) != 0) {
            fprintf(stderr, "Failed to add student %s\n", STUDENT_IDS[i]);
            free_keys();
            return EXIT_FAILURE;
        }
    }

    auth_sort_students();

    printf("Registration system initialized.\n");
    printf("RSA public key generated (n, e).\n");
    printf("Private key kept locally (static).\n");
    printf("Registration will stop when either:\n");
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
            printf("\nTime limit (15 minutes) reached. Registration is now closed.\n");
            break;
        }

        if (auth_all_tokens_generated()) {
            printf("\nAll students in the list have generated their tokens. Registration is now closed.\n");
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

        int auth_result = auth_email_verify(input_buf);

        if (auth_result == 2) {
            continue;
        }

        if (auth_result == 1) {
            printf("Worng verification code\n\n");
            continue;
        }

        printf("Verification successful. Starting token generation for student ID %s...\n", input_buf);

        int rc = run_token_generation(g_public_n, g_public_e);
        if (rc != 0) {
            fprintf(stderr, "Token generation failed for student ID %s (rc = %d).\n\n", input_buf, rc);
            continue;
        }

        Student *s = auth_find_student(input_buf);
        if (!s) {
            fprintf(stderr, "Internal error: student not found after verification.\n\n");
            continue;
        }

        s->token_generated = true;
        printf("Token for student ID %s has been successfully generated.\n\n", input_buf);
    }

    free_keys();
    return EXIT_SUCCESS;
}


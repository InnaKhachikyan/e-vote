#include <stdio.h>
#include <stdlib.h>
#include "rsa.h"

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

static const int NUM_STUDENTS = sizeof(STUDENT_IDS) / sizeof(STUDENT_IDS[0]);

bool token_generated[NUM_STUDENTS] = {false};



#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <curl/curl.h>
#include "authentication.h"

#define AUTH_TOKEN "gmailer_14134ff48f211bc6295a6cd6054351223907b405a247fb7faeb53a09bc999043"

static Student student_list[NUM_STUDENTS_MAX];
static int student_count = 0;

static void generate_verification_code(char code_buf[8]) {
    int code = rand() % 900000 + 100000;  // 100000–999999
    snprintf(code_buf, 8, "%06d", code); 
}

int send_email_via_marleyfetch(const char *auth_token, const char *to, const char *subject, const char *text_body) {
    CURL *curl = NULL;
    CURLcode res;
    int status = -1;

    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize CURL\n");
        return -1;
    }

    char json_data[2048];
    snprintf(json_data, sizeof(json_data),
             "{"
             "\"to\":\"%s\","
             "\"subject\":\"%s\","
             "\"text_body\":\"%s\""
             "}",
             to, subject, text_body);

    printf("\n--- Sending Email Request JSON ---\n%s\n---------------------------------\n", json_data);
    curl_easy_setopt(curl, CURLOPT_URL, "https://marleyfetch.com/api/send");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    char auth_header[1024];
    snprintf(auth_header, sizeof(auth_header),
             "Authorization: Bearer %s", auth_token);

    headers = curl_slist_append(headers, auth_header);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);

    res = curl_easy_perform(curl);
    if (res == CURLE_OK) {
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        printf("HTTP Response Code: %ld\n", response_code);

        if (response_code == 200 || response_code == 202) {
            status = 0;
        }
    } else {
        fprintf(stderr, "curl_easy_perform() failed: %s\n",
                curl_easy_strerror(res));
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return status;
}

// returns 0 on success, 1 on verification fail (no id, no mail, wrong mail, wrong code entered), 2 if token has already been generated
int auth_email_verify(const char *student_id) {
    if (!student_id) {
        return 1; 
    }

    Student *s = auth_find_student(student_id);
    if (!s) {
        printf("Unknown student ID: %s\n\n", student_id);
        return 1;
    }

    if (s->token_generated) {
        printf("Token for student ID %s has already been generated earlier.\n\n",
               student_id);
        return 2;
    }

    if (!s->email || s->email[0] == '\0') {
        printf("Internal error: no email stored for student ID %s\n\n", student_id);
        return 1; 
    }

    char verification_code[8];
    generate_verification_code(verification_code);

    const char *subject = "Verification Code";
    char body[256];
    snprintf(body, sizeof(body),
             "Your verification code is: %s",
             verification_code);

    printf("Sending verification code to %s...\n", s->email);

    int email_status = send_email_via_marleyfetch(
        AUTH_TOKEN,
        s->email,
        subject,
        body
    );

    if (email_status != 0) {
        printf("Failed to send verification email. Please contact the administrator.\n\n");
        return 1;
    }

    printf("Verification code sent. Please check your AUA email.\n");

    char code_input[64];
    printf("Enter the 6-digit verification code: ");
    fflush(stdout);

    if (!fgets(code_input, sizeof(code_input), stdin)) {
        printf("\nInput error. Aborting this registration attempt.\n\n");
        return 1;
    }
    size_t len = strlen(code_input);
    if (len > 0 && (code_input[len - 1] == '\n' || code_input[len - 1] == '\r')) {
        code_input[len - 1] = '\0';
    }

    if (strcmp(code_input, verification_code) != 0) {
        return 1; 
    }
    return 0;
}

int auth_add_student(const char *this_id, const char *this_email) {
    if (student_count >= NUM_STUDENTS_MAX) {
        fprintf(stderr, "Error: Student list is full\n");
        return 1;
    }

    if (this_id == NULL) {
        fprintf(stderr, "Error: ID cannot be NULL\n");
        return 1;
    }

    if (this_email == NULL) {
        student_list[student_count].email = NULL;
    } else {
        student_list[student_count].email = (char *)this_email;
    }

    strncpy(student_list[student_count].id, this_id, ID_SIZE - 1);
    student_list[student_count].id[ID_SIZE - 1] = '\0';
    student_list[student_count].token_generated = false;

    student_count++;
    return 0;
}

int auth_get_student_count(void) {
    return student_count;
}

static void swap_students(Student *a, Student *b) {
    Student temp = *a;
    *a = *b;
    *b = temp;
}

static int partition(Student arr[], int low, int high) {
    const char *pivot = arr[high].id;
    int i = low - 1;

    for (int j = low; j < high; j++) {
        if (strcmp(arr[j].id, pivot) <= 0) {
            i++;
            swap_students(&arr[i], &arr[j]);
        }
    }
    swap_students(&arr[i + 1], &arr[high]);
    return i + 1;
}

static void quicksort_students(Student arr[], int low, int high) {
    if (low < high) {
        int pi = partition(arr, low, high);
        quicksort_students(arr, low, pi - 1);
        quicksort_students(arr, pi + 1, high);
    }
}

void auth_sort_students(void) {
    if (student_count > 1) {
        quicksort_students(student_list, 0, student_count - 1);
    }
}

Student *auth_find_student(const char *id) {
    if (!id) return NULL;
    size_t left = 0;
    size_t right = (size_t)student_count;

    while (left < right) {
        size_t mid = left + (right - left) / 2;
        int cmp = strcmp(id, student_list[mid].id);

        if (cmp == 0) {
            return &student_list[mid];
        } else if (cmp < 0) {
            right = mid;
        } else {
            left = mid + 1;
        }
    }

    return NULL;
}

bool auth_all_tokens_generated(void) {
    if (student_count == 0) return false;
    for (int i = 0; i < student_count; i++) {
        if (!student_list[i].token_generated) {
            return false;
        }
    }
    return true;
}


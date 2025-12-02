#ifndef AUTHENTICATION_H
#define AUTHENTICATION_H

#include <stdbool.h>
#include <curl/curl.h>

#define NUM_STUDENTS_MAX 1000
#define ID_SIZE 64

typedef struct {
    char id[ID_SIZE];
    char *email;
    bool token_generated;
} Student;

int auth_add_student(const char *this_id, const char *this_email);
int auth_get_student_count(void);
void auth_sort_students(void);
Student *auth_find_student(const char *id);
bool auth_all_tokens_generated(void);
int auth_email_verify(const char *student_id);

#endif


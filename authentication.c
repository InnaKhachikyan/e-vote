#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define NUM_STUDENTS 1000
#define ID_SIZE 9

typedef struct {
	char id[ID_SIZE];
	char *email;
	bool token_generated;
} Student;

static Student student_list[NUM_STUDENTS];

static int student_count = 0;

static int add_student(char this_id[9], char *this_email) {
	if (student_count >= NUM_STUDENTS) {
		fprintf(stderr, "Error: Student list is full\n");
		return 1;
	}

	if (this_email == NULL) {
		fprintf(stderr, "Error: Email cannot be NULL\n");
		return 1;
	}
	
	strncpy(student_list[student_count].id, this_id, ID_SIZE - 1);
	student_list[student_count].id[ID_SIZE - 1] = '\0';
	student_list[student_count].email = this_email;
	student_list[student_count].token_generated = false;

	student_count++;

	return 0;
}

int get_student_count() {
	return student_count;
}

// I use quicksort to sort all the ready-list students by their id-s, to find later easier

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

static void sort_list() {
	quicksort_students(student_list, 0, student_count-1);
	return;
}

// I use binary search to find the student by id in the array

Student *find_student_by_id(Student arr[], size_t size, const char *id) {
    size_t left = 0;
    size_t right = size; 

    while (left < right) {
        size_t mid = left + (right - left) / 2;
        int cmp = strcmp(id, arr[mid].id);

        if (cmp == 0) {
            return &arr[mid];   
        } else if (cmp < 0) {
            right = mid;       
        } else {
            left = mid + 1;    
        }
    }

    return NULL;  
}

int main(void) {

	add_student("00C00000", "s3@example.com");
	add_student("00A00000", "s1@example.com");
	add_student("00J00000", "s10@example.com");
	add_student("00B00000", "s2@example.com");
	add_student("00G00000", "s7@example.com");
	add_student("00I00000", "s9@example.com");
	add_student("00D00000", "s4@example.com");
	add_student("00F00000", "s6@example.com");
	add_student("00H00000", "s8@example.com");
	add_student("00E00000", "s5@example.com");

	printf("Before sorting:\n");
	for (int i = 0; i < student_count; i++) {
		printf("%s -> %s\n", student_list[i].id, student_list[i].email);
	}

	sort_list();

	printf("\nAfter sorting:\n");
	for (int i = 0; i < student_count; i++) {
		printf("%s -> %s\n", student_list[i].id, student_list[i].email);
	}

	return 0;
}

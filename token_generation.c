#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <termios.h>
#include <fcntl.h>
#include <time.h>
#include <sys/select.h>
#include <sys/time.h>

#define NONCE_BYTES 16
#define ELECTION_ID "AUA_policy_change_vote_2025"

static int collect_mouse_entropy(double duration_seconds) {
	unsigned char entropy_buffer[256];
	size_t entropy_collected = 0;
	int mouse_fd = -1;

	const char *mouse_devices[] = {
		"/dev/input/mice",
		"/dev/input/mouse0",
		"/dev/psaux",
		NULL
	};

	for (int i = 0; mouse_devices[i] != NULL; i++) {
		mouse_fd = open(mouse_devices[i], O_RDONLY | O_NONBLOCK);
		if (mouse_fd >= 0) {
			printf("Reading from %s\n", mouse_devices[i]);
			break;
		}
	}

	if (mouse_fd < 0) {
		printf("Cannot access mouse devices (try: sudo chmod +r /dev/input/mice)\n");
		printf("Falling back to timing-based entropy collection...\n");
	}

	struct timespec start, now;
	clock_gettime(CLOCK_MONOTONIC, &start);

	printf("Collecting entropy");
	fflush(stdout);

	int dot_counter = 0;
	while (1) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		double elapsed = (now.tv_sec - start.tv_sec) +
		                 (now.tv_nsec - start.tv_nsec) / 1e9;

		if (elapsed >= duration_seconds) break;

		if (++dot_counter % 10 == 0) {
			printf(".");
			fflush(stdout);
		}

		if (mouse_fd >= 0) {
			unsigned char mouse_data[32];
			ssize_t n = read(mouse_fd, mouse_data, sizeof(mouse_data));
			if (n > 0) {
				for (ssize_t i = 0; i < n && entropy_collected < sizeof(entropy_buffer); i++) {
					entropy_buffer[entropy_collected++] = mouse_data[i];
				}
			}
		}

		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		if (entropy_collected < sizeof(entropy_buffer)) {
			entropy_buffer[entropy_collected++] = (unsigned char)(ts.tv_nsec & 0xFF);
		}

		usleep(10000); // delay
	}

	printf(" done!\n");

	if (mouse_fd >= 0) {
		close(mouse_fd);
	}

	if (entropy_collected > 0) {
		unsigned char hash[SHA256_DIGEST_LENGTH];
		SHA256(entropy_buffer, entropy_collected, hash);
		RAND_add(hash, sizeof(hash), (double)entropy_collected / 4.0);

		printf("Collected %zu bytes of entropy from mouse/timing\n", entropy_collected);

		memset(entropy_buffer, 0, sizeof(entropy_buffer));
		memset(hash, 0, sizeof(hash));
		return 1;
	}

	return 0;
}

static int seed_from_dev_random(size_t bytes) {
	unsigned char buf[64];
	if(bytes > sizeof(buf)) {
		bytes = sizeof(buf);
	}

	FILE *f = fopen("/dev/random", "rb");
	if(!f) {
		perror("fopen /dev/random");
		return 0;
	}

	size_t r = fread(buf, 1, bytes, f);
	fclose(f);

	if(r != bytes) {
		fprintf(stderr, "Not enough entropy from /dev/random\n");
		return 0;
	}

	RAND_add(buf, (int)bytes, (double)bytes);

	for(size_t i = 0; i < bytes; i++) {
		buf[i] = 0;
	}
	return 1;
}

static int init_random(void) {
	if(RAND_poll() != 1) {
		fprintf(stderr, "RAND_poll failed\n");
		return 0;
	}

	printf("\nCollecting User Entropy\n");
	printf("Please move your mouse randomly!\n");
	printf("Collecting for 5 seconds...\n\n");

	if(!collect_mouse_entropy(5.0)) {
		fprintf(stderr, "Warning: mouse entropy collection had issues.\n");
	}

	printf("\nStrengthening with /dev/random...\n");
	if(!seed_from_dev_random(32)) {
		fprintf(stderr, "Warning: could not strengthen RNG from /dev/random.\n");
	}

	if(RAND_status() != 1) {
		fprintf(stderr, "CSPRNG not properly seeded\n");
		return 0;
	}

	printf("\n✓ RNG successfully seeded with user entropy!\n\n");
	return 1;
}

static int generate_token(unsigned char nonce[NONCE_BYTES], unsigned char token_hash[SHA256_DIGEST_LENGTH]) {
	if(RAND_bytes(nonce, NONCE_BYTES) != 1) {
		return 0;
	}

	const char *eid = ELECTION_ID;
	size_t eid_len = strlen(eid);

	unsigned char buf[256];
	if(eid_len + NONCE_BYTES > sizeof(buf)) {
		fprintf(stderr, "Internal buffer too small\n");
		return 0;
	}

	memcpy(buf, eid, eid_len);
	memcpy(buf + eid_len, nonce, NONCE_BYTES);

	SHA256(buf, eid_len + NONCE_BYTES, token_hash);

	memset(buf, 0, sizeof(buf));
	return 1;
}

int main(void) {
    printf("=== Token Generation with RNG Test ===\n\n");

    if (!init_random()) {
        fprintf(stderr, "Failed to initialize RNG\n");
        return 1;
    }

    unsigned char nonce[NONCE_BYTES];
    unsigned char token_hash[SHA256_DIGEST_LENGTH];

    if (!generate_token(nonce, token_hash)) {
        fprintf(stderr, "Failed to generate token\n");
        return 1;
    }

    printf("Election ID: %s\n", ELECTION_ID);

    printf("Random nonce (%d bytes): ", NONCE_BYTES);
    for (int i = 0; i < NONCE_BYTES; i++) {
        printf("%02x", nonce[i]);
    }
    printf("\n");

    printf("Token = SHA256(ELECTION_ID || nonce): ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", token_hash[i]);
    }
    printf("\n");

    return 0;
}

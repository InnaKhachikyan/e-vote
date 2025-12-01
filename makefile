

all:
	gcc -Wall -O2 registration_system.c token_generation.c rsa.c rsa_core.c -lcrypto -o system
	gcc -Wall -O2 voting_system.c paillier.c miller_rabin_test.c rsa.c rsa_core.c -lcrypto -o voting_system



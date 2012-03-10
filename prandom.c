// ***********************************************************************
// prandom.c
// ***********************************************************************
//
// Containes functions which generate pseudo-random values. At the moment
// this covers whitening of random inputs and deterministic private key
// generation.
//
// This file is licensed as described by the file LICENCE.

// Defining this will facilitate testing
//#define TEST
// Defining this will provide useless stubs for interface functions, to stop
// linker errors from occuring
//#define INTERFACE_STUBS

#include "common.h"
#include "sha256.h"
#include "aes.h"
#include "bignum256.h"
#include "prandom.h"
#include "hwinterface.h"

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#endif // #ifdef TEST

// XOR 16 bytes specified by r with the 16 bytes specified by op1.
void xor16bytes(u8 *r, u8 *op1)
{
	u8 i;

	for (i = 0; i < 16; i++)
	{
		r[i] ^= op1[i];
	}
}

#define ENTROPY_SAFETY_FACTOR	2

// Uses a block cipher to mix data from the hardware random number generator.
// A block cipher is an appropriate choice for a mixing function, because
// an ideal block cipher should not reveal any information about the plaintext
// or key. Therefore, correlations or biases in the hardware random number
// generator will become hidden.
// Entropy is accumulated by running the cipher in CBC mode (albeit with a
// changing key) until the total entropy as reported by the hardware number
// generator is at least 256 * ENTROPY_SAFETY_FACTOR bits.
void get_random_256(bignum256 n)
{
	u16 totalentropy;
	u8 key[32];
	u8 randbytes[32];
	u8 expkey[EXPKEY_SIZE];
	u8 i;

	totalentropy = 0;
	for (i = 0; i < 32; i++)
	{
		n[i] = 0;
	}
	while (totalentropy < (256 * ENTROPY_SAFETY_FACTOR))
	{
		totalentropy = (u16)(totalentropy + hardware_random_bytes(key, 32));
		totalentropy = (u16)(totalentropy + hardware_random_bytes(randbytes, 32));
		// Mix plaintext with output of previous round.
		xor16bytes(n, randbytes);
		aes_expand_key(expkey, &(key[0]));
		aes_encrypt(&(n[16]), &(n[0]), expkey);
		xor16bytes(&(n[16]), &(randbytes[16]));
		aes_expand_key(expkey, &(key[16]));
		aes_encrypt(&(n[0]), &(n[16]), expkey);
	}
}

// Use a combination of cryptographic primitives to deterministically
// generate a new 256-bit number. seed should point to a 64-byte array,
// num is a counter and the resulting 256-bit number will be written to out.
// The process is: the last 256 bits of the seed are appended with the
// counter and hashed using SHA-256. The first and second 128 bits of the
// seed are used as a key to encrypt the two halves of the resulting hash
// using AES. The result is the two encrypted halves.
// If having a 512-bit seed is deemed "too big" for an application:
// - The first and second 128 bits can be the same, meaning that the
//   encryption key for the two halves is the same.
// - The last 256-bits of the seed can have up to 128 bits set to 0.
// Implementing both of these options would reduce the entropy in the seed
// to 256 bits, which should still be enough. But if possible, it is better
// to be safe than sorry and use a seed with the full 512 bits of entropy.
// Why use a hash in addition to a block cipher? Defense in depth - the
// plaintext to AES is then unknown to an attacker.
// Note: out is little-endian, so the first encrypted half of the hash
// goes into the least-significant 256 bits while the second encrypted
// half goes into the most-significant 256 bits.
void generate_deterministic_256(bignum256 out, u8 *seed, u32 num)
{
	u8 i;
	hash_state hs;
	u8 expkey[EXPKEY_SIZE];
	u8 hash[32];

	sha256_begin(&hs);
	for (i = 32; i < 64; i++)
	{
		sha256_writebyte(&hs, seed[i]);
	}
	for (i = 0; i < 4; i++)
	{
		sha256_writebyte(&hs, 0);
	}
	sha256_writebyte(&hs, (u8)(num >> 24));
	sha256_writebyte(&hs, (u8)(num >> 16));
	sha256_writebyte(&hs, (u8)(num >> 8));
	sha256_writebyte(&hs, (u8)num);
	sha256_finish(&hs);
	convertHtobytearray(hash, &hs, 1);
	aes_expand_key(expkey, &(seed[0]));
	aes_encrypt(&(out[0]), &(hash[0]), expkey);
	aes_expand_key(expkey, &(seed[16]));
	aes_encrypt(&(out[16]), &(hash[16]), expkey);
}

#ifdef INTERFACE_STUBS

extern int rand(void);

u16 hardware_random_bytes(u8 *buffer, u8 n)
{
	int i;
	for (i = 0; i < n; i++)
	{
		buffer[0] = (u8)(rand() & 0xff);
	}
	return (u16)(n << 3);
}

#endif // #ifdef INTERFACE_STUBS

#ifdef TEST

// The purpose of this "random" byte source is to test the entropy
// accumulation behaviour of get_random_256().
u16 hardware_random_bytes(u8 *buffer, u8 n)
{
	int i;

	for (i = 0 ;i < n; i++)
	{
		buffer[i] = 0;
	}
	buffer[0] = (u8)(rand() & 0xff);
	return 8;
}

// A proper test suite for randomness would be quite big, so this test
// spits out samples into random.dat, where they can be analysed using
// an external program.
int main(int argc, char **argv)
{
	u8 r[32];
	int i, j;
	int nsamples;
	FILE *f;
	u8 seed[64];
	u8 keys[64][32];
	u8 key2[32];

	// Before outputting samples, do a sanity check that
	// generate_deterministic_256() actually has different outputs when
	// each byte of the seed is changed.
	for (i = 0; i < 64; i++)
	{
		for (j = 0; j < 64; j++)
		{
			seed[j] = 0;
		}
		seed[i] = 1;
		generate_deterministic_256(keys[i], seed, 0);
		for (j = 0; j < i; j++)
		{
			if (bigcmp(keys[i], keys[j]) == BIGCMP_EQUAL)
			{
				printf("generate_deterministic_256() is ignoring byte %d of seed\n", i);
				exit(1);
			}
		}
	}
	// Check that generate_deterministic_256() isn't ignoring num.
	for (j = 0; j < 64; j++)
	{
		seed[j] = 0;
	}
	seed[0] = 1;
	generate_deterministic_256(key2, seed, 1);
	for (j = 0; j < 64; j++)
	{
		if (bigcmp(key2, keys[j]) == BIGCMP_EQUAL)
		{
			printf("generate_deterministic_256() is ignoring num\n");
			exit(1);
		}
	}
	// Check that generate_deterministic_256() is actually deterministic
	generate_deterministic_256(key2, seed, 0);
	if (bigcmp(key2, keys[0]) != BIGCMP_EQUAL)
	{
		printf("generate_deterministic_256() is not deterministic\n");
		exit(1);
	}

	if (argc != 2)
	{
		printf("Usage: %s <n>, where <n> is number of 128-bit samples to take\n", argv[0]);
		printf("Samples will go into random.dat\n");
		exit(1);
	}
	sscanf(argv[1], "%d", &nsamples);
	if (nsamples <= 0)
	{
		printf("Invalid number of samples specified\n");
		exit(1);
	}

	f = fopen("random.dat", "wb");
	if (f == NULL)
	{
		printf("Could not open random.dat for writing\n");
		exit(1);
	}
	srand(42);
	for (i = 0; i < nsamples; i++)
	{
		get_random_256(r);
		fwrite(r, 32, 1, f);
	}
	fclose(f);

	exit(0);
}

#endif // #ifdef TEST

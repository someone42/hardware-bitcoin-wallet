/** \file prandom.c
  *
  * \brief Deals with random and pseudo-random number generation.
  *
  * At the moment this covers whitening of random inputs (getRandom256()) and
  * deterministic private key generation (generateDeterministic256()).
  *
  * This file is licensed as described by the file LICENCE.
  */

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

/** Safety factor for entropy accumulation. The hardware random number
  * generator can (but should strive not to) overestimate its entropy. It can
  * overestimate its entropy by this factor without loss of security. */
#define ENTROPY_SAFETY_FACTOR	2

/** Uses a hash function to accumulate entropy from a hardware random number
  * generator (HWRNG)..
  *
  * To justify why a cryptographic hash is an appropriate means of entropy
  * accumulation, see the paper "Yarrow-160: Notes on the Design and Analysis
  * of the Yarrow Cryptographic Pseudorandom Number Generator" by J. Kelsey,
  * B. Schneier and N. Ferguson, obtained from
  * http://www.schneier.com/paper-yarrow.html on 14-April-2012. Specifically,
  * section 5.2 addresses entropy accumulation by a hash function.
  *
  * Entropy is accumulated by hashing bytes obtained from the HWRNG until the
  * total entropy (as reported by the HWRNG) is at least
  * 256 * ENTROPY_SAFETY_FACTOR bits.
  * \param n The final 256 bit random value will be written here.
  */
void getRandom256(BigNum256 n)
{
	uint16_t total_entropy;
	uint8_t random_bytes[32];
	HashState hs;
	uint8_t i;

	total_entropy = 0;
	sha256Begin(&hs);
	while (total_entropy < (256 * ENTROPY_SAFETY_FACTOR))
	{
		total_entropy = (uint16_t)(total_entropy + hardwareRandomBytes(random_bytes, 32));
		for (i = 0; i < 32; i++)
		{
			sha256WriteByte(&hs, random_bytes[i]);
		}
	}
	sha256Finish(&hs);
	writeHashToByteArray(n, &hs, 1);
}

/** First part of deterministic 256 bit number generation.
  * See comments to generateDeterministic256() for details.
  * It was split into two parts to most efficiently use stack space.
  * \param hash See generateDeterministic256().
  * \param seed See generateDeterministic256().
  * \param num See generateDeterministic256().
  */
static NOINLINE void generateDeterministic256Part1(uint8_t *hash, uint8_t *seed, uint32_t num)
{
	uint8_t i;
	HashState hs;

	sha256Begin(&hs);
	for (i = 32; i < 64; i++)
	{
		sha256WriteByte(&hs, seed[i]);
	}
	// num is written in 64 bit big-endian format.
	for (i = 0; i < 4; i++)
	{
		sha256WriteByte(&hs, 0);
	}
	sha256WriteByte(&hs, (uint8_t)(num >> 24));
	sha256WriteByte(&hs, (uint8_t)(num >> 16));
	sha256WriteByte(&hs, (uint8_t)(num >> 8));
	sha256WriteByte(&hs, (uint8_t)num);
	sha256Finish(&hs);
	writeHashToByteArray(hash, &hs, 1);
}

/** Second part of deterministic 256 bit number generation.
  * See comments to generateDeterministic256() for details.
  * It was split into two parts to most efficiently use stack space.
  * \param out See generateDeterministic256().
  * \param hash See generateDeterministic256().
  * \param seed See generateDeterministic256().
  */
static NOINLINE void generateDeterministic256Part2(BigNum256 out, uint8_t *hash, uint8_t *seed)
{
	uint8_t expanded_key[EXPANDED_KEY_SIZE];

	aesExpandKey(expanded_key, &(seed[0]));
	aesEncrypt(&(out[0]), &(hash[0]), expanded_key);
	aesExpandKey(expanded_key, &(seed[16]));
	aesEncrypt(&(out[16]), &(hash[16]), expanded_key);
}

/** Use a combination of cryptographic primitives to deterministically
  * generate a new 256 bit number.
  *
  * The process is: the last 256 bits of the seed are appended with the
  * counter (the counter is written in 64 bit big-endian format) and hashed
  * using SHA-256. The first and second 128 bits of the seed are used as keys
  * to encrypt the first and second halves (respectively) of the resulting
  * hash using AES. The final result is the two encrypted halves.
  *
  * If having a 512 bit seed is deemed "too big" for an application:
  * - The first and second 128 bits can be the same, meaning that the
  *   encryption key for the two halves is the same.
  * - The last 256 bits of the seed can have up to 128 bits set to 0.
  *
  * Implementing both of these options would reduce the entropy in the seed
  * to 256 bits, which should still be enough. But if possible, it is better
  * to be safe than sorry and use a seed with the full 512 bits of entropy.
  * Why use a hash in addition to a block cipher? Defense in depth - the
  * plaintext to AES is then unknown to an attacker.
  * Note that since out is little-endian, the first encrypted half of the hash
  * goes into the least-significant 128 bits while the second encrypted
  * half goes into the most-significant 128 bits.
  * \param out The generated 256 bit number will be written here.
  * \param seed Should point to a 64 byte array containing the seed for the
  *             pseudo-random number generator.
  * \param num A counter which determines which number the pseudo-random
  *            number generator will output.
  */
void generateDeterministic256(BigNum256 out, uint8_t *seed, uint32_t num)
{
	uint8_t hash[32];

	generateDeterministic256Part1(hash, seed, num);
	generateDeterministic256Part2(out, hash, seed);
}

#if defined(TEST) || defined(INTERFACE_STUBS)

extern int rand(void);

// The purpose of this "random" byte source is to test the entropy
// accumulation behaviour of getRandom256().
uint16_t hardwareRandomBytes(uint8_t *buffer, uint8_t n)
{
	memset(buffer, 0, n);
	buffer[0] = (uint8_t)rand();
	return 8;
}

#endif // #if defined(TEST) || defined(INTERFACE_STUBS)

#ifdef TEST

// A proper test suite for randomness would be quite big, so this test
// spits out samples into random.dat, where they can be analysed using
// an external program.
int main(int argc, char **argv)
{
	uint8_t r[32];
	int i, j;
	int num_samples;
	FILE *f;
	uint8_t seed[64];
	uint8_t keys[64][32];
	uint8_t key2[32];

	// Before outputting samples, do a sanity check that
	// generateDeterministic256() actually has different outputs when
	// each byte of the seed is changed.
	for (i = 0; i < 64; i++)
	{
		memset(seed, 0, 64);
		seed[i] = 1;
		generateDeterministic256(keys[i], seed, 0);
		for (j = 0; j < i; j++)
		{
			if (bigCompare(keys[i], keys[j]) == BIGCMP_EQUAL)
			{
				printf("generateDeterministic256() is ignoring byte %d of seed\n", i);
				exit(1);
			}
		}
	}
	// Check that generateDeterministic256() isn't ignoring num.
	memset(seed, 0, 64);
	seed[0] = 1;
	generateDeterministic256(key2, seed, 1);
	for (j = 0; j < 64; j++)
	{
		if (bigCompare(key2, keys[j]) == BIGCMP_EQUAL)
		{
			printf("generateDeterministic256() is ignoring num\n");
			exit(1);
		}
	}
	// Check that generateDeterministic256() is actually deterministic.
	generateDeterministic256(key2, seed, 0);
	if (bigCompare(key2, keys[0]) != BIGCMP_EQUAL)
	{
		printf("generateDeterministic256() is not deterministic\n");
		exit(1);
	}

	if (argc != 2)
	{
		printf("Usage: %s <n>, where <n> is number of 256 bit samples to take\n", argv[0]);
		printf("Samples will go into random.dat\n");
		exit(1);
	}
	sscanf(argv[1], "%d", &num_samples);
	if (num_samples <= 0)
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
	for (i = 0; i < num_samples; i++)
	{
		getRandom256(r);
		fwrite(r, 32, 1, f);
	}
	fclose(f);

	exit(0);
}

#endif // #ifdef TEST

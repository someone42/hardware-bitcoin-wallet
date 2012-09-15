/** \file prandom.c
  *
  * \brief Deals with random and pseudo-random number generation.
  *
  * At the moment this covers whitening of random inputs (getRandom256()) and
  * deterministic private key generation (generateDeterministic256()).
  *
  * The suggestion to use a persistent entropy pool, and much of the code
  * associated with the entropy pool, are attributed to Peter Todd (retep).
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifdef TEST
#include <stdlib.h>
#endif // #ifdef TEST

#ifdef TEST_PRANDOM
#include <stdio.h>
#include "test_helpers.h"
#include "wallet.h"
#endif // #ifdef TEST_PRANDOM

#include "common.h"
#include "aes.h"
#include "sha256.h"
#include "ripemd160.h"
#include "bignum256.h"
#include "prandom.h"
#include "hwinterface.h"
#include "storage_common.h"

/** Because stdlib.h might not be included, NULL might be undefined. NULL
  * is only used as a placeholder pointer for getRandom256Internal() if
  * there is no appropriate pointer. */
#ifndef NULL
#define NULL ((void *)0) 
#endif // #ifndef NULL

/** Calculate the entropy pool checksum of an entropy pool state.
  * Without integrity checks, an attacker with access to the persistent
  * entropy pool area (in non-volatile memory) could reduce the amount of
  * entropy in the persistent pool. Even if the persistent entropy pool is
  * encrypted, an attacker could reduce the amount of entropy in the pool down
  * to the amount of entropy in the encryption key, which is probably much
  * less than 256 bits.
  * If the persistent entropy pool is unencrypted, then the checksum provides
  * no additional security. In that case, the checksum is only used to check
  * that non-volatile memory is working as expected.
  * \param out The checksum will be written here. This must be a byte array
  *            with space for #POOL_CHECKSUM_LENGTH bytes.
  * \param pool_state The entropy pool state to calculate the checksum of.
  *                   This must be a byte array of
  *                   length #ENTROPY_POOL_LENGTH.
  */
static void calculateEntropyPoolChecksum(uint8_t *out, uint8_t *pool_state)
{
	HashState hs;
	uint8_t hash[32];
	uint8_t i;

	// RIPEMD-160 is used instead of SHA-256 because SHA-256 is already used
	// by getRandom256() to generate output values from the pool state.
	ripemd160Begin(&hs);
	for (i = 0; i < ENTROPY_POOL_LENGTH; i++)
	{
		ripemd160WriteByte(&hs, pool_state[i]);
	}
	ripemd160Finish(&hs);
	writeHashToByteArray(hash, &hs, 1);
#if POOL_CHECKSUM_LENGTH > 20
#error POOL_CHECKSUM_LENGTH is bigger than RIPEMD-160 hash size
#endif
	memcpy(out, hash, POOL_CHECKSUM_LENGTH);
}

/** Set (overwrite) the persistent entropy pool.
  * \param in_pool_state A byte array specifying the desired contents of the
  *                      persistent entropy pool. This must have a length
  *                      of #ENTROPY_POOL_LENGTH bytes.
  * \return Zero on success, non-zero if an error (couldn't write to
  *         non-volatile memory) occurred.
  */
uint8_t setEntropyPool(uint8_t *in_pool_state)
{
	uint8_t checksum[POOL_CHECKSUM_LENGTH];

	if (nonVolatileWrite(in_pool_state, ADDRESS_ENTROPY_POOL, ENTROPY_POOL_LENGTH) != NV_NO_ERROR)
	{
		return 1; // non-volatile write error
	}
	calculateEntropyPoolChecksum(checksum, in_pool_state);
	if (nonVolatileWrite(checksum, ADDRESS_POOL_CHECKSUM, POOL_CHECKSUM_LENGTH) != NV_NO_ERROR)
	{
		return 1; // non-volatile write error
	}
	nonVolatileFlush();
	return 0; // success
}

/** Obtain the contents of the persistent entropy pool.
  * \param out_pool_state A byte array specifying where the contents of the
  *                       persistent entropy pool should be placed. This must
  *                       have space for #ENTROPY_POOL_LENGTH bytes.
  * \return Zero on success, non-zero if an error (couldn't read from
  *         non-volatile memory, or invalid checksum) occurred.
  */
uint8_t getEntropyPool(uint8_t *out_pool_state)
{
	uint8_t checksum_read[POOL_CHECKSUM_LENGTH];
	uint8_t checksum_calculated[POOL_CHECKSUM_LENGTH];

	if (nonVolatileRead(out_pool_state, ADDRESS_ENTROPY_POOL, ENTROPY_POOL_LENGTH) != NV_NO_ERROR)
	{
		return 1; // non-volatile read error
	}
	calculateEntropyPoolChecksum(checksum_calculated, out_pool_state);
	if (nonVolatileRead(checksum_read, ADDRESS_POOL_CHECKSUM, POOL_CHECKSUM_LENGTH) != NV_NO_ERROR)
	{
		return 1; // non-volatile read error
	}
	if (memcmp(checksum_read, checksum_calculated, POOL_CHECKSUM_LENGTH))
	{
		return 1; // checksum doesn't match
	}
	return 0; // success
}

/** Initialise the persistent entropy pool to a specified state. If the
  * current entropy pool is uncorrupted, then its state will be mixed in with
  * the specified state.
  * \param initial_pool_state The initial entropy pool state. This must be a
  *                           byte array of length #ENTROPY_POOL_LENGTH bytes.
  * \return Zero on success, non-zero if an error (couldn't write to
  *         non-volatile memory) occurred.
  */
uint8_t initialiseEntropyPool(uint8_t *initial_pool_state)
{
	HashState hs;
	uint8_t current_pool_state[ENTROPY_POOL_LENGTH];
	uint8_t i;

	if (getEntropyPool(current_pool_state))
	{
		// Current entropy pool is not valid; overwrite it.
		return setEntropyPool(initial_pool_state);
	}
	else
	{
		// Current entropy pool is valid; mix it in with initial_pool_state.
		sha256Begin(&hs);
		for (i = 0; i < ENTROPY_POOL_LENGTH; i++)
		{
			sha256WriteByte(&hs, current_pool_state[i]);
			sha256WriteByte(&hs, initial_pool_state[i]);
		}
		sha256Finish(&hs);
		writeHashToByteArray(current_pool_state, &hs, 1);
		return setEntropyPool(current_pool_state);
	}
}

/** Safety factor for entropy accumulation. The hardware random number
  * generator can (but should strive not to) overestimate its entropy. It can
  * overestimate its entropy by this factor without loss of security. */
#define ENTROPY_SAFETY_FACTOR	2

/** Uses a hash function to accumulate entropy from a hardware random number
  * generator (HWRNG), along with the state of a persistent pool. The
  * operations used are: pool = H(HWRNG | pool) and output = H(H(pool)), where
  * "|" is concatenation and H(x) is the SHA-256 hash of x.
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
  * If the HWRNG breaks in a way that is undetected, the (maybe secret) pool
  * of random bits ensures that outputs will still be unpredictable, albeit
  * not strictly meeting their advertised amount of entropy.
  * \param n The final 256 bit random value will be written here.
  * \param pool_state If use_pool_state is non-zero, then the the state of the
  *                   persistent entropy pool will be read from and written to
  *                   this byte array. The byte array must be of
  *                   length #ENTROPY_POOL_LENGTH bytes. If use_pool_state is
  *                   zero, this parameter will be ignored.
  * \param use_pool_state Specifies whether to use RAM (non-zero) or
  *                       non-volatile memory (zero) to access the persistent
  *                       entropy pool. If this is non-zero, the persistent
  *                       entropy pool will be read/written from/to the byte
  *                       array specified by pool_state. If this is zero, the
  *                       persistent entropy pool will be read/written from/to
  *                       non-volatile memory. The option of using RAM is
  *                       provided for cases where random numbers are needed
  *                       but non-volatile memory is being cleared.
  * \return Zero on success, non-zero if an error (couldn't access
  *         non-volatile memory, or invalid entropy pool checksum) occurred.
  */
static uint8_t getRandom256Internal(BigNum256 n, uint8_t *pool_state, uint8_t use_pool_state)
{
	int r;
	uint16_t total_entropy;
	uint8_t random_bytes[MAX(32, ENTROPY_POOL_LENGTH)];
	HashState hs;
	uint8_t i;

	// Hash in HWRNG randomness until we've reached the entropy required.
	// This needs to happen before hashing the pool itself due to the
	// possibility of length extension attacks; see below.
	total_entropy = 0;
	sha256Begin(&hs);
	while (total_entropy < (256 * ENTROPY_SAFETY_FACTOR))
	{
		r = hardwareRandom32Bytes(random_bytes);
		if (r < 0)
		{
			return 1; // HWRNG failure
		}
		// Sometimes hardwareRandom32Bytes() returns 0, which signifies that
		// more samples are needed in order to do statistical testing.
		// hardwareRandom32Bytes() assumes it will be repeatedly called until
		// it returns a non-zero value. If anything in this while loop is
		// changed, make sure the code still respects this assumption.
		total_entropy = (uint16_t)(total_entropy + r);
		for (i = 0; i < 32; i++)
		{
			sha256WriteByte(&hs, random_bytes[i]);
		}
	}

	// Now include the previous state of the pool.
	if (use_pool_state)
	{
		memcpy(random_bytes, pool_state, ENTROPY_POOL_LENGTH);
	}
	else
	{
		if (getEntropyPool(random_bytes))
		{
			return 1; // error reading from non-volatile memory, or invalid checksum
		}
	}
	for (i = 0; i < ENTROPY_POOL_LENGTH; i++)
	{
		sha256WriteByte(&hs, random_bytes[i]);
	}
	sha256Finish(&hs);
	writeHashToByteArray(random_bytes, &hs, 1);

	// Save the pool state to non-volatile memory immediately as we don't want
	// it to be possible to reuse the pool state.
	if (use_pool_state)
	{
		memcpy(pool_state, random_bytes, ENTROPY_POOL_LENGTH);
	}
	else
	{
		if (setEntropyPool(random_bytes))
		{
			return 1; // error writing to non-volatile memory
		}
	}
	// Hash the pool twice to generate the random bytes to return.
	// We can't output the pool state directly, or an attacker who knew that
	// the HWRNG was broken, and how it was broken, could then predict the
	// next output. Outputting H(pool) is another possibility, but that's
	// kinda cutting it close though, as we're outputting H(pool) while the
	// next output will be H(HWRNG | pool). We've prevented a length extension
	// attack as described above, but there may be other attacks.
	sha256Begin(&hs);
	for (i = 0; i < ENTROPY_POOL_LENGTH; i++)
	{
		sha256WriteByte(&hs, random_bytes[i]);
	}
	sha256FinishDouble(&hs);
	writeHashToByteArray(n, &hs, 1);
	return 0; // success
}

/** Version of getRandom256Internal() which uses non-volatile memory to store
  * the persistent entropy pool. See getRandom256Internal() for more details.
  * \param n See getRandom256Internal()
  * \return See getRandom256Internal()
  */
uint8_t getRandom256(BigNum256 n)
{
	return getRandom256Internal(n, NULL, 0);
}

/** Version of getRandom256Internal() which uses RAM to store
  * the persistent entropy pool. See getRandom256Internal() for more details.
  * \param n See getRandom256Internal()
  * \param pool_state A byte array of length #ENTROPY_POOL_LENGTH which
  *                   contains the persistent entropy pool state. This will
  *                   be both read from and written to.
  * \return See getRandom256Internal()
  */
uint8_t getRandom256TemporaryPool(BigNum256 n, uint8_t *pool_state)
{
	return getRandom256Internal(n, pool_state, 1);
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
  * \param seed Should point to a byte array of length #SEED_LENGTH containing
  *             the seed for the pseudo-random number generator.
  * \param num A counter which determines which number the pseudo-random
  *            number generator will output.
  */
void generateDeterministic256(BigNum256 out, uint8_t *seed, uint32_t num)
{
	uint8_t hash[32];

	generateDeterministic256Part1(hash, seed, num);
	generateDeterministic256Part2(out, hash, seed);
}

#ifdef TEST

/** Set the persistent entropy pool to something, so that calls to
  * getRandom256() don't fail because the entropy pool is not valid. */
void initialiseDefaultEntropyPool(void)
{
	uint8_t pool_state[ENTROPY_POOL_LENGTH];

	memset(pool_state, 0, ENTROPY_POOL_LENGTH);
	initialiseEntropyPool(pool_state);
}

/** Corrupt the persistent entropy pool, so that the getRandom256() is unable
  * to obtain a random number. */
void corruptEntropyPool(void)
{
	uint8_t one_byte;

	nonVolatileRead(&one_byte, ADDRESS_POOL_CHECKSUM, 1);
	one_byte = (uint8_t)(one_byte ^ 0xde);
	nonVolatileWrite(&one_byte, ADDRESS_POOL_CHECKSUM, 1);
}

/** Set this to a non-zero value to simulate the HWRNG breaking. */
static int broken_hwrng;

/** The purpose of this "random" byte source is to test the entropy
  * accumulation behaviour of getRandom256().
  * \param buffer The buffer to fill. This should have enough space for 32
  *               bytes.
  * \return A stupid estimate of the total number of bits (not bytes) of
  *         entropy in the buffer.
  */
int hardwareRandom32Bytes(uint8_t *buffer)
{
	memset(buffer, 0, 32);
	if (!broken_hwrng)
	{
		buffer[0] = (uint8_t)rand();
	}
	return 8;
}

#endif // #ifdef TEST

#ifdef TEST_PRANDOM

/** A proper test suite for randomness would be quite big, so this test
  * spits out samples into random.dat, where they can be analysed using
  * an external program.
  */
int main(int argc, char **argv)
{
	uint8_t r[32];
	int i, j;
	int num_samples;
	int abort;
	int is_broken;
	unsigned int bytes_written;
	FILE *f;
	uint8_t seed[SEED_LENGTH];
	uint8_t keys[SEED_LENGTH][32];
	uint8_t key2[32];
	uint8_t pool_state[ENTROPY_POOL_LENGTH];
	uint8_t compare_pool_state[ENTROPY_POOL_LENGTH];
	uint8_t one_byte;
	uint8_t one_byte_corrupted;
	uint8_t generated_using_nv[1024];
	uint8_t generated_using_ram[1024];

	initTests(__FILE__);

	initWalletTest();
	broken_hwrng = 0;

	// Before outputting samples, do a sanity check that
	// generateDeterministic256() actually has different outputs when
	// each byte of the seed is changed.
	abort = 0;
	for (i = 0; i < SEED_LENGTH; i++)
	{
		memset(seed, 0, SEED_LENGTH);
		seed[i] = 1;
		generateDeterministic256(keys[i], seed, 0);
		for (j = 0; j < i; j++)
		{
			if (bigCompare(keys[i], keys[j]) == BIGCMP_EQUAL)
			{
				printf("generateDeterministic256() is ignoring byte %d of seed\n", i);
				abort = 1;
				break;
			}
		}
		if (abort)
		{
			break;
		}
	}
	if (abort)
	{
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that generateDeterministic256() isn't ignoring num.
	memset(seed, 0, SEED_LENGTH);
	seed[0] = 1;
	generateDeterministic256(key2, seed, 1);
	abort = 0;
	for (j = 0; j < SEED_LENGTH; j++)
	{
		if (bigCompare(key2, keys[j]) == BIGCMP_EQUAL)
		{
			printf("generateDeterministic256() is ignoring num\n");
			abort = 1;
			break;
		}
	}
	if (abort)
	{
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that generateDeterministic256() is actually deterministic.
	generateDeterministic256(key2, seed, 0);
	if (bigCompare(key2, keys[0]) != BIGCMP_EQUAL)
	{
		printf("generateDeterministic256() is not deterministic\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Test if setEntropyPool() works.
	for (i = 0; i < ENTROPY_POOL_LENGTH; i++)
	{
		pool_state[i] = (uint8_t)(rand() & 0xff);
	}
	if (setEntropyPool(pool_state))
	{
		printf("setEntropyPool() doesn't work\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that getEntropyPool() returns what was set using setEntropyPool().
	if (getEntropyPool(compare_pool_state))
	{
		printf("getEntropyPool() doesn't work\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	if (memcmp(pool_state, compare_pool_state, ENTROPY_POOL_LENGTH))
	{
		printf("getEntropyPool() doesn't return what was set using setEntropyPool()\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that the checksum actually detects modification of the entropy
	// pool.
	abort = 0;
	for (i = 0; i < ENTROPY_POOL_LENGTH; i++)
	{
		nonVolatileRead(&one_byte, (uint32_t)(ADDRESS_ENTROPY_POOL + i), 1); // save
		one_byte_corrupted = (uint8_t)(one_byte ^ 0xde);
		nonVolatileWrite(&one_byte_corrupted, (uint32_t)(ADDRESS_ENTROPY_POOL + i), 1);
		if (!getEntropyPool(pool_state))
		{
			printf("getEntropyPool() not detecting corruption at i = %d\n", i);
			reportFailure();
			abort = 1;
			break;
		}
		nonVolatileWrite(&one_byte, (uint32_t)(ADDRESS_ENTROPY_POOL + i), 1); // restore
	}
	if (!abort)
	{
		reportSuccess();
	}

	// Check that the checksum actually detects modification of the checksum
	// itself.
	abort = 0;
	for (i = 0; i < POOL_CHECKSUM_LENGTH; i++)
	{
		nonVolatileRead(&one_byte, (uint32_t)(ADDRESS_POOL_CHECKSUM + i), 1); // save
		one_byte_corrupted = (uint8_t)(one_byte ^ 0xde);
		nonVolatileWrite(&one_byte_corrupted, (uint32_t)(ADDRESS_POOL_CHECKSUM + i), 1);
		if (!getEntropyPool(pool_state))
		{
			printf("getEntropyPool() not detecting corruption at i = %d\n", i);
			reportFailure();
			abort = 1;
			break;
		}
		nonVolatileWrite(&one_byte, (uint32_t)(ADDRESS_POOL_CHECKSUM + i), 1); // restore
	}
	if (!abort)
	{
		reportSuccess();
	}

	// With a known initial pool state and with a broken HWRNG, the random
	// number generator should produce the same output whether the pool is
	// stored in non-volatile memory or RAM.
	broken_hwrng = 1;
	memset(pool_state, 42, ENTROPY_POOL_LENGTH);
	setEntropyPool(pool_state);
	for (i = 0; i < sizeof(generated_using_nv); i += 32)
	{
		if (getRandom256(&(generated_using_nv[i])))
		{
			printf("Unexpected failure of getRandom256()\n");
			exit(1);
		}
	}
	memset(pool_state, 42, ENTROPY_POOL_LENGTH);
	for (i = 0; i < sizeof(generated_using_ram); i += 32)
	{
		if (getRandom256TemporaryPool(&(generated_using_ram[i]), pool_state))
		{
			printf("Unexpected failure of getRandom256()\n");
			exit(1);
		}
	}
	if (memcmp(generated_using_nv, generated_using_ram, sizeof(generated_using_nv)))
	{
		printf("getRandom256() acts differently when using different places to store the entropy pool\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// initialiseEntropyPool() should directly set the entropy pool state if
	// the current state is invalid.
	memset(pool_state, 0, ENTROPY_POOL_LENGTH);
	setEntropyPool(pool_state); // make sure entropy pool state is valid before corrupting it
	nonVolatileRead(&one_byte, ADDRESS_POOL_CHECKSUM, 1);
	one_byte_corrupted = (uint8_t)(one_byte ^ 0xde);
	nonVolatileWrite(&one_byte_corrupted, ADDRESS_POOL_CHECKSUM, 1);
	memset(pool_state, 43, ENTROPY_POOL_LENGTH);
	if (initialiseEntropyPool(pool_state))
	{
		printf("initialiseEntropyPool() doesn't work\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	getEntropyPool(compare_pool_state);
	if (memcmp(pool_state, compare_pool_state, ENTROPY_POOL_LENGTH))
	{
		printf("initialiseEntropyPool() not setting pool state when current one is invalid\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// initialiseEntropyPool() should mix in the specified entropy pool state
	// if the current state is valid.
	memset(pool_state, 42, ENTROPY_POOL_LENGTH);
	setEntropyPool(pool_state); // make sure entropy pool state is valid
	memset(pool_state, 43, ENTROPY_POOL_LENGTH);
	initialiseEntropyPool(pool_state);
	getEntropyPool(compare_pool_state);
	if (!memcmp(pool_state, compare_pool_state, ENTROPY_POOL_LENGTH))
	{
		printf("initialiseEntropyPool() not mixing pool state when current one is valid\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	if (argc != 3)
	{
		printf("Usage: %s <n> <is_broken>, where:\n", argv[0]);
		printf("  <n> is number of 256 bit samples to take\n");
		printf("  <is_broken> specifies whether (non-zero) or not (zero) to use a\n");
		printf("              simulated broken HWRNG\n");
		printf("\n");
		printf("Samples will go into random.dat\n");
		exit(1);
	}
	sscanf(argv[1], "%d", &num_samples);
	if (num_samples <= 0)
	{
		printf("Invalid number of samples specified\n");
		exit(1);
	}
	sscanf(argv[2], "%d", &is_broken);
	if (is_broken)
	{
		broken_hwrng = 1;
	}
	else
	{
		broken_hwrng = 0;
	}

	f = fopen("random.dat", "wb");
	if (f == NULL)
	{
		printf("Could not open random.dat for writing\n");
		exit(1);
	}
	srand(42);
	bytes_written = 0;
	for (i = 0; i < num_samples; i++)
	{
		if (getRandom256(r))
		{
			printf("Unexpected failure of getRandom256()\n");
			exit(1);
		}
		bytes_written += fwrite(r, 1, 32, f);
	}
	fclose(f);

	printf("%u bytes written to random.dat\n", bytes_written);
	finishTests();

	exit(0);
}

#endif // #ifdef TEST_PRANDOM

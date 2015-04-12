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

#include <assert.h>
#endif // #ifdef TEST

#ifdef TEST_PRANDOM
#include <stdio.h>
#endif // #ifdef TEST_PRANDOM

#include <stdlib.h> // for definition of NULL
#include "common.h"
#include "aes.h"
#include "sha256.h"
#include "ripemd160.h"
#include "hmac_sha512.h"
#include "endian.h"
#include "ecdsa.h"
#include "bignum256.h"
#include "transaction.h"
#include "prandom.h"
#include "hwinterface.h"
#include "storage_common.h"

#ifdef TEST_PRANDOM
#include "test_helpers.h"
#include "wallet.h"
#endif // #ifdef TEST_PRANDOM

/** Because stdlib.h might not be included, NULL might be undefined. NULL
  * is only used as a placeholder pointer for getRandom256Internal() if
  * there is no appropriate pointer. */
#ifndef NULL
#define NULL ((void *)0) 
#endif // #ifndef NULL

/** The parent public key for the BIP 0032 deterministic key generator (see
  * generateDeterministic256()). The contents of this variable are only valid
  * if #cached_parent_public_key_valid is true.
  *
  * generateDeterministic256() could calculate the parent public key each time
  * a new deterministic key is requested. However, that would slow down
  * deterministic key generation significantly, as point multiplication would
  * be required each time a key was requested. So this variable functions as
  * a cache.
  * \warning The x and y components are stored in little-endian format.
  */
static PointAffine cached_parent_public_key;
/** Specifies whether the contents of #parent_public_key are valid. */
static bool cached_parent_public_key_valid;

#ifdef TEST_PRANDOM
/** Hack to allow test to access derived chain code. This is needed for the
  * sipa test cases. */
static uint8_t test_chain_code[32];
#endif // #ifdef TEST_PRANDOM

/** Set the parent public key for the deterministic key generator (see
  * generateDeterministic256()). This function will speed up subsequent calls
  * to generateDeterministic256(), by allowing it to use a cached parent
  * public key.
  * \param parent_private_key The parent private key, from which the parent
  *                           public key will be derived. Note that this
  *                           should be in little-endian format.
  */
static void setParentPublicKeyFromPrivateKey(BigNum256 parent_private_key)
{
	setToG(&cached_parent_public_key);
	pointMultiply(&cached_parent_public_key, parent_private_key);
	cached_parent_public_key_valid = true;
}

/** Clear the parent public key cache (see #parent_private_key). This should
  * be called whenever a wallet is unloaded, so that subsequent calls to
  * generateDeterministic256() don't result in addresses from the old wallet.
  */
void clearParentPublicKeyCache(void)
{
	memset(&cached_parent_public_key, 0xff, sizeof(cached_parent_public_key)); // just to be sure
	memset(&cached_parent_public_key, 0, sizeof(cached_parent_public_key));
	cached_parent_public_key_valid = false;
}

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
	writeHashToByteArray(hash, &hs, true);
#if POOL_CHECKSUM_LENGTH > 20
#error "POOL_CHECKSUM_LENGTH is bigger than RIPEMD-160 hash size"
#endif
	memcpy(out, hash, POOL_CHECKSUM_LENGTH);
}

/** Set (overwrite) the persistent entropy pool.
  * \param in_pool_state A byte array specifying the desired contents of the
  *                      persistent entropy pool. This must have a length
  *                      of #ENTROPY_POOL_LENGTH bytes.
  * \return false on success, true if an error (couldn't write to non-volatile
  *         memory) occurred.
  */
bool setEntropyPool(uint8_t *in_pool_state)
{
	uint8_t checksum[POOL_CHECKSUM_LENGTH];

	if (nonVolatileWrite(in_pool_state, PARTITION_GLOBAL, ADDRESS_ENTROPY_POOL, ENTROPY_POOL_LENGTH) != NV_NO_ERROR)
	{
		return true; // non-volatile write error
	}
	calculateEntropyPoolChecksum(checksum, in_pool_state);
	if (nonVolatileWrite(checksum, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, POOL_CHECKSUM_LENGTH) != NV_NO_ERROR)
	{
		return true; // non-volatile write error
	}
	if (nonVolatileFlush() != NV_NO_ERROR)
	{
		return true; // non-volatile write error
	}
	return false; // success
}

/** Obtain the contents of the persistent entropy pool.
  * \param out_pool_state A byte array specifying where the contents of the
  *                       persistent entropy pool should be placed. This must
  *                       have space for #ENTROPY_POOL_LENGTH bytes.
  * \return false on success, true if an error (couldn't read from
  *         non-volatile memory, or invalid checksum) occurred.
  */
bool getEntropyPool(uint8_t *out_pool_state)
{
	uint8_t checksum_read[POOL_CHECKSUM_LENGTH];
	uint8_t checksum_calculated[POOL_CHECKSUM_LENGTH];

	if (nonVolatileRead(out_pool_state, PARTITION_GLOBAL, ADDRESS_ENTROPY_POOL, ENTROPY_POOL_LENGTH) != NV_NO_ERROR)
	{
		return true; // non-volatile read error
	}
	calculateEntropyPoolChecksum(checksum_calculated, out_pool_state);
	if (nonVolatileRead(checksum_read, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, POOL_CHECKSUM_LENGTH) != NV_NO_ERROR)
	{
		return true; // non-volatile read error
	}
	if (memcmp(checksum_read, checksum_calculated, POOL_CHECKSUM_LENGTH))
	{
		return true; // checksum doesn't match
	}
	return false; // success
}

/** Initialise the persistent entropy pool to a specified state. If the
  * current entropy pool is uncorrupted, then its state will be mixed in with
  * the specified state.
  * \param initial_pool_state The initial entropy pool state. This must be a
  *                           byte array of length #ENTROPY_POOL_LENGTH bytes.
  * \return false on success, true if an error (couldn't write to
  *         non-volatile memory) occurred.
  */
bool initialiseEntropyPool(uint8_t *initial_pool_state)
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
		writeHashToByteArray(current_pool_state, &hs, true);
		return setEntropyPool(current_pool_state);
	}
}

/** Safety factor for entropy accumulation. The hardware random number
  * generator can (but should strive not to) overestimate its entropy. It can
  * overestimate its entropy by this factor without loss of security. */
#define ENTROPY_SAFETY_FACTOR	2

/** Uses a hash function to accumulate entropy from a hardware random number
  * generator (HWRNG), along with the state of a persistent pool. The
  * operations used are: intermediate = H(HWRNG | pool),
  * output = H(H(intermediate)) and new_pool = H(intermediate | padding),
  * where "|" is concatenation, H(x) is the SHA-256 hash of x and padding
  * consists of 32 0x42 bytes.
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
  * \param pool_state If use_pool_state is true, then the the state of the
  *                   persistent entropy pool will be read from and written to
  *                   this byte array. The byte array must be of
  *                   length #ENTROPY_POOL_LENGTH bytes. If use_pool_state is
  *                   false, this parameter will be ignored.
  * \param use_pool_state Specifies whether to use RAM (true) or
  *                       non-volatile memory (false) to access the persistent
  *                       entropy pool. If this is true, the persistent
  *                       entropy pool will be read/written from/to the byte
  *                       array specified by pool_state. If this is false, the
  *                       persistent entropy pool will be read/written from/to
  *                       non-volatile memory. The option of using RAM is
  *                       provided for cases where random numbers are needed
  *                       but non-volatile memory is being cleared.
  * \return false on success, true if an error (couldn't access
  *         non-volatile memory, or invalid entropy pool checksum) occurred.
  */
static bool getRandom256Internal(BigNum256 n, uint8_t *pool_state, bool use_pool_state)
{
	int r;
	uint16_t total_entropy;
	uint8_t random_bytes[MAX(32, ENTROPY_POOL_LENGTH)];
	uint8_t intermediate[32];
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
			return true; // HWRNG failure
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
			return true; // error reading from non-volatile memory, or invalid checksum
		}
	}
	for (i = 0; i < ENTROPY_POOL_LENGTH; i++)
	{
		sha256WriteByte(&hs, random_bytes[i]);
	}
	sha256Finish(&hs);
	writeHashToByteArray(intermediate, &hs, true);

	// Calculate new pool state.
	// We can't use the intermediate state as the new pool state, or an
	// attacker who obtained access to the pool state could determine
	// the most recent returned random output.
	sha256Begin(&hs);
	for (i = 0; i < 32; i++)
	{
		sha256WriteByte(&hs, intermediate[i]);
	}
	for (i = 0; i < 32; i++)
	{
		sha256WriteByte(&hs, 0x42); // padding
	}
	sha256Finish(&hs);
	writeHashToByteArray(random_bytes, &hs, true);

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
			return true; // error writing to non-volatile memory
		}
	}
	// Hash the intermediate state twice to generate the random bytes to
	// return.
	// We can't output the pool state directly, or an attacker who knew that
	// the HWRNG was broken, and how it was broken, could then predict the
	// next output. Outputting H(intermediate) is another possibility, but
	// that's kinda cutting it close though, as we're outputting
	// H(intermediate) while the next pool state will be
	// H(intermediate | padding). We've prevented a length extension
	// attack as described above, but there may be other attacks.
	sha256Begin(&hs);
	for (i = 0; i < ENTROPY_POOL_LENGTH; i++)
	{
		sha256WriteByte(&hs, intermediate[i]);
	}
	sha256FinishDouble(&hs);
	writeHashToByteArray(n, &hs, true);
	return false; // success
}

/** Version of getRandom256Internal() which uses non-volatile memory to store
  * the persistent entropy pool. See getRandom256Internal() for more details.
  * \param n See getRandom256Internal()
  * \return See getRandom256Internal()
  */
bool getRandom256(BigNum256 n)
{
	return getRandom256Internal(n, NULL, false);
}

/** Version of getRandom256Internal() which uses RAM to store
  * the persistent entropy pool. See getRandom256Internal() for more details.
  * \param n See getRandom256Internal()
  * \param pool_state A byte array of length #ENTROPY_POOL_LENGTH which
  *                   contains the persistent entropy pool state. This will
  *                   be both read from and written to.
  * \return See getRandom256Internal()
  */
bool getRandom256TemporaryPool(BigNum256 n, uint8_t *pool_state)
{
	return getRandom256Internal(n, pool_state, true);
}

/** Generate an insecure one-time password.
  * \param otp The generated one-time password will be written here. This must
  *            be a character array with enough space to store #OTP_LENGTH
  *            characters. The OTP will be null-terminated.
  * \warning The password generated by this function has dubious security
  *          properties. Do not use the password for anything private.
  */
void generateInsecureOTP(char *otp)
{
	unsigned int i;
	uint8_t random_bytes[32];
	uint8_t dummy_pool_state[ENTROPY_POOL_LENGTH];

	if (getRandom256(random_bytes))
	{
		// Sometimes an OTP may be required when the entropy pool hasn't
		// been initialised yet (eg. when formatting storage). In those
		// cases, use a RAM-based dummy entropy pool. This has poor security
		// properties, but then again, this function is called
		// generateInsecureOTP() for a reason.
		memset(dummy_pool_state, 42, sizeof(dummy_pool_state));
		if (getRandom256TemporaryPool(random_bytes, dummy_pool_state))
		{
			// This function must return something, even if it's not quite
			// random.
			memset(random_bytes, 42, sizeof(random_bytes));
		}
	}

#if OTP_LENGTH > 32
#error "OTP_LENGTH too big"
#endif // #if OTP_LENGTH > 32
	for (i = 0; i < (OTP_LENGTH - 1); i++)
	{
		// Each character is approximately uniformly distributed between
		// 0 and 9 (inclusive). Here, "approximately" doesn't matter because
		// this function is insecure.
		otp[i] = (char)('0' + (random_bytes[i] % 10));
	}
	otp[OTP_LENGTH - 1] = '\0';
}

/** Use a combination of cryptographic primitives to deterministically
  * generate a new 256 bit number.
  *
  * The generator uses the algorithm described in
  * https://en.bitcoin.it/wiki/BIP_0032, accessed 12-November-2012 under the
  * "Specification" header. The generator generates uncompressed keys.
  *
  * \param out The generated 256 bit number will be written here.
  * \param seed Should point to a byte array of length #SEED_LENGTH containing
  *             the seed for the pseudo-random number generator. While the
  *             seed can be considered as an arbitrary array of bytes, the
  *             bytes of the array also admit the following interpretation:
  *             the first 32 bytes are the parent private key in big-endian
  *             format, and the next 32 bytes are the chain code (endian
  *             independent).
  * \param num A counter which determines which number the pseudo-random
  *            number generator will output.
  * \return false upon success, true if the specified seed is not valid (will
  *         produce degenerate private keys).
  */
bool generateDeterministic256(BigNum256 out, const uint8_t *seed, const uint32_t num)
{
	BigNum256 i_l;
	uint8_t k_par[32];
	uint8_t hash[SHA512_HASH_LENGTH];
	uint8_t hmac_message[69]; // 04 (1 byte) + x (32 bytes) + y (32 bytes) + num (4 bytes)

	setFieldToN();
	memcpy(k_par, seed, 32);
	swapEndian256(k_par); // since seed is big-endian
	bigModulo(k_par, k_par); // just in case
	// k_par cannot be 0. If it is zero, then the output of this generator
	// will always be 0.
	if (bigIsZero(k_par))
	{
		return true; // invalid seed
	}
	if (!cached_parent_public_key_valid)
	{
		setParentPublicKeyFromPrivateKey(k_par);
	}
	// BIP 0032 specifies that the public key should be represented in a way
	// that is compatible with "SEC 1: Elliptic Curve Cryptography" by
	// Certicom research, obtained 15-August-2011 from:
	// http://www.secg.org/collateral/sec1_final.pdf section 2.3 ("Data Types
	// and Conversions"). The gist of it is: 0x04, followed by x, then y in
	// big-endian format.
	// TODO: Remove this all and implement updated BIP 32
	hmac_message[0] = 0x04;
	memcpy(&(hmac_message[1]), cached_parent_public_key.x, 32);
	swapEndian256(&(hmac_message[1]));
	memcpy(&(hmac_message[33]), cached_parent_public_key.y, 32);
	swapEndian256(&(hmac_message[33]));
	writeU32BigEndian(&(hmac_message[65]), num);
	hmacSha512(hash, &(seed[32]), 32, hmac_message, sizeof(hmac_message));

	setFieldToN();
	i_l = (BigNum256)hash;
	swapEndian256(i_l); // since hash is big-endian
	bigModulo(i_l, i_l); // just in case
	bigMultiply(out, i_l, k_par);

#ifdef TEST_PRANDOM
	memcpy(test_chain_code, &(hash[32]), sizeof(test_chain_code));
#endif // #ifdef TEST_PRANDOM

	return false; // success
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

	nonVolatileRead(&one_byte, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, 1);
	one_byte = (uint8_t)(one_byte ^ 0xde);
	nonVolatileWrite(&one_byte, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, 1);
}

/** Set this to true to simulate the HWRNG breaking. */
static bool broken_hwrng;

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

#if defined(TEST_PRANDOM) || defined(TEST_WALLET)

/** Use a combination of cryptographic primitives to deterministically
  * generate a new public key.
  *
  * The generator uses the algorithm described in
  * https://en.bitcoin.it/wiki/BIP_0032, accessed 12-November-2012 under the
  * "Specification" header. The generator generates uncompressed keys.
  *
  * \param out_public_key The generated public key will be written here.
  * \param in_parent_public_key The parent public key, referred to as K_par in
  *                             the article above.
  * \param chain_code Should point to a byte array of length 32 containing
  *                   the BIP 0032 chain code.
  * \param num A counter which determines which number the pseudo-random
  *            number generator will output.
  */
void generateDeterministicPublicKey(PointAffine *out_public_key, PointAffine *in_parent_public_key, const uint8_t *chain_code, const uint32_t num)
{
	uint8_t hash[SHA512_HASH_LENGTH];
	uint8_t hmac_message[69]; // 04 (1 byte) + x (32 bytes) + y (32 bytes) + num (4 bytes)
	BigNum256 i_l;

	hmac_message[0] = 0x04;
	memcpy(&(hmac_message[1]), in_parent_public_key->x, 32);
	swapEndian256(&(hmac_message[1]));
	memcpy(&(hmac_message[33]), in_parent_public_key->y, 32);
	swapEndian256(&(hmac_message[33]));
	writeU32BigEndian(&(hmac_message[65]), num);
	hmacSha512(hash, chain_code, 32, hmac_message, sizeof(hmac_message));
	setFieldToN();
	i_l = (BigNum256)hash;
	swapEndian256(i_l); // since hash is big-endian
	bigModulo(i_l, i_l); // just in case
	memcpy(out_public_key, in_parent_public_key, sizeof(PointAffine));
	pointMultiply(out_public_key, i_l);
}

#endif // #if defined(TEST_PRANDOM) || defined(TEST_WALLET)

#ifdef TEST_PRANDOM

/** The master private key and chain code of one of sipa's BIP 0032 test
  * vectors, obtained from
  * https://github.com/sipa/bitcoin/blob/edbdc5313c02dc82104cfb6017ce3427bf323071/src/test/detwallet_tests.cpp
  * on 13-November-2012. This is
  * sha512(0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef).
  */
const uint8_t sipa_test_master_seed[64] = {
0xb5, 0x82, 0x9c, 0xe3, 0xcc, 0xf1, 0xd8, 0xed, 0xd5, 0xda, 0x11, 0x32, 0xd4,
0x62, 0x71, 0xb0, 0x16, 0x9f, 0x58, 0xb6, 0x41, 0x4f, 0xd2, 0x63, 0xd3, 0xc9,
0x8d, 0xa6, 0x27, 0x17, 0x0f, 0x5e, 0x13, 0xcb, 0x19, 0x4e, 0xf4, 0x64, 0xe3,
0xd3, 0x96, 0x85, 0x47, 0xe0, 0x43, 0xf8, 0xca, 0xf1, 0x9e, 0x78, 0xdb, 0x5b,
0x66, 0x93, 0xba, 0x86, 0x7b, 0x1a, 0x61, 0x3b, 0x9c, 0x33, 0x7c, 0xf0};

/** Number of test cases in #sipa_test_public_keys. */
#define SIPA_TEST_ADDRESSES		8

/** Dervied public keys of one of sipa's BIP 0032 test vectors
  * (see #sipa_test_master_seed). These are the public keys which result from
  * repeatedly applying the child key derivation function with n = 0x12345678.
  */
const uint8_t sipa_test_public_keys[SIPA_TEST_ADDRESSES][65] = {
{0x04, 0x65, 0x23, 0x2f, 0x8c, 0x57, 0x94, 0x7d, 0x0b, 0xee, 0x67, 0x18, 0x76,
0x03, 0xec, 0xb4, 0x35, 0x90, 0x2f, 0x56, 0x9b, 0x71, 0xf5, 0xc5, 0xb3, 0x1f,
0xda, 0xd4, 0x2f, 0x2b, 0x60, 0xfe, 0xa3, 0xbb, 0xe7, 0x83, 0xb7, 0xe6, 0x26,
0x99, 0x13, 0xfc, 0x37, 0x21, 0x31, 0x0e, 0x7e, 0x09, 0x83, 0x57, 0x7c, 0x00,
0xe3, 0x8f, 0xa5, 0x91, 0xd8, 0x8f, 0x07, 0x5c, 0xc7, 0xe6, 0x66, 0x4e, 0x47},
{0x04, 0x0c, 0xb5, 0x75, 0x82, 0xe3, 0x7f, 0x42, 0x63, 0x5c, 0xf2, 0xb9, 0xee,
0x21, 0xe7, 0xc1, 0x20, 0xea, 0x56, 0x29, 0x20, 0x8d, 0x02, 0xf5, 0xf7, 0x22,
0xbe, 0x06, 0x84, 0xe8, 0xc4, 0x50, 0xdd, 0x84, 0xfa, 0x4b, 0x45, 0x31, 0xf9,
0x84, 0x53, 0xee, 0x05, 0x6f, 0x84, 0xec, 0xd3, 0x94, 0xa4, 0xae, 0x27, 0xf9,
0x10, 0x0f, 0x6b, 0xb0, 0xe5, 0xea, 0x35, 0xba, 0xf8, 0xd2, 0x13, 0x5d, 0x4b},
{0x04, 0x94, 0x37, 0x56, 0xa7, 0x87, 0x4e, 0x79, 0xb8, 0x40, 0x38, 0x3b, 0xa9,
0xf2, 0xfc, 0x37, 0xd9, 0x3e, 0xd9, 0x83, 0x7f, 0x4e, 0x1f, 0xcc, 0x17, 0x32,
0xac, 0x65, 0x92, 0xf4, 0x19, 0x4d, 0x87, 0x9a, 0x02, 0xbb, 0xae, 0xb2, 0x00,
0x18, 0xc9, 0xc2, 0x3c, 0x6d, 0x04, 0x5d, 0x99, 0x48, 0x8b, 0x44, 0x4c, 0xb4,
0x4a, 0x42, 0x4c, 0x35, 0xec, 0x47, 0xa7, 0x56, 0x41, 0xa1, 0xa1, 0x71, 0x0d},
{0x04, 0xe2, 0xdb, 0x6b, 0x4a, 0x01, 0xf9, 0xa0, 0x2f, 0x54, 0x6f, 0xad, 0x07,
0xb4, 0x25, 0x4a, 0x2c, 0x46, 0x6c, 0xea, 0x48, 0xb6, 0x7b, 0xb3, 0xd9, 0xda,
0x4a, 0x91, 0xc8, 0xaa, 0xbf, 0x38, 0x1a, 0x78, 0x0b, 0x4f, 0x2a, 0x55, 0xc3,
0x97, 0x44, 0x32, 0xc1, 0x59, 0x39, 0x6f, 0x50, 0x0f, 0x4a, 0x7c, 0xb3, 0x1f,
0x26, 0x01, 0x7c, 0x45, 0x41, 0x4e, 0xdb, 0xa6, 0x8a, 0x58, 0x9f, 0x87, 0xc6},
{0x04, 0x23, 0x2f, 0x63, 0x0b, 0xe0, 0x15, 0x30, 0x2f, 0x57, 0x07, 0x8b, 0x5d,
0x44, 0x8d, 0x55, 0x65, 0xc7, 0xea, 0x1b, 0x8a, 0x2d, 0x9b, 0xea, 0x4e, 0xff,
0xee, 0x42, 0xa8, 0xe2, 0x10, 0xc3, 0x96, 0x5e, 0x01, 0x32, 0x7f, 0xf2, 0xe1,
0x85, 0x44, 0x94, 0xa6, 0x8d, 0x37, 0x05, 0xd0, 0x01, 0x7a, 0x49, 0x74, 0xe2,
0x7c, 0x26, 0x0b, 0x64, 0x85, 0xbc, 0xd1, 0x66, 0x53, 0x49, 0x29, 0xb7, 0xc5},
{0x04, 0x02, 0x4e, 0xe3, 0x78, 0xd4, 0xfe, 0xdb, 0x3e, 0xf0, 0x21, 0xac, 0xaf,
0xaf, 0x5a, 0xf4, 0x59, 0x54, 0x33, 0x54, 0xd4, 0x4e, 0x88, 0xa7, 0x83, 0xb5,
0x5c, 0x0b, 0xe9, 0x6c, 0x43, 0x92, 0x2a, 0xd2, 0x46, 0x5c, 0xa6, 0x08, 0xcb,
0x35, 0x20, 0x35, 0x1a, 0x1b, 0x3f, 0xe5, 0xbb, 0xce, 0x60, 0xf4, 0xc6, 0xa6,
0x55, 0x06, 0x47, 0xd8, 0x93, 0xbd, 0xfb, 0x5a, 0xcf, 0x94, 0xea, 0xa6, 0xe0},
{0x04, 0x73, 0x73, 0xf6, 0xc5, 0x66, 0x72, 0xa0, 0x1b, 0xd2, 0x27, 0xb5, 0xb0,
0x88, 0xdb, 0xf2, 0x00, 0x73, 0x5a, 0xd8, 0x51, 0xad, 0xad, 0xec, 0x4f, 0x9d,
0x3b, 0x4f, 0xd8, 0x33, 0xbe, 0xad, 0x67, 0x1e, 0x88, 0x56, 0x61, 0x0f, 0x8f,
0xca, 0xe9, 0xd6, 0x4e, 0x04, 0xf3, 0xfd, 0x04, 0xc8, 0x48, 0x26, 0xf9, 0xa1,
0x93, 0xf4, 0xa5, 0x8a, 0x3b, 0x17, 0x8c, 0xe1, 0x80, 0xf9, 0xeb, 0x42, 0xa1},
{0x04, 0x17, 0x9e, 0x3a, 0x57, 0x63, 0xb0, 0xcd, 0x1b, 0x0e, 0x4f, 0xa2, 0xed,
0xb0, 0x77, 0xfb, 0x12, 0xcc, 0x3d, 0x84, 0xac, 0xa8, 0x9f, 0x99, 0x51, 0xb5,
0xc6, 0x18, 0x3a, 0xee, 0xb7, 0xa3, 0xe8, 0xe1, 0x16, 0xb9, 0x4e, 0x94, 0xc9,
0x8d, 0x07, 0xbb, 0x11, 0x8d, 0x3a, 0x54, 0xb1, 0xc5, 0x72, 0x82, 0xf5, 0xea,
0x2f, 0xf6, 0x80, 0x46, 0x1c, 0x85, 0x7d, 0xd3, 0x74, 0xe6, 0x08, 0xf1, 0xf3}};

/** Test whether deterministic key generator is a type-2 generator. This means
  * that CKD(x, n) * G = CKD'(x * G, n) i.e. public keys can be derived
  * without knowing the parent private key.
  * \param seed generateDeterministic256().
  * \param num See generateDeterministic256().
  */
static void type2DeterministicTest(uint8_t *seed, uint32_t num)
{
	uint8_t private_key[32];
	PointAffine compare_public_key;
	PointAffine other_parent_public_key;
	PointAffine public_key;

	// Calculate CKD(x, n) * G.
	clearParentPublicKeyCache(); // ensure public key cache has been cleared
	assert(!generateDeterministic256(private_key, seed, num));
	setToG(&compare_public_key);
	pointMultiply(&compare_public_key, private_key);
	// Calculate CKD'(x * G, n).
	memcpy(private_key, seed, 32);
	swapEndian256(private_key);
	setToG(&other_parent_public_key);
	pointMultiply(&other_parent_public_key, private_key);
	generateDeterministicPublicKey(&public_key, &other_parent_public_key, &(seed[32]), num);
	// Compare them.
	if (memcmp(&compare_public_key, &public_key, sizeof(PointAffine)))
	{
		printf("Determinstic key generator is not type-2, num = %u\n", num);
		printf("Parent private key: ");
		printBigEndian16(seed);
		printf("\nChain code: ");
		printBigEndian16(&(seed[32]));
		printf("\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
}

/** A proper test suite for randomness would be quite big, so this test
  * spits out samples into random.dat, where they can be analysed using
  * an external program.
  */
int main(int argc, char **argv)
{
	uint8_t r[32];
	int i, j;
	int num_samples;
	bool abort;
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
	uint8_t public_key_binary[65];
	PointAffine public_key;
	char otp[OTP_LENGTH];
	char otp2[OTP_LENGTH];

	initTests(__FILE__);

	initWalletTest();
	broken_hwrng = false;

	// Before outputting samples, do a sanity check that
	// generateDeterministic256() actually has different outputs when
	// each byte of the seed is changed.
	abort = false;
	for (i = 0; i < SEED_LENGTH; i++)
	{
		memset(seed, 42, SEED_LENGTH); // seed cannot be all 0
		seed[i] = 1;
		clearParentPublicKeyCache(); // ensure public key cache has been cleared
		assert(!generateDeterministic256(keys[i], seed, 0));
		for (j = 0; j < i; j++)
		{
			if (bigCompare(keys[i], keys[j]) == BIGCMP_EQUAL)
			{
				printf("generateDeterministic256() is ignoring byte %d of seed\n", i);
				abort = true;
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
	memset(seed, 42, SEED_LENGTH); // seed cannot be all 0
	seed[0] = 1;
	clearParentPublicKeyCache(); // ensure public key cache has been cleared
	assert(!generateDeterministic256(key2, seed, 1));
	abort = false;
	for (j = 0; j < SEED_LENGTH; j++)
	{
		if (bigCompare(key2, keys[j]) == BIGCMP_EQUAL)
		{
			printf("generateDeterministic256() is ignoring num\n");
			abort = true;
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
	clearParentPublicKeyCache(); // ensure public key cache has been cleared
	assert(!generateDeterministic256(key2, seed, 0));
	if (bigCompare(key2, keys[0]) != BIGCMP_EQUAL)
	{
		printf("generateDeterministic256() is not deterministic\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that generateDeterministic256() generates BIP 0032 private keys
	// correctly.
	memcpy(seed, sipa_test_master_seed, SEED_LENGTH);
	for (i = 1; i < SIPA_TEST_ADDRESSES; i++)
	{
		clearParentPublicKeyCache(); // ensure public key cache has been cleared
		assert(!generateDeterministic256(key2, seed, (uint32_t)0x12345678));
		// generateDeterministic256() generates private keys, but the test
		// vectors include only derived public keys, so the generated private
		// keys need to be converted into public keys.
		setToG(&public_key);
		pointMultiply(&public_key, key2);
		swapEndian256(public_key.x);
		swapEndian256(public_key.y);
		// Compare generated public keys with test vectors.
		public_key_binary[0] = 0x04;
		memcpy(&(public_key_binary[1]), public_key.x, 32);
		memcpy(&(public_key_binary[33]), public_key.y, 32);
		if (public_key.is_point_at_infinity
			|| memcmp(public_key_binary, sipa_test_public_keys[i], sizeof(public_key_binary)))
		{
			printf("generateDeterministic256() failed sipa test %d\n", i);
			reportFailure();
		}
		else
		{
			reportSuccess();
		}
		// Get derived seed.
		memcpy(seed, key2, 32);
		swapEndian256(seed);
		memcpy(&(seed[32]), test_chain_code, sizeof(test_chain_code));
	}

	// Check that generateDeterministic256() functions as a type-2
	// deterministic wallet i.e. CKD(x, n) * G = CKD'(x * G, n).
	for (i = 0; i < 2; i++)
	{
		// Try two different seeds.
		if (i == 0)
		{
			memset(seed, 42, SEED_LENGTH);
			seed[2] = 1;
		}
		else
		{
			memcpy(seed, sipa_test_master_seed, SEED_LENGTH);
		}
		type2DeterministicTest(seed, 0);
		type2DeterministicTest(seed, 1);
		type2DeterministicTest(seed, 0xfffffffe);
		type2DeterministicTest(seed, 4095);
		type2DeterministicTest(seed, 0xffffffff);
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
	abort = false;
	for (i = 0; i < ENTROPY_POOL_LENGTH; i++)
	{
		nonVolatileRead(&one_byte, PARTITION_GLOBAL, (uint32_t)(ADDRESS_ENTROPY_POOL + i), 1); // save
		one_byte_corrupted = (uint8_t)(one_byte ^ 0xde);
		nonVolatileWrite(&one_byte_corrupted, PARTITION_GLOBAL, (uint32_t)(ADDRESS_ENTROPY_POOL + i), 1);
		if (!getEntropyPool(pool_state))
		{
			printf("getEntropyPool() not detecting corruption at i = %d\n", i);
			reportFailure();
			abort = true;
			break;
		}
		nonVolatileWrite(&one_byte, PARTITION_GLOBAL, (uint32_t)(ADDRESS_ENTROPY_POOL + i), 1); // restore
	}
	if (!abort)
	{
		reportSuccess();
	}

	// Check that the checksum actually detects modification of the checksum
	// itself.
	abort = false;
	for (i = 0; i < POOL_CHECKSUM_LENGTH; i++)
	{
		nonVolatileRead(&one_byte,PARTITION_GLOBAL,  (uint32_t)(ADDRESS_POOL_CHECKSUM + i), 1); // save
		one_byte_corrupted = (uint8_t)(one_byte ^ 0xde);
		nonVolatileWrite(&one_byte_corrupted, PARTITION_GLOBAL, (uint32_t)(ADDRESS_POOL_CHECKSUM + i), 1);
		if (!getEntropyPool(pool_state))
		{
			printf("getEntropyPool() not detecting corruption at i = %d\n", i);
			reportFailure();
			abort = true;
			break;
		}
		nonVolatileWrite(&one_byte, PARTITION_GLOBAL, (uint32_t)(ADDRESS_POOL_CHECKSUM + i), 1); // restore
	}
	if (!abort)
	{
		reportSuccess();
	}

	// With a known initial pool state and with a broken HWRNG, the random
	// number generator should produce the same output whether the pool is
	// stored in non-volatile memory or RAM.
	broken_hwrng = true;
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
	nonVolatileRead(&one_byte, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, 1);
	one_byte_corrupted = (uint8_t)(one_byte ^ 0xde);
	nonVolatileWrite(&one_byte_corrupted, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, 1);
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

	// Check that generateInsecureOTP() passwords are actually one-time.
	broken_hwrng = false;
	generateInsecureOTP(otp);
	generateInsecureOTP(otp2);
	if (!memcmp(otp, otp2, sizeof(otp)))
	{
		printf("generateInsecureOTP() passwords are not one-time\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that generateInsecureOTP() still works when the entropy
	// pool is corrupted.
	nonVolatileRead(&one_byte, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, 1);
	one_byte_corrupted = (uint8_t)(one_byte ^ 0xde);
	nonVolatileWrite(&one_byte_corrupted, PARTITION_GLOBAL, ADDRESS_POOL_CHECKSUM, 1);
	generateInsecureOTP(otp);
	generateInsecureOTP(otp2);
	if (!memcmp(otp, otp2, sizeof(otp)))
	{
		printf("generateInsecureOTP() doesn't work when entropy pool is borked\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	memset(pool_state, 42, ENTROPY_POOL_LENGTH);
	initialiseEntropyPool(pool_state);

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
		broken_hwrng = true;
	}
	else
	{
		broken_hwrng = false;
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

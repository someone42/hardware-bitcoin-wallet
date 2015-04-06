/** \file hmac_sha512.c
  *
  * \brief Calculates HMAC-SHA512 hashes.
  *
  * This file contains an implementation of SHA-512, as well as a wrapper
  * around the SHA-512 implementation which converts it into a keyed
  * message authentication code.
  *
  * The SHA-512 implementation is based on the formulae and pseudo-code in
  * FIPS PUB 180-4. The HMAC wrapper is based on the pseudo-code in
  * FIPS PUB 198.
  *
  * Since SHA-512 is based on 64 bit operations, the code in sha256.c and
  * hash.c cannot be re-used here, despite the essentially identical structure
  * of SHA-256 and SHA-512.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifdef TEST_HMAC_SHA512
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "test_helpers.h"
#endif // #ifdef TEST_HMAC_SHA512

#include "common.h"
#include "endian.h"
#include "hmac_sha512.h"

#if defined(AVR) && defined(__GNUC__)
#define LOOKUP_QWORD(x)		(my_pgm_read_qword_near(&(x)))
/** Read a 64 bit unsigned integer from AVR program memory.
  * AVR libc doesn't have a pgm_read_qword_near(), so one needs to be
  * implemented here.
  * \param address Near address of the integer.
  * \return The 64 bit unsigned integer.
  */
static uint64_t my_pgm_read_qword_near(const void *address)
{
	uint32_t l;
	uint32_t r;
	l = LOOKUP_DWORD(((uint32_t *)address)[0]);
	r = LOOKUP_DWORD(((uint32_t *)address)[1]);
	return (uint64_t)l | ((uint64_t)r << 32);
}
#else
/** Use this to access #PROGMEM lookup tables which have qword (64 bit)
  * entries. For example, normally you would use `r = qword_table[i];` but
  * for a #PROGMEM table, use `r = LOOKUP_QWORD(qword_table[i]);`. */
#define LOOKUP_QWORD(x)		(x)
#endif // #if defined(AVR) && defined(__GNUC__)

/** Container for 64 bit hash state. */
typedef struct HashState64Struct
{
	/** Where final hash value will be placed. */
	uint64_t h[8];
	/** Current index into HashState64#m, ranges from 0 to 15. */
	uint8_t index_m;
	/** Current byte within (64 bit) double word of HashState64#m. 0 = most
	  * significant byte, 7 = least significant byte. */
	uint8_t byte_position_m;
	/** 1024 bit message buffer. */
	uint64_t m[16];
	/** Total length of message; updated as bytes are written. */
	uint32_t message_length;
} HashState64;

/** Constants for SHA-512. See section 4.2.3 of FIPS PUB 180-4. */
static const uint64_t k[80] PROGMEM = {
0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

/** 64 bit rotate right.
  * \param x The integer to rotate right.
  * \param n Number of times to rotate right.
  * \return The rotated integer.
  */
static uint64_t rotateRight(const uint64_t x, const uint8_t n)
{
	return (x >> n) | (x << (64 - n));
}

/** Function defined as (4.8) in section 4.1.3 of FIPS PUB 180-4.
  * \param x First input integer.
  * \param y Second input integer.
  * \param z Third input integer.
  * \return Non-linear combination of x, y and z.
  */
static uint64_t ch(const uint64_t x, const uint64_t y, const uint64_t z)
{
	return (x & y) ^ ((~x) & z);
}

/** Function defined as (4.9) in section 4.1.3 of FIPS PUB 180-4.
  * \param x First input integer.
  * \param y Second input integer.
  * \param z Third input integer.
  * \return Non-linear combination of x, y and z.
  */
static uint64_t maj(const uint64_t x, const uint64_t y, const uint64_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

/** Function defined as (4.10) in section 4.1.3 of FIPS PUB 180-4.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint64_t bigSigma0(const uint64_t x)
{
	return rotateRight(x, 28) ^ rotateRight(x, 34) ^ rotateRight(x, 39);
}

/** Function defined as (4.11) in section 4.1.3 of FIPS PUB 180-4.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint64_t bigSigma1(const uint64_t x)
{
	return rotateRight(x, 14) ^ rotateRight(x, 18) ^ rotateRight(x, 41);
}

/** Function defined as (4.12) in section 4.1.3 of FIPS PUB 180-4.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint64_t littleSigma0(const uint64_t x)
{
	return rotateRight(x, 1) ^ rotateRight(x, 8) ^ (x >> 7);
}

/** Function defined as (4.13) in section 4.1.3 of FIPS PUB 180-4.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint64_t littleSigma1(const uint64_t x)
{
	return rotateRight(x, 19) ^ rotateRight(x, 61) ^ (x >> 6);
}

/** Update hash value based on the contents of a full message buffer.
  * This implements the pseudo-code in section 6.4.2 of FIPS PUB 180-4.
  * \param hs64 The 64 bit hash state to update.
  */
static void sha512Block(HashState64 *hs64)
{
	uint64_t a, b, c, d, e, f, g, h;
	uint64_t t1, t2;
	uint8_t t;
	uint64_t w[80];

	for (t = 0; t < 16; t++)
	{
		w[t] = hs64->m[t];
	}
	for (t = 16; t < 80; t++)
	{
		w[t] = littleSigma1(w[t - 2]) + w[t - 7] + littleSigma0(w[t - 15]) + w[t - 16];
	}
	a = hs64->h[0];
	b = hs64->h[1];
	c = hs64->h[2];
	d = hs64->h[3];
	e = hs64->h[4];
	f = hs64->h[5];
	g = hs64->h[6];
	h = hs64->h[7];
	for (t = 0; t < 80; t++)
	{
		t1 = h + bigSigma1(e) + ch(e, f, g) + LOOKUP_QWORD(k[t]) + w[t];
		t2 = bigSigma0(a) + maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}
	hs64->h[0] += a;
	hs64->h[1] += b;
	hs64->h[2] += c;
	hs64->h[3] += d;
	hs64->h[4] += e;
	hs64->h[5] += f;
	hs64->h[6] += g;
	hs64->h[7] += h;
}

/** Clear the message buffer.
  * \param hs64 The 64 bit hash state to act on.
  */
static void clearM(HashState64 *hs64)
{
	hs64->index_m = 0;
	hs64->byte_position_m = 0;
	memset(hs64->m, 0, sizeof(hs64->m));
}

/** Begin calculating hash for new message.
  * See section 5.3.5 of FIPS PUB 180-4.
  * \param hs64 The 64 bit hash state to initialise.
  */
static void sha512Begin(HashState64 *hs64)
{
	hs64->message_length = 0;
	hs64->h[0] = 0x6a09e667f3bcc908;
	hs64->h[1] = 0xbb67ae8584caa73b;
	hs64->h[2] = 0x3c6ef372fe94f82b;
	hs64->h[3] = 0xa54ff53a5f1d36f1;
	hs64->h[4] = 0x510e527fade682d1;
	hs64->h[5] = 0x9b05688c2b3e6c1f;
	hs64->h[6] = 0x1f83d9abfb41bd6b;
	hs64->h[7] = 0x5be0cd19137e2179;
	clearM(hs64);
}

/** Add one more byte to the message buffer and call sha512Block()
  * if the message buffer is full.
  * \param hs64 The 64 bit hash state to act on.
  * \param byte The byte to add.
  */
static void sha512WriteByte(HashState64 *hs64, const uint8_t byte)
{
	unsigned int pos;
	unsigned int shift_amount;

	hs64->message_length++;
	pos = (unsigned int)(7 - hs64->byte_position_m);
	shift_amount = pos << 3;
	hs64->m[hs64->index_m] |= ((uint64_t)byte << shift_amount);

	if (hs64->byte_position_m == 7)
	{
		hs64->index_m++;
	}
	hs64->byte_position_m = (uint8_t)((hs64->byte_position_m + 1) & 7);
	if (hs64->index_m == 16)
	{
		sha512Block(hs64);
		clearM(hs64);
	}
}

/** Finalise the hashing of a message by writing appropriate padding and
  * length bytes, then write the hash value into a byte array.
  * \param out A byte array where the final SHA-512 hash value will be written
  *            into. This must have space for #SHA512_HASH_LENGTH bytes.
  * \param hs64 The 64 bit hash state to act on.
  */
static void sha512Finish(uint8_t *out, HashState64 *hs64)
{
	uint32_t length_bits;
	uint8_t i;
	uint8_t buffer[16];

	// Subsequent calls to sha512WriteByte() will keep incrementing
	// message_length, so the calculation of length (in bits) must be
	// done before padding.
	length_bits = hs64->message_length << 3;

	// Pad using a 1 bit followed by enough 0 bits to get the message buffer
	// to exactly 896 bits full.
	sha512WriteByte(hs64, (uint8_t)0x80);
	while ((hs64->index_m != 14) || (hs64->byte_position_m != 0))
	{
		sha512WriteByte(hs64, 0);
	}
	// Write 128 bit length (in bits).
	memset(buffer, 0, 16);
	writeU32BigEndian(&(buffer[12]), length_bits);
	for (i = 0; i < 16; i++)
	{
		sha512WriteByte(hs64, buffer[i]);
	}
	for (i = 0; i < 8; i++)
	{
		writeU32BigEndian(&(out[i * 8]), (uint32_t)(hs64->h[i] >> 32));
		writeU32BigEndian(&(out[i * 8 + 4]), (uint32_t)hs64->h[i]);
	}
}

/** Calculate a 64 byte HMAC of an arbitrary message and key using SHA-512 as
  * the hash function.
  * The code in here is based on the description in section 5
  * ("HMAC SPECIFICATION") of FIPS PUB 198.
  * \param out A byte array where the HMAC-SHA512 hash value will be written.
  *            This must have space for #SHA512_HASH_LENGTH bytes.
  * \param key A byte array containing the key to use in the HMAC-SHA512
  *            calculation. The key can be of any length.
  * \param key_length The length, in bytes, of the key.
  * \param text A byte array containing the message to use in the HMAC-SHA512
  *             calculation. The message can be of any length.
  * \param text_length The length, in bytes, of the message.
  */
void hmacSha512(uint8_t *out, const uint8_t *key, const unsigned int key_length, const uint8_t *text, const unsigned int text_length)
{
	unsigned int i;
	uint8_t hash[SHA512_HASH_LENGTH];
	uint8_t padded_key[128];
	HashState64 hs64;

	// Determine key.
	memset(padded_key, 0, sizeof(padded_key));
	if (key_length <= sizeof(padded_key))
	{
		memcpy(padded_key, key, key_length);
	}
	else
	{
		sha512Begin(&hs64);
		for (i = 0; i < key_length; i++)
		{
			sha512WriteByte(&hs64, key[i]);
		}
		sha512Finish(padded_key, &hs64);
	}
	// Calculate hash = H((K_0 XOR ipad) || text).
	sha512Begin(&hs64);
	for (i = 0; i < sizeof(padded_key); i++)
	{
		sha512WriteByte(&hs64, (uint8_t)(padded_key[i] ^ 0x36));
	}
	for (i = 0; i < text_length; i++)
	{
		sha512WriteByte(&hs64, text[i]);
	}
	sha512Finish(hash, &hs64);
	// Calculate H((K_0 XOR opad) || hash).
	sha512Begin(&hs64);
	for (i = 0; i < sizeof(padded_key); i++)
	{
		sha512WriteByte(&hs64, (uint8_t)(padded_key[i] ^ 0x5c));
	}
	for (i = 0; i < sizeof(hash); i++)
	{
		sha512WriteByte(&hs64, hash[i]);
	}
	sha512Finish(out, &hs64);
}

#ifdef TEST_HMAC_SHA512

/** Run unit tests using test vectors from a file. The file is expected to be
  * in the same format as the NIST "HMAC Test Vectors", which can be obtained
  * from:
  * http://csrc.nist.gov/groups/STM/cavp/index.html#07
  * \param filename The name of the file containing the test vectors.
  */
static void scanTestVectors(char *filename)
{
	FILE *f;
	unsigned int i;
	unsigned int key_length;
	unsigned int message_length;
	unsigned int result_length;
	unsigned int compare_length;
	int test_number;
	int value;
	uint8_t *key;
	uint8_t *message;
	uint8_t *expected_result;
	uint8_t actual_result[SHA512_HASH_LENGTH];
	char buffer[2048];

	f = fopen(filename, "r");
	if (f == NULL)
	{
		printf("Could not open %s, please get it \
(HMAC Test Vectors) from \
http://csrc.nist.gov/groups/STM/cavp/index.html#07", filename);
		exit(1);
	}

	// Skip to past [L=64] (since we want the SHA-512 based tests).
	test_number = 1;
	while (!feof(f))
	{
		fgets(buffer, sizeof(buffer), f);
		if (!strcmp(buffer, "[L=64]\n"))
		{
			break;
		}
	}
	while (!feof(f))
	{
		skipWhiteSpace(f);
		skipLine(f); // skip "Count =" line
		// Get length of key and result.
		if (!fscanf(f, "Klen = %u", &key_length))
		{
			printf("fscanf error when reading key length\n");
			exit(1);
		}
		skipLine(f);
		if (!fscanf(f, "Tlen = %u", &result_length))
		{
			printf("fscanf error when reading result length\n");
			exit(1);
		}
		message_length = 128; // that seems to be the case
		// Get key.
		skipWhiteSpace(f);
		fgets(buffer, 7, f);
		if (strcmp(buffer, "Key = "))
		{
			printf("Parse error; expected \"Key = \"\n");
			exit(1);
		}
		key = malloc(key_length);
		for (i = 0; i < key_length; i++)
		{
			fscanf(f, "%02x", &value);
			key[i] = (uint8_t)value;
		}
		// Get message.
		skipWhiteSpace(f);
		fgets(buffer, 7, f);
		if (strcmp(buffer, "Msg = "))
		{
			printf("Parse error; expected \"Msg = \"\n");
			exit(1);
		}
		message = malloc(message_length);
		for (i = 0; i < message_length; i++)
		{
			fscanf(f, "%02x", &value);
			message[i] = (uint8_t)value;
		}
		// Get expected result.
		skipWhiteSpace(f);
		fgets(buffer, 7, f);
		if (strcmp(buffer, "Mac = "))
		{
			printf("Parse error; expected \"Mac = \"\n");
			exit(1);
		}
		expected_result = malloc(result_length);
		for (i = 0; i < result_length; i++)
		{
			fscanf(f, "%02x", &value);
			expected_result[i] = (uint8_t)value;
		}
		skipWhiteSpace(f);
		// Calculate HMAC-SHA512 and compare.
		hmacSha512(actual_result, key, key_length, message, message_length);
		compare_length = MIN(result_length, sizeof(actual_result));
		if (!memcmp(actual_result, expected_result, compare_length))
		{
			reportSuccess();
		}
		else
		{
			printf("Test number %d failed (key len = %u, result len = %u)\n", test_number, key_length, result_length);
			reportFailure();
		}
		free(key);
		free(message);
		free(expected_result);
		test_number++;
	}
	fclose(f);
}

int main(void)
{
	initTests(__FILE__);
	scanTestVectors("HMAC.rsp");
	finishTests();
	exit(0);
}

#endif // #ifdef TEST_HMAC_SHA512

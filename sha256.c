/** \file sha256.c
  *
  * \brief Calculates SHA-256 hashes.
  *
  * The code here is based on formulae and pseudo-code in FIPS PUB 180-3.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifdef TEST_SHA256
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "test_helpers.h"
#endif // #ifdef TEST_SHA256

#include "common.h"
#include "hash.h"
#include "sha256.h"

/** Constants for SHA-256. See section 4.2.2 of FIPS PUB 180-3. */
static const uint32_t k[64] PROGMEM = {
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/** Rotate right.
  * \param x The integer to rotate right.
  * \param n Number of times to rotate right.
  * \return The rotated integer.
  */
static uint32_t rotateRight(uint32_t x, uint8_t n)
{
	return (x >> n) | (x << (32 - n));
}

/** Function defined as (4.2) in section 4.1.2 of FIPS PUB 180-3.
  * \param x First input integer.
  * \param y Second input integer.
  * \param z Third input integer.
  * \return Non-linear combination of x, y and z.
  */
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ ((~x) & z);
}

/** Function defined as (4.3) in section 4.1.2 of FIPS PUB 180-3.
  * \param x First input integer.
  * \param y Second input integer.
  * \param z Third input integer.
  * \return Non-linear combination of x, y and z.
  */
static uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

/** Function defined as (4.4) in section 4.1.2 of FIPS PUB 180-3.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint32_t bigSigma0(uint32_t x)
{
	return rotateRight(x, 2) ^ rotateRight(x, 13) ^ rotateRight(x, 22);
}

/** Function defined as (4.5) in section 4.1.2 of FIPS PUB 180-3.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint32_t bigSigma1(uint32_t x)
{
	return rotateRight(x, 6) ^ rotateRight(x, 11) ^ rotateRight(x, 25);
}

/** Function defined as (4.6) in section 4.1.2 of FIPS PUB 180-3.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint32_t littleSigma0(uint32_t x)
{
	return rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3);
}

/** Function defined as (4.7) in section 4.1.2 of FIPS PUB 180-3.
  * \param x Input integer.
  * \return Transformed integer.
  */
static uint32_t littleSigma1(uint32_t x)
{
	return rotateRight(x, 17) ^ rotateRight(x, 19) ^ (x >> 10);
}

/** Update hash value based on the contents of a full message buffer.
  * This is an implementation of HashState#hashBlock().
  * This implements the pseudo-code in section 6.2.2 of FIPS PUB 180-3.
  * \param hs The hash state to update.
  */
static void sha256Block(HashState *hs)
{
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t t1, t2;
	uint8_t t;
	uint32_t w[64];

	for (t = 0; t < 16; t++)
	{
		w[t] = hs->m[t];
	}
	for (t = 16; t < 64; t++)
	{
		w[t] = littleSigma1(w[t - 2]) + w[t - 7] + littleSigma0(w[t - 15]) + w[t - 16];
	}
	a = hs->h[0];
	b = hs->h[1];
	c = hs->h[2];
	d = hs->h[3];
	e = hs->h[4];
	f = hs->h[5];
	g = hs->h[6];
	h = hs->h[7];
	for (t = 0; t < 64; t++)
	{
		t1 = h + bigSigma1(e) + ch(e, f, g) + LOOKUP_DWORD(k[t]) + w[t];
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
	hs->h[0] += a;
	hs->h[1] += b;
	hs->h[2] += c;
	hs->h[3] += d;
	hs->h[4] += e;
	hs->h[5] += f;
	hs->h[6] += g;
	hs->h[7] += h;
}

/** Begin calculating hash for new message.
  * See section 5.3.3 of FIPS PUB 180-3.
  * \param hs The hash state to initialise.
  */
void sha256Begin(HashState *hs)
{
	hs->message_length = 0;
	hs->hashBlock = sha256Block;
	hs->is_big_endian = true;
	hs->h[0] = 0x6a09e667;
	hs->h[1] = 0xbb67ae85;
	hs->h[2] = 0x3c6ef372;
	hs->h[3] = 0xa54ff53a;
	hs->h[4] = 0x510e527f;
	hs->h[5] = 0x9b05688c;
	hs->h[6] = 0x1f83d9ab;
	hs->h[7] = 0x5be0cd19;
	clearM(hs);
}

/** Add one more byte to the message buffer and call sha256Block()
  * if the message buffer is full.
  * \param hs The hash state to act on. The hash state must be one that has
  *           been initialised using sha256Begin() at some time in the past.
  * \param byte The byte to add.
  */
void sha256WriteByte(HashState *hs, uint8_t byte)
{
	hashWriteByte(hs, byte);
}

/** Finalise the hashing of a message by writing appropriate padding and
  * length bytes.
  * \param hs The hash state to act on. The hash state must be one that has
  *           been initialised using sha256Begin() at some time in the past.
  */
void sha256Finish(HashState *hs)
{
	hashFinish(hs);
}

/** Just like sha256Finish(), except this does a double SHA-256 hash. A
  * double SHA-256 hash is sometimes used in the Bitcoin protocol.
  * \param hs The hash state to act on. The hash state must be one that has
  *           been initialised using sha256Begin() at some time in the past.
  */
void sha256FinishDouble(HashState *hs)
{
	uint8_t temp[32];
	uint8_t i;

	sha256Finish(hs);
	writeHashToByteArray(temp, hs, true);
	sha256Begin(hs);
	for (i = 0; i < 32; i++)
	{
		sha256WriteByte(hs, temp[i]);
	}
	sha256Finish(hs);
}

#ifdef TEST_SHA256

/** Where hash value will be stored after sha256() returns. */
static uint32_t h[8];

/** Calculate SHA-256 hash of a message. The result is returned in #h.
  * \param message The message to calculate the hash of. This must be a byte
  *                array of the size specified by length.
  * \param length The length (in bytes) of the message.
  */
static void sha256(uint8_t *message, uint32_t length)
{
	uint32_t i;
	HashState hs;

	sha256Begin(&hs);
	for (i = 0; i < length; i++)
	{
		sha256WriteByte(&hs, message[i]);
	}
	sha256Finish(&hs);
	memcpy(h, hs.h, 32);
}

/** Run unit tests using test vectors from a file. The file is expected to be
  * in the same format as the NIST "SHA Test Vectors for Hashing Byte-Oriented
  * Messages", which can be obtained from:
  * http://csrc.nist.gov/groups/STM/cavp/index.html#03
  * \param filename The name of the file containing the test vectors.
  */
static void scanTestVectors(char *filename)
{
	FILE *f;
	unsigned int length;
	unsigned int bytes_to_read;
	unsigned int i;
	int value;
	int test_number;
	uint32_t compare_h[8];
	char buffer[16];
	uint8_t *message;

	f = fopen(filename, "r");
	if (f == NULL)
	{
		printf("Could not open %s, please get it \
(Byte-Oriented test vectors) from \
http://csrc.nist.gov/groups/STM/cavp/index.html#03", filename);
		exit(1);
	}

	test_number = 1;
	for (i = 0; i < 7; i++)
	{
		skipLine(f);
	}
	while (!feof(f))
	{
		// Get length of message.
		if (!fscanf(f, "Len = %u", &length))
		{
			printf("fscanf error when reading length\n");
			exit(1);
		}
		length = length >> 3;
		bytes_to_read = length;
		if (bytes_to_read == 0)
		{
			// Special case: for empty message, the message is still listed
			// as "Msg = 00".
			bytes_to_read = 1;
		}
		skipWhiteSpace(f);
		// Get message itself.
		fgets(buffer, 7, f);
		if (strcmp(buffer, "Msg = "))
		{
			printf("Parse error; expected \"Msg = \"\n");
			exit(1);
		}
		message = malloc(bytes_to_read);
		for (i = 0; i < bytes_to_read; i++)
		{
			fscanf(f, "%02x", &value);
			message[i] = (uint8_t)value;
		}
		skipWhiteSpace(f);
		sha256(message, length);
		free(message);
		// Get expected message digest.
		fgets(buffer, 6, f);
		if (strcmp(buffer, "MD = "))
		{
			printf("Parse error; expected \"MD = \"\n");
			exit(1);
		}
		for (i = 0; i < 8; i++)
		{
			fscanf(f, "%08x", &value);
			compare_h[i] = (uint32_t)value;
		}
		skipWhiteSpace(f);
		if (!memcmp(h, compare_h, 32))
		{
			//printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
			reportSuccess();
		}
		else
		{
			printf("Test number %d (Len = %u) failed\n", test_number, length << 3);
			reportFailure();
		}
		test_number++;
	}
	fclose(f);
}

int main(void)
{
	initTests(__FILE__);
	scanTestVectors("SHA256ShortMsg.rsp");
	scanTestVectors("SHA256LongMsg.rsp");
	finishTests();
	exit(0);
}

#endif // #ifdef TEST_SHA256

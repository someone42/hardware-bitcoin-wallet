// ***********************************************************************
// sha256.c
// ***********************************************************************
//
// Containes functions which calculate the SHA-256 message digest ("hash")
// of an arbitrary byte-oriented message.
// The code here is based on formulae and pseudo-code in FIPS PUB 180-3.
//
// This file is licensed as described by the file LICENCE.

// Defining this will facilitate testing
//#define TEST

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#endif // #ifdef TEST

#include "common.h"
#include "hash.h"
#include "sha256.h"

static const u32 K[64] PROGMEM = {
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

static u32 ROTR(u32 x, u8 n)
{
	return (x >> n) | (x << (32 - n));
}

// Functions defined in section 4.1.2 of FIPS PUB 180-3

static u32 Ch(u32 x, u32 y, u32 z)
{
	return (x & y) ^ ((~x) & z);
}

static u32 Maj(u32 x, u32 y, u32 z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

static u32 SIGMA_0(u32 x)
{
	return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

static u32 SIGMA_1(u32 x)
{
	return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

static u32 sigma_0(u32 x)
{
	return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}

static u32 sigma_1(u32 x)
{
	return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}

// Update hash based on 512-bit block M
// Implements pseudo-code in section 6.2.2 of FIPS PUB 180-3
static void sha256_block(hash_state *hs)
{
	u32 a, b, c, d, e, f, g, h;
	u32 T1, T2;
	u8 t;
	u32 W[64];

	for (t = 0; t < 16; t++)
	{
		W[t] = hs->M[t];
	}
	for (t = 16; t < 64; t++)
	{
		W[t] = sigma_1(W[t - 2]) + W[t - 7] + sigma_0(W[t - 15]) + W[t - 16];
	}
	a = hs->H[0];
	b = hs->H[1];
	c = hs->H[2];
	d = hs->H[3];
	e = hs->H[4];
	f = hs->H[5];
	g = hs->H[6];
	h = hs->H[7];
	for (t = 0; t < 64; t++)
	{
		T1 = h + SIGMA_1(e) + Ch(e, f, g) + LOOKUP_DWORD(&(K[t])) + W[t];
		T2 = SIGMA_0(a) + Maj(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}
	hs->H[0] += a;
	hs->H[1] += b;
	hs->H[2] += c;
	hs->H[3] += d;
	hs->H[4] += e;
	hs->H[5] += f;
	hs->H[6] += g;
	hs->H[7] += h;
}

// Begin calculating hash for new message
// See section 5.3.3 of FIPS PUB 180-3
void sha256_begin(hash_state *hs)
{
	hs->messagelength = 0;
	hs->hash_block = sha256_block;
	hs->isbigendian = 1;
	hs->H[0] = 0x6a09e667;
	hs->H[1] = 0xbb67ae85;
	hs->H[2] = 0x3c6ef372;
	hs->H[3] = 0xa54ff53a;
	hs->H[4] = 0x510e527f;
	hs->H[5] = 0x9b05688c;
	hs->H[6] = 0x1f83d9ab;
	hs->H[7] = 0x5be0cd19;
	clearM(hs);
}

// Send one more byte to be hashed.
void sha256_writebyte(hash_state *hs, u8 byte)
{
	hash_writebyte(hs, byte);
}

// Finish off hashing message (write padding and length) and calculate
// final hash.
void sha256_finish(hash_state *hs)
{
	hash_finish(hs);
}

// Just like sha256_finish(), except this does a double SHA-256 hash.
void sha256_finishdouble(hash_state *hs)
{
	u8 temp[32];
	u8 i;

	sha256_finish(hs);
	convertHtobytearray(temp, hs, 1);
	sha256_begin(hs);
	for (i = 0; i < 32; i++)
	{
		sha256_writebyte(hs, temp[i]);
	}
	sha256_finish(hs);
}

#ifdef TEST

static int succeeded;
static int failed;

static u32 H[8];

// Result is returned in H.
static void sha256(u8 *message, u32 length)
{
	u32 i;
	hash_state hs;

	sha256_begin(&hs);
	for (i = 0; i < length; i++)
	{
		sha256_writebyte(&hs, message[i]);
	}
	sha256_finish(&hs);
	for (i = 0; i < 8; i++)
	{
		H[i] = hs.H[i];
	}
}

static void skipwhitespace(FILE *f)
{
	int onechar;
	do
	{
		onechar = fgetc(f);
	} while ((onechar == ' ') || (onechar == '\t') || (onechar == '\n') || (onechar == '\r'));
	ungetc(onechar, f);
}

static void skipline(FILE *f)
{
	int onechar;
	do
	{
		onechar = fgetc(f);
	} while (onechar != '\n');
}

static void scantestvectors(char *filename)
{
	FILE *f;
	int length;
	int bytestoread;
	int i;
	int value;
	int testnumber;
	u32 compareH[8];
	char buffer[16];
	u8 *message;

	f = fopen(filename, "r");
	if (f == NULL)
	{
		printf("Could not open %s, please get it \
(Byte-Oriented test vectors) from \
http://csrc.nist.gov/groups/STM/cavp/index.html#03", filename);
		exit(1);
	}

	testnumber = 1;
	for (i = 0; i < 7; i++)
	{
		skipline(f);
	}
	while (!feof(f))
	{
		// Get length of message
		if (!fscanf(f, "Len = %d", &length))
		{
			printf("fscanf error when reading length\n");
			exit(1);
		}
		length = length >> 3;
		bytestoread = length;
		if (bytestoread == 0)
		{
			// Special case: for empty message, the message is still listed
			// as "Msg = 00"
			bytestoread = 1;
		}
		skipwhitespace(f);
		// Get message itself
		fgets(buffer, 7, f);
		if (strcmp(buffer, "Msg = "))
		{
			printf("Parse error; expected \"Msg = \"\n");
			exit(1);
		}
		message = malloc(bytestoread);
		for (i = 0; i < bytestoread; i++)
		{
			fscanf(f, "%02x", &value);
			message[i] = (u8)value;
		}
		skipwhitespace(f);
		sha256(message, length);
		free(message);
		// Get expected message digest
		fgets(buffer, 6, f);
		if (strcmp(buffer, "MD = "))
		{
			printf("Parse error; expected \"MD = \"\n");
			exit(1);
		}
		for (i = 0; i < 8; i++)
		{
			fscanf(f, "%08x", &value);
			compareH[i] = (u32)value;
		}
		skipwhitespace(f);
		if ((H[0] == compareH[0]) && (H[1] == compareH[1])
			&& (H[2] == compareH[2]) && (H[3] == compareH[3])
			&& (H[4] == compareH[4]) && (H[5] == compareH[5])
			&& (H[6] == compareH[6]) && (H[7] == compareH[7]))
		{
			//printf("%08x%08x%08x%08x%08x%08x%08x%08x\n", H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
			succeeded++;
		}
		else
		{
			printf("Test number %d (Len = %d) failed\n", testnumber, length << 3);
			failed++;
		}
		testnumber++;
	}
	fclose(f);
}

int main(void)
{
	succeeded = 0;
	failed = 0;
	scantestvectors("SHA256ShortMsg.rsp");
	scantestvectors("SHA256LongMsg.rsp");
	printf("Tests which succeeded: %d\n", succeeded);
	printf("Tests which failed: %d\n", failed);
	exit(0);
}

#endif // #ifdef TEST

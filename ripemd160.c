// ***********************************************************************
// ripemd160.c
// ***********************************************************************
//
// Containes functions which calculate the RIPEMD-160 message digest ("hash")
// of an arbitrary byte-oriented message.
// The code here is based on the paper: "RIPEMD-160: A strengthened
// version of RIPEMD" by Hans Dobbertin, Antoon Bosselaers and Bart Preneel,
// obtained from
// http://homes.esat.kuleuven.be/~cosicart/pdf/AB-9601/AB-9601.pdf
// on 30-August-2011.
// All references in source comments to "the paper" refer to that.
//
// This file is licensed as described by the file LICENCE.

// Defining this will facilitate testing
//#define TEST

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#endif // #ifdef TEST

#if defined(AVR) && defined(__GNUC__)
#include <avr/io.h>
#include <avr/pgmspace.h>
#define LOOKUP_BYTE(x)		(pgm_read_byte_near(x))
#else
#define PROGMEM
#define LOOKUP_BYTE(x)		(*(x))
#endif // #if defined(AVR) && defined(__GNUC__)

#include "common.h"
#include "hash.h"
#include "ripemd160.h"

// Selection of message word for main rounds.
static u8 r1[80] PROGMEM = {
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};

// Selection of message word for parallel rounds.
static u8 r2[80] PROGMEM = {
5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};

// Amount of rotate left for main rounds.
static u8 s1[80] PROGMEM = {
11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};

// Amount of rotate left for parallel rounds.
static u8 s2[80] PROGMEM = {
8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};

// Cyclic shift left (rotate left).
static u32 rol(u32 x, u8 n)
{
	return (x << n) | (x >> (32 - n));
}

// Five non-linear at bit level functions.
static u32 f0(u32 x, u32 y, u32 z)
{
	return x ^ y ^ z;
}

static u32 f1(u32 x, u32 y, u32 z)
{
	return (x & y) | (~x & z);
}

static u32 f2(u32 x, u32 y, u32 z)
{
	return (x | ~y) ^ z;
}

static u32 f3(u32 x, u32 y, u32 z)
{
	return (x & z) | (y & ~z);
}

static u32 f4(u32 x, u32 y, u32 z)
{
	return x ^ (y | ~z);
}

// Update hash based on 512-bit block M.
static void ripemd160_block(hash_state *hs)
{
	// 1 = unprimed, 2 = primed.
	// A to E and T are the variables used in the pseudo-code of Appendix A
	// of the paper.
	// K is the "added constant" for that round.
	// R is the return value of the relevant non-linear at bit level
	// function.
	u32 A1, B1, C1, D1, E1;
	u32 A2, B2, C2, D2, E2;
	u32 T;
	u32 K1, K2, R1, R2;
	u8 j;
	u8 fnselector;

	A1 = hs->H[0];
	A2 = A1;
	B1 = hs->H[1];
	B2 = B1;
	C1 = hs->H[2];
	C2 = C1;
	D1 = hs->H[3];
	D2 = D1;
	E1 = hs->H[4];
	E2 = E1;
	for (j = 0; j < 80; j++)
	{
		fnselector = (u8)(j >> 4);
		switch(fnselector)
		{
		case 0:
			R1 = f0(B1, C1, D1);
			R2 = f4(B2, C2, D2);
			K1 = 0x00000000;
			K2 = 0x50a28be6;
			break;
		case 1:
			R1 = f1(B1, C1, D1);
			R2 = f3(B2, C2, D2);
			K1 = 0x5a827999;
			K2 = 0x5c4dd124;
			break;
		case 2:
			R1 = f2(B1, C1, D1);
			R2 = f2(B2, C2, D2);
			K1 = 0x6ed9eba1;
			K2 = 0x6d703ef3;
			break;
		case 3:
			R1 = f3(B1, C1, D1);
			R2 = f1(B2, C2, D2);
			K1 = 0x8f1bbcdc;
			K2 = 0x7a6d76e9;
			break;
		default:
			R1 = f4(B1, C1, D1);
			R2 = f0(B2, C2, D2);
			K1 = 0xa953fd4e;
			K2 = 0x00000000;
			break;
		}
		T = rol(A1 + R1 + hs->M[LOOKUP_BYTE(&(r1[j]))] + K1, LOOKUP_BYTE(&(s1[j]))) + E1;
		A1 = E1;
		E1 = D1;
		D1 = rol(C1, 10);
		C1 = B1;
		B1 = T;
		T = rol(A2 + R2 + hs->M[LOOKUP_BYTE(&(r2[j]))] + K2, LOOKUP_BYTE(&(s2[j]))) + E2;
		A2 = E2;
		E2 = D2;
		D2 = rol(C2, 10);
		C2 = B2;
		B2 = T;
	}
	T = hs->H[1] + C1 + D2;
	hs->H[1] = hs->H[2] + D1 + E2;
	hs->H[2] = hs->H[3] + E1 + A2;
	hs->H[3] = hs->H[4] + A1 + B2;
	hs->H[4] = hs->H[0] + B1 + C2;
	hs->H[0] = T;
}

// Begin calculating hash for new message.
void ripemd160_begin(hash_state *hs)
{
	hs->messagelength = 0;
	hs->hash_block = ripemd160_block;
	hs->isbigendian = 0;
	hs->H[0] = 0x67452301;
	hs->H[1] = 0xefcdab89;
	hs->H[2] = 0x98badcfe;
	hs->H[3] = 0x10325476;
	hs->H[4] = 0xc3d2e1f0;
	clearM(hs);
}

// Send one more byte to be hashed.
void ripemd160_writebyte(hash_state *hs, u8 byte)
{
	hash_writebyte(hs, byte);
}

// Finish off hashing message (write padding and length) and calculate
// final hash.
void ripemd160_finish(hash_state *hs)
{
	hash_finish(hs);
}

#ifdef TEST

static int succeeded;
static int failed;

static u32 H[5];

// Result is returned in H.
static void ripemd160(u8 *message, u32 length)
{
	u32 i;
	hash_state hs;

	ripemd160_begin(&hs);
	for (i = 0; i < length; i++)
	{
		ripemd160_writebyte(&hs, message[i]);
	}
	ripemd160_finish(&hs);
	for (i = 0; i < 5; i++)
	{
		H[i] = hs.H[i];
	}
}

// All the tests (including the million "a" test) are from Appendix B of the
// paper.
#define NUMTESTS 8

static const char *teststrings[NUMTESTS] = {
"",
"a",
"abc",
"message digest",
"abcdefghijklmnopqrstuvwxyz",
"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
"12345678901234567890123456789012345678901234567890123456789012345678901234567890"};

static const u32 testhashes[5 * NUMTESTS] = {
0x9c1185a5, 0xc5e9fc54, 0x61280897, 0x7ee8f548, 0xb2258d31,
0x0bdc9d2d, 0x256b3ee9, 0xdaae347b, 0xe6f4dc83, 0x5a467ffe,
0x8eb208f7, 0xe05d987a, 0x9b044a8e, 0x98c6b087, 0xf15a0bfc,
0x5d0689ef, 0x49d2fae5, 0x72b881b1, 0x23a85ffa, 0x21595f36,
0xf71c2710, 0x9c692c1b, 0x56bbdceb, 0x5b9d2865, 0xb3708dbc,
0x12a05338, 0x4a9c0c88, 0xe405a06c, 0x27dcf49a, 0xda62eb2b,
0xb0e20b6e, 0x31166402, 0x86ed3a87, 0xa5713079, 0xb21f5189,
0x9b752e45, 0x573d4b39, 0xf4dbd332, 0x3cab82bf, 0x63326bfb};

int main(void)
{
	int i;
	char *str;
	u32 *compareH;

	succeeded = 0;
	failed = 0;
	for (i = 0; i < NUMTESTS; i++)
	{
		str = (char *)teststrings[i];
		ripemd160((u8 *)str, strlen(str));
		compareH = (u32 *)&(testhashes[i * 5]);
		if ((H[0] == compareH[0]) && (H[1] == compareH[1])
			&& (H[2] == compareH[2]) && (H[3] == compareH[3])
			&& (H[4] == compareH[4]))
		{
			//printf("%08x%08x%08x%08x%08x\n", H[0], H[1], H[2], H[3], H[4]);
			succeeded++;
		}
		else
		{
			printf("Test number %d failed\n", i + 1);
			printf("String: %s\n", str);
			failed++;
		}
	}
	// Million "a" test
	str = malloc(1000000);
	memset(str, 'a', 1000000);
	ripemd160((u8 *)str, 1000000);
	free(str);
	if ((H[0] == 0x52783243) && (H[1] == 0xc1697bdb)
		&& (H[2] == 0xe16d37f9) && (H[3] == 0x7f68f083)
		&& (H[4] == 0x25dc1528))
	{
		//printf("%08x%08x%08x%08x%08x\n", H[0], H[1], H[2], H[3], H[4]);
		succeeded++;
	}
	else
	{
		printf("Million \"a\" test failed\n");
		failed++;
	}
	printf("Tests which succeeded: %d\n", succeeded);
	printf("Tests which failed: %d\n", failed);
	exit(0);
}

#endif

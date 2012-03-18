// ***********************************************************************
// bignum256.c
// ***********************************************************************
//
// Containes functions which perform modular arithmetic operations on
// 256-bit wide numbers. These include: addition, subtraction, multiplication,
// and inversion.
// All computation functions have been written in a way so that their
// execution time is independent of the data they are processing. However, the
// compiler may use optimisations which destroy this property; inspection of
// the generated assembly code is the only way to check. The advantage of
// data-independent timing is that implementations of cryptography based on
// this code should be more timing attack resistant. The main disadvantage is
// that the code is relatively inefficient.
// All functions here expect 256-bit numbers to be an array of 32 bytes, with
// the least significant byte first.
// To use the exported functions here, you must call bigsetfield() first to
// set field parameters. If you don't do this, you'll get a segfault!
//
// This file is licensed as described by the file LICENCE.

// Defining this will facilitate testing
// Testing requires the GNU Multi-Precision library (without nails)
//#define TEST

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <gmp.h>
#include "endian.h"
#endif // #ifdef TEST

#ifdef _DEBUG
#include <assert.h>
#endif // #ifdef _DEBUG

#include "common.h"
#include "bignum256.h"

// Field parameters: n is the prime modulus. compn is the 2s complement
// of n (with most significant zero bytes removed) and sizecompn is the
// size of compn. The smaller sizecompn is, the faster multiplication
// will be.
// n must be greater than 2 ^ 255. The least significant byte of n must
// be >= 2 (otherwise biginvert() will not work correctly).
static bignum256 n;
static bignum256 compn;
static u8 sizecompn;

// C specification says that all remaining initialisers will be 0.
static const u8 zero[32] = {0};

#ifdef TEST
static void bigprint(bignum256 number)
{
	u8 i;
	for (i = 31; i < 32; i--)
	{
		printf("%02x", number[i]);
	}
}
#endif // #ifdef TEST

// Returns BIGCMP_GREATER if op1 > op2, BIGCMP_EQUAL if they're equal and
// BIGCMP_LESS if op1 < op2.
// op1 may alias op2.
// This supports bignums with sizes other than 256 bits.
u8 bigcmp_varsize(u8 *op1, u8 *op2, u8 size)
{
	u8 i;
	u8 r;
	u8 cmp;

	r = BIGCMP_EQUAL;
	for (i = (u8)(size - 1); i < size; i--)
	{
		// The following code is a branch free way of doing:
		// if (r == BIGCMP_EQUAL)
		// {
		//     if (op1[i] > op2[i])
		//     {
		//         r = BIGCMP_GREATER;
		//     }
		// }
		// if (r == BIGCMP_EQUAL)
		// {
		//     if (op2[i] > op1[i])
		//     {
		//         r = BIGCMP_LESS;
		//     }
		// }
		// Note that it relies on BIGCMP_EQUAL having the value 0.
		// It inspired by the code at:
		// http://aggregate.ee.engr.uky.edu/MAGIC/#Integer%20Selection
		cmp = (u8)((((u16)((int)op2[i] - (int)op1[i])) >> 8) & BIGCMP_GREATER);
		r = (u8)(((((u16)(-(int)r)) >> 8) & (r ^ cmp)) ^ cmp);
		cmp = (u8)((((u16)((int)op1[i] - (int)op2[i])) >> 8) & BIGCMP_LESS);
		r = (u8)(((((u16)(-(int)r)) >> 8) & (r ^ cmp)) ^ cmp);
	}
	return r;
}

// Returns BIGCMP_GREATER if op1 > op2, BIGCMP_EQUAL if they're equal and
// BIGCMP_LESS if op1 < op2.
// op1 may alias op2.
u8 bigcmp(bignum256 op1, bignum256 op2)
{
	return bigcmp_varsize(op1, op2, 32);
}

// Returns 1 if op1 is zero, returns 0 otherwise.
// This supports bignums with sizes other than 256 bits.
u8 bigiszero_varsize(u8 *op1, u8 size)
{
	u8 i;
	u8 r;

	r = 0;
	for (i = 0; i < size; i++)
	{
		r |= op1[i];
	}
	// The following line does: "return r ? 0 : 1;"
	return (u8)((((u16)(-(int)r)) >> 8) + 1);
}

// Returns 1 if op1 is zero, returns 0 otherwise.
u8 bigiszero(bignum256 op1)
{
	return bigiszero_varsize(op1, 32);
}

// Set r to 0
void bigsetzero(bignum256 r)
{
	u8 i;
	for (i = 0; i < 32; i++)
	{
		r[i] = 0;
	}
}

// Assign op1 to r.
void bigassign(bignum256 r, bignum256 op1)
{
	u8 i;
	for (i = 0; i < 32; i++)
	{
		r[i] = op1[i];
	}
}

// Set field parameters n, compn and sizecompn. See comments above
// n/compn/sizecompn.
void bigsetfield(const u8 *in_n, const u8 *in_compn, const u8 in_sizecompn)
{
	n = (bignum256)in_n;
	compn = (bignum256)in_compn;
	sizecompn = (u8)in_sizecompn;
}

// Returns 1 if there's carry, 0 otherwise.
// r may alias op1 or op2. op1 may alias op2.
// opsize is the size (in bytes) of the operands and result.
static u8 bigadd_internal(u8 *r, u8 *op1, u8 *op2, u8 opsize)
{
	u16 partial;
	u8 carry;
	u8 i;

	carry = 0;
	for (i = 0; i < opsize; i++)
	{
		partial = (u16)((u16)op1[i] + (u16)op2[i] + (u16)carry);
		r[i] = (u8)partial;
		carry = (u8)(partial >> 8);
	}
	return carry;
}

// Subtract op2 from op1. Returns 1 if there's borrow, 0 otherwise.
// r may alias op1 or op2. op1 may alias op2.
// This supports bignums with sizes other than 256 bits.
u8 bigsubtract_varsize(u8 *r, u8 *op1, u8 *op2, u8 size)
{
	u16 partial;
	u8 borrow;
	u8 i;

	borrow = 0;
	for (i = 0; i < size; i++)
	{
		partial = (u16)((u16)op1[i] - (u16)op2[i] - (u16)borrow);
		r[i] = (u8)partial;
		borrow = (u8)((u8)(partial >> 8) & 1);
	}
	return borrow;
}

// Subtract op2 from op1. Returns 1 if there's borrow, 0 otherwise.
// r may alias op1 or op2. op1 may alias op2.
static u8 bigsubtract_internal(bignum256 r, bignum256 op1, bignum256 op2)
{
	return bigsubtract_varsize(r, op1, op2, 32);
}

// Computes op1 modulo n.
// r may alias op1.
void bigmod(bignum256 r, bignum256 op1)
{
	u8 cmp;
	u8 *lookup[2];

	// The following 2 lines do: cmp = "bigcmp(op1, n) == BIGCMP_LESS ? 1 : 0"
	cmp = (u8)(bigcmp(op1, n) ^ BIGCMP_LESS);
	cmp = (u8)((((u16)(-(int)cmp)) >> 8) + 1);
	lookup[0] = n;
	lookup[1] = (u8 *)zero;
	bigsubtract_internal(r, op1, lookup[cmp]);
}

// Computes op1 + op2 modulo n and places result into r.
// op1 must be < n and op2 must also be < n.
// r may alias op1 or op2. op1 may alias op2.
void bigadd(bignum256 r, bignum256 op1, bignum256 op2)
{
	u8 too_big;
	u8 cmp;
	u8 *lookup[2];

#ifdef _DEBUG
	assert(bigcmp(op1, n) == BIGCMP_LESS);
	assert(bigcmp(op2, n) == BIGCMP_LESS);
#endif // #ifdef _DEBUG
	too_big = bigadd_internal(r, op1, op2, 32);
	cmp = (u8)(bigcmp(r, n) ^ BIGCMP_LESS);
	cmp = (u8)((((u16)(-(int)cmp)) >> 8) & 1);
	too_big |= cmp;
	lookup[0] = (u8 *)zero;
	lookup[1] = n;
	bigsubtract_internal(r, r, lookup[too_big]);
}

// Computes op1 - op2 modulo n and places result into r.
// op1 must be < n and op2 must also be < n.
// r may alias op1 or op2. op1 may alias op2.
void bigsubtract(bignum256 r, bignum256 op1, bignum256 op2)
{
	u8 *lookup[2];
	u8 too_small;

#ifdef _DEBUG
	assert(bigcmp(op1, n) == BIGCMP_LESS);
	assert(bigcmp(op2, n) == BIGCMP_LESS);
#endif // #ifdef _DEBUG
	too_small = bigsubtract_internal(r, op1, op2);
	lookup[0] = (u8 *)zero;
	lookup[1] = n;
	bigadd_internal(r, r, lookup[too_small], 32);
}

// Computes op1 * op2 and places result into r. op1size is the size
// (in bytes) of op1 and op2size is the size (in bytes) of op2.
// r needs to be an array of (op1size + op2size) bytes (instead of the
// usual 32). r cannot alias op1 or op2. op1 may alias op2.
static void bigmultiply_internal(u8 *r, u8 *op1, u8 op1size, u8 *op2, u8 op2size)
{
	u8 partialop1;
	u8 locarry;
	u8 hicarry;
	u16 multiplyresult16;
	u8 multiplyresultlo8;
	u8 multiplyresulthi8;
	u16 partialsum;
	u8 i;
	u8 j;

	for (i = 0; i < (op1size + op2size); i++)
	{
		r[i] = 0;
	}
	for (i = 0; i < op1size; i++)
	{
		partialop1 = op1[i];
		hicarry = 0;
		for (j = 0; j < op2size; j++)
		{
			multiplyresult16 = (u16)((u16)partialop1 * (u16)op2[j]);
			multiplyresultlo8 = (u8)multiplyresult16;
			multiplyresulthi8 = (u8)(multiplyresult16 >> 8);
			partialsum = (u16)((u16)r[i + j] + (u16)multiplyresultlo8);
			r[i + j] = (u8)partialsum;
			locarry = (u8)(partialsum >> 8);
			partialsum = (u16)((u16)r[i + j + 1] + (u16)multiplyresulthi8 + (u16)locarry + (u16)hicarry);
			r[i + j + 1] = (u8)partialsum;
			hicarry = (u8)(partialsum >> 8);
		}
#ifdef _DEBUG
		assert(hicarry == 0);
#endif // #ifdef _DEBUG
	}
}

// Computes op1 * op2 modulo n and places result into r.
// r may alias op1 or op2. op1 may alias op2.
void bigmultiply(bignum256 r, bignum256 op1, bignum256 op2)
{
	u8 temp[64];
	u8 fullr[64];
	u8 i;
	u8 remaining;

	bigmultiply_internal(fullr, op1, 32, op2, 32);
	// The modular reduction is done by subtracting off some multiple of
	// n. The upper 256 bits of r are used as an estimate for that multiple.
	// As long as n is close to 2 ^ 256, this estimate should be very close.
	// However, since n < 2 ^ 256, the estimate will always be an
	// underestimate. That's okay, because the algorithm can be applied
	// repeatedly, until the upper 256 bits of r are zero.
	// remaining denotes the maximum number of possible non-zero bytes left in
	// the result.
	remaining = 64;
	while (remaining > 32)
	{
		for (i = 0; i < 64; i++)
		{
			temp[i] = 0;
		}
		// n should be equal to 2 ^ 256 - compn. Therefore, subtracting
		// off (upper 256 bits of r) * n is equivalent to setting the
		// upper 256 bits of r to 0 and adding (upper 256 bits of r) * compn.
		bigmultiply_internal(temp, compn, sizecompn, &(fullr[32]), (u8)(remaining - 32));
		for (i = 32; i < 64; i++)
		{
			fullr[i] = 0;
		}
		bigadd_internal(fullr, fullr, temp, remaining);
		// This update of the bound is only valid for remaining > 32.
		remaining = (u8)(remaining - 32 + sizecompn);
	}
	// The upper 256 bits of r should now be 0. But r could still be >= n.
	// As long as n > 2 ^ 255, at most one subtraction is
	// required to ensure that r < n.
	bigmod(fullr, fullr);
	bigassign(r, fullr);
}

// Compute the modular inverse of op1 (i. e. a number r such that r * op1 = 1
// modulo n).
// r may alias op1.
void biginvert(bignum256 r, bignum256 op1)
{
	u8 temp[32];
	u8 i;
	u8 j;
	u8 byteofnminus2;
	u8 bitofnminus2;
	u8 *lookup[2];

	// This uses Fermat's Little Theorem, of which an immediate corollary is:
	// a ^ (p - 2) = a ^ (-1) modulo n.
	// The Montgomery ladder method is used to perform the exponentiation.
	bigassign(temp, op1);
	bigsetzero(r);
	r[0] = 1;
	lookup[0] = r;
	lookup[1] = temp;
	for (i = 31; i < 32; i--)
	{
		byteofnminus2 = n[i];
		if (i == 0)
		{
			byteofnminus2 = (u8)(byteofnminus2 - 2);
		}
		for (j = 0; j < 8; j++)
		{
			bitofnminus2 = (u8)((byteofnminus2 & 0x80) >> 7);
			byteofnminus2 = (u8)(byteofnminus2 << 1);
			// The next two lines do the following:
			// if (bitofnminus2)
			// {
			//     bigmultiply(r, r, temp);
			//     bigmultiply(temp, temp, temp);
			// }
			// else
			// {
			//     bigmultiply(temp, r, temp);
			//     bigmultiply(r, r, r);
			// }
			bigmultiply(lookup[1 - bitofnminus2], r, temp);
			bigmultiply(lookup[bitofnminus2], lookup[bitofnminus2], lookup[bitofnminus2]);
		}
	}
}

#ifdef TEST

// Number of low edge cases (numbers near minimum) to test
#define LOW_EDGE_CASES		700
// Number of high edge cases (numbers near maximum) to test
#define HIGH_EDGE_CASES		700
// Number of "random" numbers to test
#define RANDOM_CASES		3000

#define TOTAL_CASES			(LOW_EDGE_CASES + HIGH_EDGE_CASES + RANDOM_CASES)

static u8 one[32] = {
0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// The prime number used to define the prime field for secp256k1
static const u8 secp256k1_p[32] = {
0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static const u8 secp256k1_compp[5] = {
0xd1, 0x03, 0x00, 0x00, 0x01};

// The order of the base point used in secp256k1
static const u8 secp256k1_n[32] = {
0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf,
0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static const u8 secp256k1_compn[17] = {
0xbf, 0xbe, 0xc9, 0x2f, 0x73, 0xa1, 0x2d, 0x40,
0xc4, 0x5f, 0xb7, 0x50, 0x19, 0x23, 0x51, 0x45,
0x01};

static u8 test_cases[TOTAL_CASES][32];

// Low edge cases will start from 0 and go up.
// High edge cases will start from max - 1 and go down.
// Random test cases will be within [0, max - 1].
static void generate_test_cases(const u8 *max)
{
	int testnum;
	int i;
	int j;
	u8 currenttest[32];

	bigassign(currenttest, (bignum256)zero);
	testnum = 0;
	for (i = 0; i < LOW_EDGE_CASES; i++)
	{
		bigassign(test_cases[testnum++], currenttest);
		bigadd_internal(currenttest, currenttest, one, 32);
	}
	bigassign(currenttest, (bignum256)max);
	bigsubtract_internal(currenttest, currenttest, one);
	for (i = 0; i < HIGH_EDGE_CASES; i++)
	{
		bigassign(test_cases[testnum++], currenttest);
		bigsubtract_internal(currenttest, currenttest, one);
	}
	for (i = 0; i < RANDOM_CASES; i++)
	{
		do
		{
			for (j = 0; j < 32; j++)
			{
				currenttest[j] = (u8)(rand() & 0xff);
			}
			if (bigiszero((bignum256)max))
			{
				// Special case; 2 ^ 256 is represented as 0 and every
				// representable 256-bit number is >= 0. Thus the test
				// below will always be true even though it should be
				// false every time (since every representable 256-bit
				// number is < 2 ^ 256).
				break;
			}
		} while (bigcmp(currenttest, (bignum256)max) != BIGCMP_LESS);
		bigassign(test_cases[testnum++], currenttest);
	}
#ifdef _DEBUG
	assert(testnum == TOTAL_CASES);
#endif // #ifdef _DEBUG
}

// Convert number from byte array format to GMP limb array
// format. n is the number of limbs in GMP limb array.
static void byte_to_mpn(mp_limb_t *out, bignum256 in, int n)
{
	int i;

	for (i = 0; i < n; i++)
	{
		out[i] = (mp_limb_t)read_u32_littleendian(&(in[i * 4]));
	}
}

// Convert number from GMP limb array format to byte array format.
// n is the number of limbs in GMP limb array.
static void mpn_to_byte(bignum256 out, mp_limb_t *in, int n)
{
	int i;

	for (i = 0; i < n; i++)
	{
		write_u32_littleendian(&(out[i * 4]), in[i]);
	}
}

int main(int argc, char **argv)
{
	int operation;
	int i;
	int j;
	int succeeded;
	int failed;
	u8 op1[32];
	u8 op2[32];
	u8 result[64];
	u8 result_compare[64];
	u8 returned;
	int result_size; // in number of GMP limbs
	int divisor_select;
	mp_limb_t mpn_op1[8];
	mp_limb_t mpn_op2[8];
	mp_limb_t mpn_result[16];
	mp_limb_t compare_returned;
	mp_limb_t mpn_divisor[8];
	mp_limb_t mpn_quotient[9];
	mp_limb_t mpn_remainder[8];

	// Reference argc and argv just to make certain compilers happy.
	if (argc == 2)
	{
		printf("%s\n", argv[1]);
	}

	if (sizeof(mp_limb_t) != 4)
	{
		printf("Please run tests on platform where sizeof(mp_limb_t) == 4");
		exit(1);
	}

	srand(42);
	succeeded = 0;
	failed = 0;

	// Test bigcmp, since many other functions rely on it.
	op1[0] = 10;
	op2[0] = 2;
	op1[1] = 5;
	op2[1] = 5;
	if (bigcmp_varsize(op1, op2, 2) != BIGCMP_GREATER)
	{
		printf("bigcmp doesn't recognise when op1 > op2\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	op1[0] = 1;
	if (bigcmp_varsize(op1, op2, 2) != BIGCMP_LESS)
	{
		printf("bigcmp doesn't recognise when op1 < op2\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	op1[0] = 2;
	if (bigcmp_varsize(op1, op2, 2) != BIGCMP_EQUAL)
	{
		printf("bigcmp doesn't recognise when op1 == op2\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	op1[0] = 255;
	op2[0] = 254;
	if (bigcmp_varsize(op1, op2, 2) != BIGCMP_GREATER)
	{
		printf("bigcmp doesn't recognise when op1 > op2, possibly a signed/unsigned thing\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	op1[0] = 254;
	op2[0] = 255;
	if (bigcmp_varsize(op1, op2, 2) != BIGCMP_LESS)
	{
		printf("bigcmp doesn't recognise when op1 < op2, possibly a signed/unsigned thing\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	op1[0] = 1;
	op2[0] = 2;
	op1[1] = 4;
	op2[1] = 3;
	if (bigcmp_varsize(op1, op2, 2) != BIGCMP_GREATER)
	{
		printf("bigcmp doesn't recognise when op1 > op2, possibly a endian thing\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	op1[0] = 2;
	op2[0] = 1;
	op1[1] = 3;
	op2[1] = 4;
	if (bigcmp_varsize(op1, op2, 2) != BIGCMP_LESS)
	{
		printf("bigcmp doesn't recognise when op1 < op2, possibly a endian thing\n");
		failed++;
	}
	else
	{
		succeeded++;
	}

	// Test internal functions, which don't do modular reduction (hence
	// max is 2 ^ 256).
	generate_test_cases(zero);
	for (operation = 0; operation < 3; operation++)
	{
		for (i = 0; i < TOTAL_CASES; i++)
		{
			bigassign(op1, test_cases[i]);
			for (j = 0; j < TOTAL_CASES; j++)
			{
				bigassign(op2, test_cases[j]);

				// Calculate result using functions in this file
				if (operation == 0)
				{
					returned = bigadd_internal(result, op1, op2, 32);
					result_size = 8;
				}
				else if (operation == 1)
				{
					returned = bigsubtract_internal(result, op1, op2);
					result_size = 8;
				}
				else
				{
					returned = 0;
					bigmultiply_internal(result, op1, 32, op2, 32);
					result_size = 16;
				}

				// Calculate result using GMP
				byte_to_mpn(mpn_op1, op1, 8);
				byte_to_mpn(mpn_op2, op2, 8);
				if (operation == 0)
				{
					compare_returned = mpn_add_n(mpn_result, mpn_op1, mpn_op2, 8);
				}
				else if (operation == 1)
				{
					compare_returned = mpn_sub_n(mpn_result, mpn_op1, mpn_op2, 8);
				}
				else
				{
					compare_returned = 0;
					mpn_mul_n(mpn_result, mpn_op1, mpn_op2, 8);
				}

				// Compare results
				mpn_to_byte(result_compare, mpn_result, result_size);
				if ((memcmp(result, result_compare, result_size * 4))
					|| (returned != compare_returned))
				{
					if (operation == 0)
					{
						printf("Test failed (internal addition)\n");
					}
					else if (operation == 1)
					{
						printf("Test failed (internal subtraction)\n");
					}
					else
					{
						printf("Test failed (internal multiplication)\n");
					}
					printf("op1: ");
					bigprint(op1);
					printf("\nop2: ");
					bigprint(op2);
					printf("\nExpected: ");
					if (result_size > 8)
					{
						bigprint(&(result_compare[32]));
					}
					bigprint(result_compare);
					printf("\nGot: ");
					if (result_size > 8)
					{
						bigprint(&(result[32]));
					}
					bigprint(result);
					printf("\n");
					printf("Expected return value: %d\n", (int)compare_returned);
					printf("Got return value: %d\n", (int)returned);
					failed++;
				}
				else
				{
					succeeded++;
				}
			} // for (j = 0; j < TOTAL_CASES; j++)
		} // for (i = 0; i < TOTAL_CASES; i++)
	} // for (operation = 0; operation < 3; operation++)

	// Test non-internal functions, which do modular reduction. The modular
	// reduction is tested against both p and n.
	for (divisor_select = 0; divisor_select < 2; divisor_select++)
	{
		if (divisor_select == 0)
		{
			generate_test_cases(secp256k1_p);
			byte_to_mpn(mpn_divisor, (bignum256)secp256k1_p, 8);
			bigsetfield(secp256k1_p, secp256k1_compp, sizeof(secp256k1_compp));
		}
		else
		{
			generate_test_cases(secp256k1_n);
			byte_to_mpn(mpn_divisor, (bignum256)secp256k1_n, 8);
			bigsetfield(secp256k1_n, secp256k1_compn, sizeof(secp256k1_compn));
		}
		for (operation = 0; operation < 4; operation++)
		{
			for (i = 0; i < TOTAL_CASES; i++)
			{
				bigassign(op1, test_cases[i]);
				if (operation != 3)
				{
					for (j = 0; j < TOTAL_CASES; j++)
					{
						bigassign(op2, test_cases[j]);

						// Calculate result using functions in this file
						if (operation == 0)
						{
							bigadd(result, op1, op2);
						}
						else if (operation == 1)
						{
							bigsubtract(result, op1, op2);
						}
						else
						{
							bigmultiply(result, op1, op2);
						}

						// Calculate result using GMP
						byte_to_mpn(mpn_op1, op1, 8);
						byte_to_mpn(mpn_op2, op2, 8);
						if (operation == 0)
						{
							compare_returned = mpn_add_n(mpn_result, mpn_op1, mpn_op2, 8);
							if (compare_returned)
							{
								mpn_result[8] = 1;
							}
							else
							{
								mpn_result[8] = 0;
							}
							result_size = 9;
						}
						else if (operation == 1)
						{
							compare_returned = mpn_sub_n(mpn_result, mpn_op1, mpn_op2, 8);
							if (compare_returned)
							{
								// Because the low-level functions in GMP
								// don't care about sign, the division below
								// won't work correctly if the subtraction
								// resulted in a negative number.
								// The workaround is to add the divisor (which
								// does not change mpn_result modulo the
								// dovisor) to make mpn_result positive.
								mpn_add_n(mpn_result, mpn_result, mpn_divisor, 8);
							}
							result_size = 8;
						}
						else
						{
							mpn_mul_n(mpn_result, mpn_op1, mpn_op2, 8);
							result_size = 16;
						}
						mpn_tdiv_qr(mpn_quotient, mpn_remainder, 0, mpn_result, result_size, mpn_divisor, 8);

						// Compare results
						// Now that we're doing modular arithmetic, the
						// results are always 256 bits (8 GMP limbs).
						mpn_to_byte(result_compare, mpn_remainder, 8);
						if (bigcmp(result, result_compare) != BIGCMP_EQUAL)
						{
							if (operation == 0)
							{
								printf("Test failed (modular addition)\n");
							}
							else if (operation == 1)
							{
								printf("Test failed (modular subtraction)\n");
							}
							else
							{
								printf("Test failed (modular multiplication)\n");
							}
							printf("divisor: ");
							if (divisor_select == 0)
							{
								bigprint((bignum256)secp256k1_p);
							}
							else
							{
								bigprint((bignum256)secp256k1_n);
							}
							printf("\nop1: ");
							bigprint(op1);
							printf("\nop2: ");
							bigprint(op2);
							printf("\nExpected: ");
							bigprint(result_compare);
							printf("\nGot: ");
							bigprint(result);
							printf("\n");
							failed++;
						}
						else
						{
							succeeded++;
						}
					} // for (j = 0; j < TOTAL_CASES; j++)
				} // if (operation != 3)
				else
				{
					if (!bigiszero(op1))
					{
						// Calculate result using functions in this file
						biginvert(result, op1);

						// The mpn_gcdext function in GMP is a bit of a pain
						// to use because it doesn't quite give the modular
						// inverse. However, there's another way to test
						// the modular inverse function. Assuming modular
						// multiplication is working, then result * op1
						// should be 1 by definition of the modular inverse.
						bigmultiply(result, result, op1);
						if (bigcmp(result, one) != BIGCMP_EQUAL)
						{
							printf("Test failed (modular inversion)\n");
							printf("divisor: ");
							if (divisor_select == 0)
							{
								bigprint((bignum256)secp256k1_p);
							}
							else
							{
								bigprint((bignum256)secp256k1_n);
							}
							printf("\nop1: ");
							bigprint(op1);
							printf("\nExpected inverse * op1 to be 1\n");
							printf("Got: ");
							bigprint(result);
							printf("\n");
							failed++;
						}
						else
						{
							succeeded++;
						}
					} // if (!bigiszero(op1))
				}
			} // for (i = 0; i < TOTAL_CASES; i++)
		} // for (operation = 0; operation < 4; operation++)
	}

	printf("Tests which succeeded: %d\n", succeeded);
	printf("Tests which failed: %d\n", failed);

	exit(0);
}

#endif // #ifdef TEST

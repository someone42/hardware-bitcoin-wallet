/** \file bignum256.c
  *
  * \brief Has functions which perform multi-precision modular arithmetic.
  *
  * Arithmetic operations supported include: addition, subtraction,
  * multiplication, and inversion (i.e. division). For all operations, there
  * is a version which operates under a prime finite field. For nearly all
  * operations, there is also a version which does not operate under a prime
  * finite field.
  *
  * All computation functions have been written in a way so that their
  * execution time is independent of the data they are processing. However,
  * the compiler may use optimisations which destroy this property; inspection
  * of the generated assembly code is the only way to check. The advantage of
  * data-independent timing is that implementations of cryptography based on
  * this code should be more timing attack resistant. The main disadvantage is
  * that the code is relatively inefficient.
  *
  * All functions here expect multi-precision numbers to be an array of bytes,
  * with the least significant byte first. For example, {0xff, 0x02, 0x06}
  * represents the number 393983. All numbers are unsigned.
  * Normally, functions in this file assume the array to have a size of 32
  * bytes (such functions will use the typedef #BigNum256), but some functions
  * accept variable-sized arrays.
  *
  * To use most of the exported functions here, you must call bigSetField()
  * first to set field parameters. If you don't do this, you'll get a
  * segfault! Functions which do not operate under a prime finite field (eg.
  * bigSubtractVariableSizeNoModulo() and bigCompare()) do not need
  * bigSetField() to be called first.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifdef TEST
#include <assert.h>
#endif // #ifdef TEST

#ifdef TEST_BIGNUM256
#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include "endian.h"
#include "test_helpers.h"
#endif // #ifdef TEST_BIGNUM256

#include "common.h"
#include "bignum256.h"

/** The prime modulus to operate under.
  * \warning This must be greater than 2 ^ 255.
  * \warning The least significant byte of this must be >= 2, otherwise
  *          bigInvert() will not work correctly.
  */
static BigNum256 n;
/** The 2s complement of #n, with most significant zero bytes removed. */
static uint8_t *complement_n;
/** The size of #complement_n, in number of bytes. */
static uint8_t size_complement_n;

/** Compare two multi-precision numbers of arbitrary size.
  * \param op1 One of the numbers to compare.
  * \param op2 The other number to compare. This may alias op1.
  * \param size The size of the multi-precision numbers op1 and op2, in number
  *             of bytes.
  * \return #BIGCMP_GREATER if op1 > op2, #BIGCMP_EQUAL if they're equal
  *         and #BIGCMP_LESS if op1 < op2.
  */
uint8_t bigCompareVariableSize(uint8_t *op1, uint8_t *op2, uint8_t size)
{
	uint8_t i;
	uint8_t r;
	uint8_t cmp;

	r = BIGCMP_EQUAL;
	for (i = (uint8_t)(size - 1); i < size; i--)
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
		cmp = (uint8_t)((((uint16_t)((int)op2[i] - (int)op1[i])) >> 8) & BIGCMP_GREATER);
		r = (uint8_t)(((((uint16_t)(-(int)r)) >> 8) & (r ^ cmp)) ^ cmp);
		cmp = (uint8_t)((((uint16_t)((int)op1[i] - (int)op2[i])) >> 8) & BIGCMP_LESS);
		r = (uint8_t)(((((uint16_t)(-(int)r)) >> 8) & (r ^ cmp)) ^ cmp);
	}
	return r;
}

/** Compare two 32 byte multi-precision numbers.
  * \param op1 One of the 32 byte numbers to compare.
  * \param op2 The other 32 byte number to compare. This may alias op1.
  * \return #BIGCMP_GREATER if op1 > op2, #BIGCMP_EQUAL if they're equal
  *         and #BIGCMP_LESS if op1 < op2.
  */
uint8_t bigCompare(BigNum256 op1, BigNum256 op2)
{
	return bigCompareVariableSize(op1, op2, 32);
}

/** Check if a multi-precision number of arbitrary size is equal to zero.
  * \param op1 The number to check.
  * \param size The size of the multi-precision number op1, in number of
  *             bytes.
  * \return 1 if op1 is zero, 0 if op1 is not zero.
  */
uint8_t bigIsZeroVariableSize(uint8_t *op1, uint8_t size)
{
	uint8_t i;
	uint8_t r;

	r = 0;
	for (i = 0; i < size; i++)
	{
		r |= op1[i];
	}
	// The following line does: "return r ? 0 : 1;".
	return (uint8_t)((((uint16_t)(-(int)r)) >> 8) + 1);
}

/** Check if a 32 byte multi-precision number is equal to zero.
  * \param op1 The 32 byte number to check.
  * \return 1 if op1 is zero, 0 if op1 is not zero.
  */
uint8_t bigIsZero(BigNum256 op1)
{
	return bigIsZeroVariableSize(op1, 32);
}

/** Set a 32 byte multi-precision number to zero.
  * \param r The 32 byte number to set to zero.
  */
void bigSetZero(BigNum256 r)
{
	memset(r, 0, 32);
}

/** Assign one 32 byte multi-precision number to another.
  * \param r The 32 byte number to assign to.
  * \param op1 The 32 byte number to read from.
  */
void bigAssign(BigNum256 r, BigNum256 op1)
{
	memcpy(r, op1, 32);
}

/** Swap endian representation of a 256 bit integer.
  * \param buffer An array of 32 bytes representing the integer to change.
  */
void swapEndian256(BigNum256 buffer)
{
	uint8_t i;
	uint8_t temp;

	for (i = 0; i < 16; i++)
	{
		temp = buffer[i];
		buffer[i] = buffer[31 - i];
		buffer[31 - i] = temp;
	}
}

/** Set prime finite field parameters. The arrays passed as parameters to
  * this function will never be written to, hence the const modifiers.
  * \param in_n See #n.
  * \param in_complement_n See #complement_n.
  * \param in_size_complement_n See #size_complement_n.
  * \warning There are some restrictions on what the parameters can be.
  *          See #n, #complement_n and #size_complement_n for more details.
  */
void bigSetField(const uint8_t *in_n, const uint8_t *in_complement_n, const uint8_t in_size_complement_n)
{
	n = (BigNum256)in_n;
	complement_n = (uint8_t *)in_complement_n;
	size_complement_n = (uint8_t)in_size_complement_n;
}

/** Add (r = op1 + op2) two multi-precision numbers of arbitrary size,
  * ignoring the current prime finite field. In other words, this does
  * multi-precision binary addition.
  * \param r The result will be written into here.
  * \param op1 The first operand to add. This may alias r.
  * \param op2 The second operand to add. This may alias r or op1.
  * \param op_size Size, in bytes, of the operands and the result.
  * \return 1 if carry occurred, 0 if no carry occurred.
  */
uint8_t bigAddVariableSizeNoModulo(uint8_t *r, uint8_t *op1, uint8_t *op2, uint8_t op_size)
{
	uint16_t partial;
	uint8_t carry;
	uint8_t i;

	carry = 0;
	for (i = 0; i < op_size; i++)
	{
		partial = (uint16_t)((uint16_t)op1[i] + (uint16_t)op2[i] + (uint16_t)carry);
		r[i] = (uint8_t)partial;
		carry = (uint8_t)(partial >> 8);
	}
	return carry;
}

/** Subtract (r = op1 - op2) two multi-precision numbers of arbitrary size,
  * ignoring the current prime finite field. In other words, this does
  * multi-precision binary subtraction.
  * \param r The result will be written into here.
  * \param op1 The operand to subtract from. This may alias r.
  * \param op2 The operand to subtract off op1. This may alias r or op1.
  * \param op_size Size, in bytes, of the operands and the result.
  * \return 1 if borrow occurred, 0 if no borrow occurred.
  */
uint8_t bigSubtractVariableSizeNoModulo(uint8_t *r, uint8_t *op1, uint8_t *op2, uint8_t op_size)
{
	uint16_t partial;
	uint8_t borrow;
	uint8_t i;

	borrow = 0;
	for (i = 0; i < op_size; i++)
	{
		partial = (uint16_t)((uint16_t)op1[i] - (uint16_t)op2[i] - (uint16_t)borrow);
		r[i] = (uint8_t)partial;
		borrow = (uint8_t)((uint8_t)(partial >> 8) & 1);
	}
	return borrow;
}

/** Subtract (r = op1 - op2) two 32 byte multi-precision numbers,
  * ignoring the current prime finite field. In other words, this does
  * multi-precision binary subtraction.
  * \param r The 32 byte result will be written into here.
  * \param op1 The 32 byte operand to subtract from. This may alias r.
  * \param op2 The 32 byte operand to subtract off op1. This may alias r or op1.
  * \return 1 if borrow occurred, 0 if no borrow occurred.
  */
uint8_t bigSubtractNoModulo(BigNum256 r, BigNum256 op1, BigNum256 op2)
{
	return bigSubtractVariableSizeNoModulo(r, op1, op2, 32);
}

/** Compute op1 modulo #n, where op1 is a 32 byte multi-precision number.
  * The "modulo" part makes it sound like this function does division
  * somewhere, but since #n is also a 32 byte multi-precision number, all
  * this function actually does is subtract #n off op1 if op1 is >= #n.
  * \param r The 32 byte result will be written into here.
  * \param op1 The 32 byte operand to apply the modulo to. This may alias r.
  */
void bigModulo(BigNum256 r, BigNum256 op1)
{
	uint8_t cmp;
	uint8_t *lookup[2];
	uint8_t zero[32];

	bigSetZero(zero);
	// The following 2 lines do: cmp = "bigCompare(op1, n) == BIGCMP_LESS ? 1 : 0".
	cmp = (uint8_t)(bigCompare(op1, n) ^ BIGCMP_LESS);
	cmp = (uint8_t)((((uint16_t)(-(int)cmp)) >> 8) + 1);
	lookup[0] = n;
	lookup[1] = zero;
	bigSubtractNoModulo(r, op1, lookup[cmp]);
}

/** Add (r = (op1 + op2) modulo #n) two 32 byte multi-precision numbers under
  * the current prime finite field.
  * \param r The 32 byte result will be written into here.
  * \param op1 The first 32 byte operand to add. This may alias r.
  * \param op2 The second 32 byte operand to add. This may alias r or op1.
  * \warning op1 and op2 must both be < #n.
  */
void bigAdd(BigNum256 r, BigNum256 op1, BigNum256 op2)
{
	uint8_t too_big;
	uint8_t cmp;
	uint8_t *lookup[2];
	uint8_t zero[32];

	bigSetZero(zero);
#ifdef TEST
	assert(bigCompare(op1, n) == BIGCMP_LESS);
	assert(bigCompare(op2, n) == BIGCMP_LESS);
#endif // #ifdef TEST
	too_big = bigAddVariableSizeNoModulo(r, op1, op2, 32);
	cmp = (uint8_t)(bigCompare(r, n) ^ BIGCMP_LESS);
	cmp = (uint8_t)((((uint16_t)(-(int)cmp)) >> 8) & 1);
	too_big |= cmp;
	lookup[0] = zero;
	lookup[1] = n;
	bigSubtractNoModulo(r, r, lookup[too_big]);
}

/** Subtract (r = (op1 - op2) modulo #n) two 32 byte multi-precision numbers
  * under the current prime finite field.
  * \param r The 32 byte result will be written into here.
  * \param op1 The 32 byte operand to subtract from. This may alias r.
  * \param op2 The 32 byte operand to sutract off op1. This may alias r or
  *            op1.
  * \warning op1 and op2 must both be < #n.
  */
void bigSubtract(BigNum256 r, BigNum256 op1, BigNum256 op2)
{
	uint8_t *lookup[2];
	uint8_t too_small;
	uint8_t zero[32];

	bigSetZero(zero);
#ifdef TEST
	assert(bigCompare(op1, n) == BIGCMP_LESS);
	assert(bigCompare(op2, n) == BIGCMP_LESS);
#endif // #ifdef TEST
	too_small = bigSubtractNoModulo(r, op1, op2);
	lookup[0] = zero;
	lookup[1] = n;
	bigAddVariableSizeNoModulo(r, r, lookup[too_small], 32);
}

/** Divide a 32 byte multi-precision number by 2, truncating if necessary.
  * \param r The 32 byte result will be written into here.
  * \param op1 The 32 byte operand to divide by 2. This may alias r.
  */
void bigShiftRightNoModulo(BigNum256 r, const BigNum256 op1)
{
	uint8_t i;
	uint8_t carry;
	uint8_t old_carry;

	bigAssign(r, op1);
	old_carry = 0;
	for (i = 31; i < 32; i--)
	{
		carry = (uint8_t)(r[i] & 1);
		r[i] = (uint8_t)((r[i] >> 1) | (old_carry << 7));
		old_carry = carry;
	}
}

#ifndef PLATFORM_SPECIFIC_BIGMULTIPLY

/** Multiplies (r = op1 x op2) two multi-precision numbers of arbitrary size,
  * ignoring the current prime finite field. In other words, this does
  * multi-precision binary multiplication.
  * \param r The result will be written into here. The size of the result (in
  *          number of bytes) will be op1_size + op2_size.
  * \param op1 The first operand to multiply. This cannot alias r.
  * \param op1_size The size, in number of bytes, of op1.
  * \param op2 The second operand to multiply. This cannot alias r, but it can
  *            alias op1.
  * \param op2_size The size, in number of bytes, of op2.
  * \warning This function is the speed bottleneck in an ECDSA signing
  *          operation. To speed up ECDSA signing, reimplement this in
  *          assembly and define PLATFORM_SPECIFIC_BIGMULTIPLY.
  */
void bigMultiplyVariableSizeNoModulo(uint8_t *r, uint8_t *op1, uint8_t op1_size, uint8_t *op2, uint8_t op2_size)
{
	uint8_t cached_op1;
	uint8_t low_carry;
	uint8_t high_carry;
	uint16_t multiply_result16;
	uint8_t multiply_result_low8;
	uint8_t multiply_result_high8;
	uint16_t partial_sum;
	uint8_t i;
	uint8_t j;

	memset(r, 0, (uint16_t)(op1_size + op2_size));
	// The multiplication algorithm here is what GMP calls the "schoolbook"
	// method. It's also sometimes referred to as "long multiplication". It's
	// the most straightforward method of multiplication.
	// Note that for the operand sizes this function typically deals with,
	// and with the platforms this code is intended to run on, the Karatsuba
	// algorithm isn't significantly better.
	for (i = 0; i < op1_size; i++)
	{
		cached_op1 = op1[i];
		high_carry = 0;
		for (j = 0; j < op2_size; j++)
		{
			multiply_result16 = (uint16_t)((uint16_t)cached_op1 * (uint16_t)op2[j]);
			multiply_result_low8 = (uint8_t)multiply_result16;
			multiply_result_high8 = (uint8_t)(multiply_result16 >> 8);
			partial_sum = (uint16_t)((uint16_t)r[i + j] + (uint16_t)multiply_result_low8);
			r[i + j] = (uint8_t)partial_sum;
			low_carry = (uint8_t)(partial_sum >> 8);
			partial_sum = (uint16_t)((uint16_t)r[i + j + 1] + (uint16_t)multiply_result_high8 + (uint16_t)low_carry + (uint16_t)high_carry);
			r[i + j + 1] = (uint8_t)partial_sum;
			high_carry = (uint8_t)(partial_sum >> 8);
		}
#ifdef TEST
		assert(high_carry == 0);
#endif // #ifdef TEST
	}
}

#endif // #ifndef PLATFORM_SPECIFIC_BIGMULTIPLY

/** Multiplies (r = (op1 x op2) modulo #n) two 32 byte multi-precision
  * numbers under the current prime finite field.
  * \param r The 32 byte result will be written into here.
  * \param op1 The first 32 byte operand to multiply. This may alias r.
  * \param op2 The second 32 byte operand to multiply. This may alias r or
  *            op1.
  */
void bigMultiply(BigNum256 r, BigNum256 op1, BigNum256 op2)
{
	uint8_t temp[64];
	uint8_t full_r[64];
	uint8_t remaining;

	bigMultiplyVariableSizeNoModulo(full_r, op1, 32, op2, 32);
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
		memset(temp, 0, 64);
		// n should be equal to 2 ^ 256 - complement_n. Therefore, subtracting
		// off (upper 256 bits of r) * n is equivalent to setting the
		// upper 256 bits of r to 0 and
		// adding (upper 256 bits of r) * complement_n.
		bigMultiplyVariableSizeNoModulo(\
			temp,
			complement_n, size_complement_n,
			&(full_r[32]), (uint8_t)(remaining - 32));
		memset(&(full_r[32]), 0, 32);
		bigAddVariableSizeNoModulo(full_r, full_r, temp, remaining);
		// This update of the bound is only valid for remaining > 32.
		remaining = (uint8_t)(remaining - 32 + size_complement_n);
	}
	// The upper 256 bits of r should now be 0. But r could still be >= n.
	// As long as n > 2 ^ 255, at most one subtraction is
	// required to ensure that r < n.
	bigModulo(full_r, full_r);
	bigAssign(r, full_r);
}


/** Compute the modular inverse of a 32 byte multi-precision number under
  * the current prime finite field (i.e. find r such that
  * (r x op1) modulo #n = 1).
  * \param r The 32 byte result will be written into here.
  * \param op1 The 32 byte operand to find the inverse of. This may alias r.
  */
void bigInvert(BigNum256 r, BigNum256 op1)
{
	uint8_t temp[32];
	uint8_t i;
	uint8_t j;
	uint8_t byte_of_n_minus_2;
	uint8_t bit_of_n_minus_2;
	uint8_t *lookup[2];

	// This uses Fermat's Little Theorem, of which an immediate corollary is:
	// a ^ (p - 2) = a ^ (-1) modulo n.
	// The Montgomery ladder method is used to perform the exponentiation.
	bigAssign(temp, op1);
	bigSetZero(r);
	r[0] = 1;
	lookup[0] = r;
	lookup[1] = temp;
	for (i = 31; i < 32; i--)
	{
		byte_of_n_minus_2 = n[i];
		if (i == 0)
		{
			byte_of_n_minus_2 = (uint8_t)(byte_of_n_minus_2 - 2);
		}
		for (j = 0; j < 8; j++)
		{
			bit_of_n_minus_2 = (uint8_t)((byte_of_n_minus_2 & 0x80) >> 7);
			byte_of_n_minus_2 = (uint8_t)(byte_of_n_minus_2 << 1);
			// The next two lines do the following:
			// if (bit_of_n_minus_2)
			// {
			//     bigMultiply(r, r, temp);
			//     bigMultiply(temp, temp, temp);
			// }
			// else
			// {
			//     bigMultiply(temp, r, temp);
			//     bigMultiply(r, r, r);
			// }
			bigMultiply(lookup[1 - bit_of_n_minus_2], r, temp);
			bigMultiply(lookup[bit_of_n_minus_2], lookup[bit_of_n_minus_2], lookup[bit_of_n_minus_2]);
		}
	}
}

#ifdef TEST_BIGNUM256

/** Number of low edge test numbers (numbers near minimum). */
#define LOW_EDGE_CASES		700
/** Number of high edge test numbers (numbers near maximum). */
#define HIGH_EDGE_CASES		700
/** Number of "random" test numbers. */
#define RANDOM_CASES		3000

/** The total number of test numbers. */
#define TOTAL_CASES			(LOW_EDGE_CASES + HIGH_EDGE_CASES + RANDOM_CASES)

/** 32 byte multi-precision representation of 0. */
static uint8_t zero[32] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** 32 byte multi-precision representation of 1. */
static uint8_t one[32] = {
0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** The prime number used to define the prime finite field for secp256k1. */
static uint8_t secp256k1_p[32] = {
0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/** 2s complement of #secp256k1_p. */
static const uint8_t secp256k1_complement_p[5] = {
0xd1, 0x03, 0x00, 0x00, 0x01};

/** The order of the base point used in secp256k1. */
static uint8_t secp256k1_n[32] = {
0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf,
0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/** 2s complement of #secp256k1_n. */
static const uint8_t secp256k1_complement_n[17] = {
0xbf, 0xbe, 0xc9, 0x2f, 0x73, 0xa1, 0x2d, 0x40,
0xc4, 0x5f, 0xb7, 0x50, 0x19, 0x23, 0x51, 0x45,
0x01};

/** Storage for test numbers. */
static uint8_t test_cases[TOTAL_CASES][32];

/** Generate test numbers according to:
  * - Low edge cases will start from 0 and go up.
  * - High edge cases will start from max - 1 and go down.
  * - Random test cases will be within [0, max - 1].
  * \param max The number of elements in the field, expressed as a 32 byte
  *            little-endian multi-precision integer. As a special case, all
  *            zeroes represents 2 ^ 256.
  */
static void generateTestCases(BigNum256 max)
{
	int test_num;
	int i;
	int j;
	uint8_t current_test[32];

	bigSetZero(current_test);
	test_num = 0;
	for (i = 0; i < LOW_EDGE_CASES; i++)
	{
		bigAssign(test_cases[test_num++], current_test);
		bigAddVariableSizeNoModulo(current_test, current_test, one, 32);
	}
	bigAssign(current_test, (BigNum256)max);
	bigSubtractNoModulo(current_test, current_test, one);
	for (i = 0; i < HIGH_EDGE_CASES; i++)
	{
		bigAssign(test_cases[test_num++], current_test);
		bigSubtractNoModulo(current_test, current_test, one);
	}
	for (i = 0; i < RANDOM_CASES; i++)
	{
		do
		{
			for (j = 0; j < 32; j++)
			{
				current_test[j] = (uint8_t)rand();
			}
			if (bigIsZero((BigNum256)max))
			{
				// Special case; 2 ^ 256 is represented as 0 and every
				// representable 256 bit number is >= 0. Thus the test
				// below will always be true even though it should be
				// false every time (since every representable 256 bit
				// number is < 2 ^ 256).
				break;
			}
		} while (bigCompare(current_test, (BigNum256)max) != BIGCMP_LESS);
		bigAssign(test_cases[test_num++], current_test);
	}
#ifdef TEST
	assert(test_num == TOTAL_CASES);
#endif // #ifdef TEST
}

/** Convert number from byte array format to GMP limb array format.
  * \param out Destination GMP limb array.
  * \param in Source little-endian byte array.
  * \param n The number of limbs in the GMP limb array.
  */
static void byteToMpn(mp_limb_t *out, BigNum256 in, int n)
{
	int i;

	for (i = 0; i < n; i++)
	{
		out[i] = (mp_limb_t)readU32LittleEndian(&(in[i * 4]));
	}
}

/** Convert number from GMP limb array format to byte array format.
  * \param out Destination little-endian byte array.
  * \param in Source GMP limb array.
  * \param n The number of limbs in the GMP limb array.
  */
static void mpnToByte(BigNum256 out, mp_limb_t *in, int n)
{
	int i;

	for (i = 0; i < n; i++)
	{
		writeU32LittleEndian(&(out[i * 4]), in[i]);
	}
}

int main(void)
{
	int operation;
	int i;
	int j;
	uint8_t op1[32];
	uint8_t op2[32];
	uint8_t result[64];
	uint8_t result_compare[64];
	uint8_t returned;
	int result_size; // in number of GMP limbs
	int divisor_select;
	mp_limb_t mpn_op1[8];
	mp_limb_t mpn_op2[8];
	mp_limb_t mpn_result[16];
	mp_limb_t compare_returned;
	mp_limb_t mpn_divisor[8];
	mp_limb_t mpn_quotient[9];
	mp_limb_t mpn_remainder[8];

	if (sizeof(mp_limb_t) != 4)
	{
		printf("Please run tests on platform where sizeof(mp_limb_t) == 4");
		exit(1);
	}

	initTests(__FILE__);

	srand(42);

	// Test bigCompareVariableSize(), since many other functions rely on it.
	op1[0] = 10;
	op2[0] = 2;
	op1[1] = 5;
	op2[1] = 5;
	if (bigCompareVariableSize(op1, op2, 2) != BIGCMP_GREATER)
	{
		printf("bigCompare doesn't recognise when op1 > op2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	op1[0] = 1;
	if (bigCompareVariableSize(op1, op2, 2) != BIGCMP_LESS)
	{
		printf("bigCompare doesn't recognise when op1 < op2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	op1[0] = 2;
	if (bigCompareVariableSize(op1, op2, 2) != BIGCMP_EQUAL)
	{
		printf("bigCompare doesn't recognise when op1 == op2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	op1[0] = 255;
	op2[0] = 254;
	if (bigCompareVariableSize(op1, op2, 2) != BIGCMP_GREATER)
	{
		printf("bigCompare doesn't recognise when op1 > op2, possibly a signed/unsigned thing\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	op1[0] = 254;
	op2[0] = 255;
	if (bigCompareVariableSize(op1, op2, 2) != BIGCMP_LESS)
	{
		printf("bigCompare doesn't recognise when op1 < op2, possibly a signed/unsigned thing\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	op1[0] = 1;
	op2[0] = 2;
	op1[1] = 4;
	op2[1] = 3;
	if (bigCompareVariableSize(op1, op2, 2) != BIGCMP_GREATER)
	{
		printf("bigCompare doesn't recognise when op1 > op2, possibly an endian thing\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	op1[0] = 2;
	op2[0] = 1;
	op1[1] = 3;
	op2[1] = 4;
	if (bigCompareVariableSize(op1, op2, 2) != BIGCMP_LESS)
	{
		printf("bigCompare doesn't recognise when op1 < op2, possibly a endian thing\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Test internal functions, which don't do modular reduction (hence
	// max is 2 ^ 256).
	generateTestCases(zero);
	for (operation = 0; operation < 3; operation++)
	{
		for (i = 0; i < TOTAL_CASES; i++)
		{
			bigAssign(op1, test_cases[i]);
			for (j = 0; j < TOTAL_CASES; j++)
			{
				bigAssign(op2, test_cases[j]);

				// Calculate result using functions in this file.
				if (operation == 0)
				{
					returned = bigAddVariableSizeNoModulo(result, op1, op2, 32);
					result_size = 8;
				}
				else if (operation == 1)
				{
					returned = bigSubtractNoModulo(result, op1, op2);
					result_size = 8;
				}
				else
				{
					returned = 0;
					bigMultiplyVariableSizeNoModulo(result, op1, 32, op2, 32);
					result_size = 16;
				}

				// Calculate result using GMP.
				byteToMpn(mpn_op1, op1, 8);
				byteToMpn(mpn_op2, op2, 8);
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

				// Compare results.
				mpnToByte(result_compare, mpn_result, result_size);
				if ((memcmp(result, result_compare, (size_t)(result_size * 4)))
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
					printLittleEndian32(op1);
					printf("\nop2: ");
					printLittleEndian32(op2);
					printf("\nExpected: ");
					if (result_size > 8)
					{
						printLittleEndian32(&(result_compare[32]));
					}
					printLittleEndian32(result_compare);
					printf("\nGot: ");
					if (result_size > 8)
					{
						printLittleEndian32(&(result[32]));
					}
					printLittleEndian32(result);
					printf("\n");
					printf("Expected return value: %d\n", (int)compare_returned);
					printf("Got return value: %d\n", (int)returned);
					reportFailure();
				}
				else
				{
					reportSuccess();
				}
			} // for (j = 0; j < TOTAL_CASES; j++)
		} // for (i = 0; i < TOTAL_CASES; i++)
	} // for (operation = 0; operation < 3; operation++)

	// Test bigShiftRightNoModulo().
	for (i = 0; i < TOTAL_CASES; i++)
	{
		bigAssign(op1, test_cases[i]);
		bigShiftRightNoModulo(result, op1);
		byteToMpn(mpn_op1, op1, 8);
		mpn_rshift(mpn_result, mpn_op1, 8, 1);
		mpnToByte(result_compare, mpn_result, 8);
		if (memcmp(result, result_compare, 32))
		{
			printf("Test failed (shift right)\n");
			printf("op1: ");
			printLittleEndian32(op1);
			printf("\nExpected: ");
			printLittleEndian32(result_compare);
			printf("\nGot: ");
			printLittleEndian32(result);
			printf("\n");
			reportFailure();
		}
		else
		{
			reportSuccess();
		}
	}

	// Test non-internal functions, which do modular reduction. The modular
	// reduction is tested against both p and n.
	for (divisor_select = 0; divisor_select < 2; divisor_select++)
	{
		if (divisor_select == 0)
		{
			generateTestCases(secp256k1_p);
			byteToMpn(mpn_divisor, (BigNum256)secp256k1_p, 8);
			bigSetField(secp256k1_p, secp256k1_complement_p, sizeof(secp256k1_complement_p));
		}
		else
		{
			generateTestCases(secp256k1_n);
			byteToMpn(mpn_divisor, (BigNum256)secp256k1_n, 8);
			bigSetField(secp256k1_n, secp256k1_complement_n, sizeof(secp256k1_complement_n));
		}
		for (operation = 0; operation < 4; operation++)
		{
			for (i = 0; i < TOTAL_CASES; i++)
			{
				bigAssign(op1, test_cases[i]);
				if (operation != 3)
				{
					for (j = 0; j < TOTAL_CASES; j++)
					{
						bigAssign(op2, test_cases[j]);

						// Calculate result using functions in this file.
						if (operation == 0)
						{
							bigAdd(result, op1, op2);
						}
						else if (operation == 1)
						{
							bigSubtract(result, op1, op2);
						}
						else
						{
							bigMultiply(result, op1, op2);
						}

						// Calculate result using GMP.
						byteToMpn(mpn_op1, op1, 8);
						byteToMpn(mpn_op2, op2, 8);
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

						// Compare results.
						// Now that we're doing modular arithmetic, the
						// results are always 256 bits (8 GMP limbs).
						mpnToByte(result_compare, mpn_remainder, 8);
						if (bigCompare(result, result_compare) != BIGCMP_EQUAL)
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
								printLittleEndian32((BigNum256)secp256k1_p);
							}
							else
							{
								printLittleEndian32((BigNum256)secp256k1_n);
							}
							printf("\nop1: ");
							printLittleEndian32(op1);
							printf("\nop2: ");
							printLittleEndian32(op2);
							printf("\nExpected: ");
							printLittleEndian32(result_compare);
							printf("\nGot: ");
							printLittleEndian32(result);
							printf("\n");
							reportFailure();
						}
						else
						{
							reportSuccess();
						}
					} // for (j = 0; j < TOTAL_CASES; j++)
				} // if (operation != 3)
				else
				{
					if (!bigIsZero(op1))
					{
						// Calculate result using functions in this file.
						bigInvert(result, op1);

						// The mpn_gcdext function in GMP is a bit of a pain
						// to use because it doesn't quite give the modular
						// inverse. However, there's another way to test
						// the modular inverse function. Assuming modular
						// multiplication is working, then result * op1
						// should be 1 by definition of the modular inverse.
						bigMultiply(result, result, op1);
						if (bigCompare(result, one) != BIGCMP_EQUAL)
						{
							printf("Test failed (modular inversion)\n");
							printf("divisor: ");
							if (divisor_select == 0)
							{
								printLittleEndian32((BigNum256)secp256k1_p);
							}
							else
							{
								printLittleEndian32((BigNum256)secp256k1_n);
							}
							printf("\nop1: ");
							printLittleEndian32(op1);
							printf("\nExpected inverse * op1 to be 1\n");
							printf("Got: ");
							printLittleEndian32(result);
							printf("\n");
							reportFailure();
						}
						else
						{
							reportSuccess();
						}
					} // if (!bigIsZero(op1))
				} // if (operation != 3) (else clause)
			} // for (i = 0; i < TOTAL_CASES; i++)
		} // for (operation = 0; operation < 4; operation++)
	}

	finishTests();

	exit(0);
}

#endif // #ifdef TEST_BIGNUM256

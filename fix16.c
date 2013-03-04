/** \file fix16.c
  *
  * \brief fix16.c from libfixmath.
  *
  * This file implements some fixed-point calculation primitives.
  *
  * This file was adapted from fix16.c and fix16_exp.c of libfixmath r78,
  * which can be obtained from
  * http://code.google.com/p/libfixmath/source/browse/trunk/libfixmath/.
  * The main modifications are:
  * - Removed code of unused functions.
  * - Changed overflow code to set #fix16_error_occurred instead of just
  *   returning #fix16_overflow.
  * - Moved fix16_log2() into fix16.c.
  * - Changed fix16_log2() to avoid division.
  *
  * The rest of the file was written mainly by the libfixmath contributors.
  * A list of contributors can be retrieved from
  * http://code.google.com/p/libfixmath/people/list.
  *
  * This file is licensed as described by the file LIBFIXMATH_LICENCE.
  */

#include "common.h"
#include "fix16.h"
#ifndef FIXMATH_NO_64BIT
#include "int64.h"
#endif

/** At the beginning of a series of computations, this will be set to false.
  * If it is set to true during the computations, then
  * something unexpected occurred (eg. arithmetic overflow) and the result
  * should be considered invalid.
  */
bool fix16_error_occurred;

/* Subtraction and addition with overflow detection.
*/
fix16_t fix16_add(fix16_t a, fix16_t b)
{
	// Use unsigned integers because overflow with signed integers is
	// an undefined operation (http://www.airs.com/blog/archives/120).
	uint32_t _a = a, _b = b;
	uint32_t sum = _a + _b;

#ifndef FIXMATH_NO_OVERFLOW
	// Overflow can only happen if sign of a == sign of b, and then
	// it causes sign of sum != sign of a.
	if (!((_a ^ _b) & 0x80000000) && ((_a ^ sum) & 0x80000000))
	{
		fix16_error_occurred = true;
		return fix16_overflow;
	}
#endif

	return sum;
}

fix16_t fix16_sub(fix16_t a, fix16_t b)
{
	uint32_t _a = a, _b = b;
	uint32_t diff = _a - _b;

#ifndef FIXMATH_NO_OVERFLOW
	// Overflow can only happen if sign of a != sign of b, and then
	// it causes sign of diff != sign of a.
	if (((_a ^ _b) & 0x80000000) && ((_a ^ diff) & 0x80000000))
	{
		fix16_error_occurred = true;
		return fix16_overflow;
	}
#endif

	return diff;
}

/* 64-bit implementation for fix16_mul. Fastest version for e.g. ARM Cortex M3.
 * Performs a 32*32 -> 64bit multiplication. The middle 32 bits are the result,
 * bottom 16 bits are used for rounding, and upper 16 bits are used for overflow
 * detection.
 */
 
#if !defined(FIXMATH_NO_64BIT) && !defined(FIXMATH_OPTIMIZE_8BIT)
fix16_t fix16_mul(fix16_t inArg0, fix16_t inArg1)
{
	int64_t product = (int64_t)inArg0 * inArg1;
	
	#ifndef FIXMATH_NO_OVERFLOW
	// The upper 17 bits should all be the same (the sign).
	uint32_t upper = (product >> 47);
	#endif
	
	if (product < 0)
	{
		#ifndef FIXMATH_NO_OVERFLOW
		if (~upper)
		{
			fix16_error_occurred = true;
			return fix16_overflow;
		}
		#endif
		
		#ifndef FIXMATH_NO_ROUNDING
		// This adjustment is required in order to round -1/2 correctly
		product--;
		#endif
	}
	else
	{
		#ifndef FIXMATH_NO_OVERFLOW
		if (upper)
		{
			fix16_error_occurred = true;
			return fix16_overflow;
		}
		#endif
	}
	
	#ifdef FIXMATH_NO_ROUNDING
	return product >> 16;
	#else
	fix16_t result = product >> 16;
	result += (product & 0x8000) >> 15;
	
	return result;
	#endif
}
#endif

/* 32-bit implementation of fix16_mul. Potentially fast on 16-bit processors,
 * and this is a relatively good compromise for compilers that do not support
 * uint64_t. Uses 16*16->32bit multiplications.
 */
#if defined(FIXMATH_NO_64BIT) && !defined(FIXMATH_OPTIMIZE_8BIT)
fix16_t fix16_mul(fix16_t inArg0, fix16_t inArg1)
{
	uint32_t product_lo_tmp;
	fix16_t result;
	// Each argument is divided to 16-bit parts.
	//					AB
	//			*	 CD
	// -----------
	//					BD	16 * 16 -> 32 bit products
	//				 CB
	//				 AD
	//				AC
	//			 |----| 64 bit product
	int32_t A = (inArg0 >> 16), C = (inArg1 >> 16);
	uint32_t B = (inArg0 & 0xFFFF), D = (inArg1 & 0xFFFF);
	
	int32_t AC = A*C;
	int32_t AD_CB = A*D + C*B;
	uint32_t BD = B*D;
	
	int32_t product_hi = AC + (AD_CB >> 16);
	
	// Handle carry from lower 32 bits to upper part of result.
	uint32_t ad_cb_temp = AD_CB << 16;
	uint32_t product_lo = BD + ad_cb_temp;
	if (product_lo < BD)
		product_hi++;
	
#ifndef FIXMATH_NO_OVERFLOW
	// The upper 17 bits should all be the same (the sign).
	if (product_hi >> 31 != product_hi >> 15)
	{
		fix16_error_occurred = true;
		return fix16_overflow;
	}
#endif
	
#ifdef FIXMATH_NO_ROUNDING
	return (product_hi << 16) | (product_lo >> 16);
#else
	// Subtracting 0x8000 (= 0.5) and then using signed right shift
	// achieves proper rounding to result-1, except in the corner
	// case of negative numbers and lowest word = 0x8000.
	// To handle that, we also have to subtract 1 for negative numbers.
	product_lo_tmp = product_lo;
	product_lo -= 0x8000;
	product_lo -= (uint32_t)product_hi >> 31;
	if (product_lo > product_lo_tmp)
		product_hi--;
	
	// Discard the lowest 16 bits. Note that this is not exactly the same
	// as dividing by 0x10000. For example if product = -1, result will
	// also be -1 and not 0. This is compensated by adding +1 to the result
	// and compensating this in turn in the rounding above.
	result = (product_hi << 16) | (product_lo >> 16);
	result += 1;
	return result;
#endif
}
#endif

/* 8-bit implementation of fix16_mul. Fastest on e.g. Atmel AVR.
 * Uses 8*8->16bit multiplications, and also skips any bytes that
 * are zero.
 */
#if defined(FIXMATH_OPTIMIZE_8BIT)
fix16_t fix16_mul(fix16_t inArg0, fix16_t inArg1)
{
	uint32_t _a = (inArg0 >= 0) ? inArg0 : (-inArg0);
	uint32_t _b = (inArg1 >= 0) ? inArg1 : (-inArg1);
	
	uint8_t va[4] = {_a, (_a >> 8), (_a >> 16), (_a >> 24)};
	uint8_t vb[4] = {_b, (_b >> 8), (_b >> 16), (_b >> 24)};
	
	uint32_t low = 0;
	uint32_t mid = 0;
	
	// Result column i depends on va[0..i] and vb[i..0]

	#ifndef FIXMATH_NO_OVERFLOW
	// i = 6
	if (va[3] && vb[3])
	{
		fix16_error_occurred = true;
		return fix16_overflow;
	}
	#endif
	
	// i = 5
	if (va[2] && vb[3]) mid += (uint16_t)va[2] * vb[3];
	if (va[3] && vb[2]) mid += (uint16_t)va[3] * vb[2];
	mid <<= 8;
	
	// i = 4
	if (va[1] && vb[3]) mid += (uint16_t)va[1] * vb[3];
	if (va[2] && vb[2]) mid += (uint16_t)va[2] * vb[2];
	if (va[3] && vb[1]) mid += (uint16_t)va[3] * vb[1];
	
	#ifndef FIXMATH_NO_OVERFLOW
	if (mid & 0xFF000000)
	{
		fix16_error_occurred = true;
		return fix16_overflow;
	}
	#endif
	mid <<= 8;
	
	// i = 3
	if (va[0] && vb[3]) mid += (uint16_t)va[0] * vb[3];
	if (va[1] && vb[2]) mid += (uint16_t)va[1] * vb[2];
	if (va[2] && vb[1]) mid += (uint16_t)va[2] * vb[1];
	if (va[3] && vb[0]) mid += (uint16_t)va[3] * vb[0];
	
	#ifndef FIXMATH_NO_OVERFLOW
	if (mid & 0xFF000000)
	{
		fix16_error_occurred = true;
		return fix16_overflow;
	}
	#endif
	mid <<= 8;
	
	// i = 2
	if (va[0] && vb[2]) mid += (uint16_t)va[0] * vb[2];
	if (va[1] && vb[1]) mid += (uint16_t)va[1] * vb[1];
	if (va[2] && vb[0]) mid += (uint16_t)va[2] * vb[0];		
	
	// i = 1
	if (va[0] && vb[1]) low += (uint16_t)va[0] * vb[1];
	if (va[1] && vb[0]) low += (uint16_t)va[1] * vb[0];
	low <<= 8;
	
	// i = 0
	if (va[0] && vb[0]) low += (uint16_t)va[0] * vb[0];
	
	#ifndef FIXMATH_NO_ROUNDING
	low += 0x8000;
	#endif
	mid += (low >> 16);
	
	#ifndef FIXMATH_NO_OVERFLOW
	if (mid & 0x80000000)
	{
		fix16_error_occurred = true;
		return fix16_overflow;
	}
	#endif
	
	fix16_t result = mid;
	
	/* Figure out the sign of result */
	if ((inArg0 >= 0) != (inArg1 >= 0))
	{
		result = -result;
	}
	
	return result;
}
#endif

/**
 * Divides x by 2 and returns the result, rounding if appropriate.
 */
static fix16_t fix16_rs(fix16_t x)
{
	#ifdef FIXMATH_NO_ROUNDING
	return (x >> 1);
	#else
	fix16_t y = (x >> 1) + (x & 1);
	return y;
	#endif
}

/**
 * Calculates the log base 2 of input.
 * Note that negative inputs are invalid! (will set #fix16_error_occurred,
 * since there are no exceptions)
 * 
 * i.e. 2 to the power output = input.
 * It's equivalent to the log or ln functions, except it uses base 2 instead
 * of base 10 or base e. This is useful as binary things like this are easy
 * for binary devices, like modern microprocessros, to calculate.
 * 
 * This can be used as a helper function to calculate powers with non-integer
 * powers and/or bases.
 */
fix16_t fix16_log2(fix16_t x)
{
	fix16_t result = 0;
	unsigned int i;

	// Note that a negative x gives a non-real result.
	// If x == 0, the limit of log2(x)  as x -> 0 = -infinity.
	// log2(-ve) gives a complex result.
	if (x <= 0)
	{
		fix16_error_occurred = true;
		return fix16_overflow;
	}

	while (x >= fix16_from_int(2))
	{
		result++;
		x = fix16_rs(x);
	}
	while (x < fix16_one)
	{
		result--;
		x <<= 1;
	}

	if (x == 0) return (result << 16);

	for (i = 16; i > 0; i--)
	{
		x = fix16_mul(x, x);
		result <<= 1;
		if (x >= fix16_from_int(2))
		{
			result |= 1;
			x = fix16_rs(x);
		}
	}
	#ifndef FIXMATH_NO_ROUNDING
	x = fix16_mul(x, x);
	if (x >= fix16_from_int(2)) result++;
	#endif

	return result;
}

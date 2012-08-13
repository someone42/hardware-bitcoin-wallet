/** \file fix16_inline.h
  *
  * \brief Inline functions from libfixmath.
  *
  * This file was adapted from fix16.c and fix16.h of libfixmath r78, which
  * can be obtained from
  * http://code.google.com/p/libfixmath/source/browse/trunk/libfixmath/.
  *
  * The functions in this file were selected for inlining because they're
  * small but perform simple arithmetic operations. Inlining them has a major
  * impact on execution speed, and the resulting space penality is small.
  *
  * The contents of this file were written mainly by the libfixmath
  * contributors. A list of contributors can be retrieved from
  * http://code.google.com/p/libfixmath/people/list.
  *
  * This file is licensed as described by the file LIBFIXMATH_LICENCE.
  */

#include "fix16.h"

#ifndef FIXMATH_ALWAYS_INLINE
# ifdef __GNUC__
#   define FIXMATH_ALWAYS_INLINE __attribute__((always_inline, unused))
# else
#   define FIXMATH_ALWAYS_INLINE
# endif
#endif

/*! Adds the two given fix16_t's and returns the result.
*/
static FIXMATH_ALWAYS_INLINE fix16_t fix16_add(fix16_t a, fix16_t b)
{
	// Use unsigned integers because overflow with signed integers is
	// an undefined operation (http://www.airs.com/blog/archives/120).
	uint32_t _a = a, _b = b;
	uint32_t sum = _a + _b;

#ifndef FIXMATH_NO_OVERFLOW
	// Overflow can only happen if sign of a == sign of b, and then
	// it causes sign of sum != sign of a.
	if (!((_a ^ _b) & 0x80000000) && ((_a ^ sum) & 0x80000000))
		fix16_error_flag = 1;
#endif

	return sum;
}

/*! Subtracts the second given fix16_t from the first and returns the result.
*/
static FIXMATH_ALWAYS_INLINE fix16_t fix16_sub(fix16_t a, fix16_t b)
{
	uint32_t _a = a, _b = b;
	uint32_t diff = _a - _b;

#ifndef FIXMATH_NO_OVERFLOW
	// Overflow can only happen if sign of a != sign of b, and then
	// it causes sign of diff != sign of a.
	if (((_a ^ _b) & 0x80000000) && ((_a ^ diff) & 0x80000000))
		fix16_error_flag = 1;
#endif

	return diff;
}

/*! Convert an integer to its fix16_t representation.
*/
static FIXMATH_ALWAYS_INLINE fix16_t fix16_from_int(int a)
{
	return a * fix16_one;
}

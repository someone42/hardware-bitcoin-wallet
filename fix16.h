/** \file fix16.h
  *
  * \brief fix16.h from libfixmath.
  *
  * This file was adapted from fix16.h of libfixmath r82, which can be
  * obtained from
  * http://code.google.com/p/libfixmath/source/browse/trunk/libfixmath/.
  * The main modifications are:
  * - Removed declarations of unused functions.
  * - Removed inline conversion functions.
  * - Moved add/subtract to fix16_inline.h.
  * - Removed C++ boilerplate and reference to "fix16.hpp".
  * - Added this header and some comments.
  *
  * The rest of the file was written mainly by the libfixmath contributors.
  * A list of contributors can be retrieved from
  * http://code.google.com/p/libfixmath/people/list.
  *
  * This file is licensed as described by the file LIBFIXMATH_LICENCE.
  */

#ifndef __libfixmath_fix16_h__
#define __libfixmath_fix16_h__

/*! These options may let the optimizer to remove some calls to the functions.
 *  Refer to http://gcc.gnu.org/onlinedocs/gcc/Function-Attributes.html
 */
#ifndef FIXMATH_FUNC_ATTRS
# ifdef __GNUC__
#   if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 6)
#     define FIXMATH_FUNC_ATTRS __attribute__((leaf, nothrow, const))
#   else
#     define FIXMATH_FUNC_ATTRS __attribute__((nothrow, const))
#   endif
# else
#   define FIXMATH_FUNC_ATTRS
# endif
#endif

#ifndef FIXMATH_ALWAYS_INLINE
# ifdef __GNUC__
#   define FIXMATH_ALWAYS_INLINE __attribute__((always_inline, unused))
# else
#   define FIXMATH_ALWAYS_INLINE
# endif
#endif

#include "common.h"

/*! Represent real numbers using the signed Q16.16 fixed-point representation.
 *  Numbers are stored in a signed 32 bit integer, where the least significant
 *  16 bits represent the fractional part and the most significant 16 bits
 *  represent the integer part. The integer part has an implied most-significant
 *  sign bit.
 */
typedef int32_t fix16_t;

static const fix16_t fix16_maximum  = 0x7FFFFFFF; /*!< the maximum value of fix16_t */
static const fix16_t fix16_minimum  = 0x80000000; /*!< the minimum value of fix16_t */
static const fix16_t fix16_overflow = 0x80000000; /*!< the value used to indicate overflows when FIXMATH_NO_OVERFLOW is not specified */

static const fix16_t fix16_pi   = 205887;     /*!< fix16_t value of pi */
static const fix16_t fix16_e    = 178145;     /*!< fix16_t value of e */
static const fix16_t fix16_one  = 0x00010000; /*!< fix16_t value of 1 */
static const fix16_t fix16_zero = 0x00000000; /*!< fix16_t value of 0 */

/*! Generate multiplicative constant for division by x. This does not do
 *  rounding and only works for positive numbers.
*/
#define  FIX16_RECIPROCAL_OF(x)		(0x00010000 / (x))

/*! Macro for defining fix16_t constant values.
   The functions above can't be used from e.g. global variable initializers,
   and their names are quite long also. This macro is useful for constants
   springled alongside code, e.g. F16(1.234).

   Note that the argument is evaluated multiple times, and also otherwise
   you should only use this for constant values. For runtime-conversions,
   use the functions above.
*/
#define F16(x) ((fix16_t)(((x) >= 0) ? ((x) * 65536.0 + 0.5) : ((x) * 65536.0 - 0.5)))

extern bool fix16_error_occurred;

/*! Adds the two given fix16_t's and returns the result.
*/
extern fix16_t fix16_add(fix16_t a, fix16_t b) FIXMATH_FUNC_ATTRS;

/*! Subtracts the second given fix16_t from the first and returns the result.
*/
extern fix16_t fix16_sub(fix16_t a, fix16_t b) FIXMATH_FUNC_ATTRS;

/*! Multiplies the two given fix16_t's and returns the result.
*/
extern fix16_t fix16_mul(fix16_t inArg0, fix16_t inArg1) FIXMATH_FUNC_ATTRS;

/*! Returns the base 2 logarithm of the given fix16_t.
 */
extern fix16_t fix16_log2(fix16_t x) FIXMATH_FUNC_ATTRS;

/*! Convert an integer to its fix16_t representation.
*/
static FIXMATH_ALWAYS_INLINE fix16_t fix16_from_int(int a)
{
	return a * fix16_one;
}

#endif

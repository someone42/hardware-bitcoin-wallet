/** \file fix16.h
  *
  * \brief fix16.h from libfixmath.
  *
  * This file was adapted from fix16.h of libfixmath r78, which can be
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

#include <stdint.h>

/*! Represent real numbers using the signed Q16.16 fixed-point representation.
 *  Numbers are stored in a signed 32 bit integer, where the least significant
 *  16 bits represent the fractional part and the most significant 16 bits
 *  represent the integer part. The integer part has an implied most-significant
 *  sign bit.
 */
typedef int32_t fix16_t;

static const fix16_t FOUR_DIV_PI  = 0x145F3;            /*!< Fix16 value of 4/PI */
static const fix16_t _FOUR_DIV_PI2 = 0xFFFF9840;        /*!< Fix16 value of -4/PI² */
static const fix16_t X4_CORRECTION_COMPONENT = 0x399A;  /*!< Fix16 value of 0.225 */
static const fix16_t PI_DIV_4 = 0x0000C90F;             /*!< Fix16 value of PI/4 */
static const fix16_t THREE_PI_DIV_4 = 0x00025B2F;       /*!< Fix16 value of 3PI/4 */

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
#define  FIX16_RECIPROCAL_OF(x)		(0x00010000 / x)

extern uint8_t fix16_error_flag;

/*! Multiplies the two given fix16_t's and returns the result.
*/
extern fix16_t fix16_mul(fix16_t inArg0, fix16_t inArg1) FIXMATH_FUNC_ATTRS;

/*! Returns the base 2 logarithm of the given fix16_t.
 */
extern fix16_t fix16_log2(fix16_t x) FIXMATH_FUNC_ATTRS;

#endif

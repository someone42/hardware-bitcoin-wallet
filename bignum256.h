/** \file bignum256.h
  *
  * \brief Describes functions and constants exported by bignum256.c.
  * 
  * To use most of the functions described here, you must call bigSetField()
  * first to set field parameters. See bignum256.c for more details.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef BIGNUM256_H_INCLUDED
#define BIGNUM256_H_INCLUDED

#include "common.h"

/** Little-endian (in bytes), multi-precision integer of width 256 bits
  * (i.e. 32 bytes).
  * When this type is used, expect the identifier to have the type of a
  * pointer which points to a 32 byte array. Do not use this type when the
  * pointer points to an array which may not be exactly 32 bytes in size. */
typedef uint8_t * BigNum256;

/**
 * \defgroup BigCompareReturn Return values for bigCompare()
 *
 * \warning These all must be unsigned and <= 127, otherwise some bit
 *          twiddling hacks in bignum256.c won't work.
 * @{
 */
/** Return value for bigCompare() which indicates that the first operand is
  * less than the second. */
#define BIGCMP_LESS			2
/** Return value for bigCompare() which indicates that the first operand is
  * equal to the second.
  * \warning This must be 0 or some hacks in bigCompareVariableSize() won't
  *          work.
  */
#define BIGCMP_EQUAL		0
/** Return value for bigCompare() which indicates that the first operand is
  * greater than the second. */
#define BIGCMP_GREATER		1
/**@}*/

extern uint8_t bigCompareVariableSize(uint8_t *op1, uint8_t *op2, uint8_t size);
extern uint8_t bigCompare(BigNum256 op1, BigNum256 op2);
extern uint8_t bigIsZero(BigNum256 op1);
extern uint8_t bigIsZeroVariableSize(uint8_t *op1, uint8_t size);
extern void bigSetZero(BigNum256 r);
extern void bigAssign(BigNum256 r, BigNum256 op1);
extern void swapEndian256(BigNum256 buffer);
extern void bigSetField(const uint8_t *in_n, const uint8_t *in_complement_n, const uint8_t in_size_complement_n);
extern void bigModulo(BigNum256 r, BigNum256 op1);
extern uint8_t bigAddVariableSizeNoModulo(uint8_t *r, uint8_t *op1, uint8_t *op2, uint8_t op_size);
extern uint8_t bigSubtractVariableSizeNoModulo(uint8_t *r, uint8_t *op1, uint8_t *op2, uint8_t size);
extern uint8_t bigSubtractNoModulo(BigNum256 r, BigNum256 op1, BigNum256 op2);
extern void bigAdd(BigNum256 r, BigNum256 op1, BigNum256 op2);
extern void bigSubtract(BigNum256 r, BigNum256 op1, BigNum256 op2);
extern void bigShiftRightNoModulo(BigNum256 r, const BigNum256 op1);
extern void bigMultiplyVariableSizeNoModulo(uint8_t *r, uint8_t *op1, uint8_t op1_size, uint8_t *op2, uint8_t op2_size);
extern void bigMultiply(BigNum256 r, BigNum256 op1, BigNum256 op2);
extern void bigInvert(BigNum256 r, BigNum256 op1);

#endif // #ifndef BIGNUM256_H_INCLUDED

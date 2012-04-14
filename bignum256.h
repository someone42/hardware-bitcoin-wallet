// ***********************************************************************
// bignum256.h
// ***********************************************************************
//
// This describes functions and constants exported by bignum256.c
// To use the functions described here, you must call bigSetField() first to
// set field parameters.
//
// This file is licensed as described by the file LICENCE.

#ifndef BIGNUM256_H_INCLUDED
#define BIGNUM256_H_INCLUDED

#include "common.h"

// Little-endian (in bytes), 256-bit integer.
// When this type is used, expect the identifier to have the type of a pointer
// which points to a 32 byte array. Do not use this type when the pointer
// points to an array which may not be exactly 32 bytes in size.
typedef uint8_t * BigNum256;

// Return values for bigCompare(). These all must be unsigned and <= 127.
// Also, BIGCMP_EQUAL must be 0 or some hacks in bigCompareVariableSize()
// won't work.
#define BIGCMP_LESS			2
#define BIGCMP_EQUAL		0
#define BIGCMP_GREATER		1

extern uint8_t bigCompareVariableSize(uint8_t *op1, uint8_t *op2, uint8_t size);
extern uint8_t bigCompare(BigNum256 op1, BigNum256 op2);
extern uint8_t bigIsZero(BigNum256 op1);
extern uint8_t bigIsZeroVariableSize(uint8_t *op1, uint8_t size);
extern void bigSetZero(BigNum256 r);
extern void bigAssign(BigNum256 r, BigNum256 op1);
extern void bigSetField(const uint8_t *in_n, const uint8_t *in_complement_n, const uint8_t in_size_complement_n);
extern void bigModulo(BigNum256 r, BigNum256 op1);
extern uint8_t bigSubtractVariableSizeNoModulo(uint8_t *r, uint8_t *op1, uint8_t *op2, uint8_t size);
extern void bigAdd(BigNum256 r, BigNum256 op1, BigNum256 op2);
extern void bigSubtract(BigNum256 r, BigNum256 op1, BigNum256 op2);
extern void bigMultiply(BigNum256 r, BigNum256 op1, BigNum256 op2);
extern void bigInvert(BigNum256 r, BigNum256 op1);

#endif // #ifndef BIGNUM256_H_INCLUDED

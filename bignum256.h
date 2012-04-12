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
typedef u8 * BigNum256;

// Return values for bigCompare(). These all must be unsigned and <= 127.
// Also, BIGCMP_EQUAL must be 0 or some hacks in bigCompareVariableSize()
// won't work.
#define BIGCMP_LESS			2
#define BIGCMP_EQUAL		0
#define BIGCMP_GREATER		1

extern u8 bigCompareVariableSize(u8 *op1, u8 *op2, u8 size);
extern u8 bigCompare(BigNum256 op1, BigNum256 op2);
extern u8 bigIsZero(BigNum256 op1);
extern u8 bigIsZeroVariableSize(u8 *op1, u8 size);
extern void bigSetZero(BigNum256 r);
extern void bigAssign(BigNum256 r, BigNum256 op1);
extern void bigSetField(const u8 *in_n, const u8 *in_complement_n, const u8 in_size_complement_n);
extern void bigModulo(BigNum256 r, BigNum256 op1);
extern u8 bigSubtractVariableSizeNoModulo(u8 *r, u8 *op1, u8 *op2, u8 size);
extern void bigAdd(BigNum256 r, BigNum256 op1, BigNum256 op2);
extern void bigSubtract(BigNum256 r, BigNum256 op1, BigNum256 op2);
extern void bigMultiply(BigNum256 r, BigNum256 op1, BigNum256 op2);
extern void bigInvert(BigNum256 r, BigNum256 op1);

#endif // #ifndef BIGNUM256_H_INCLUDED

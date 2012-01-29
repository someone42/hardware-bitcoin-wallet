// ***********************************************************************
// bignum256.h
// ***********************************************************************
//
// This describes functions and constants exported by bignum256.c
// To use the functions described here, you must call bigsetfield() first to
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
typedef u8 *bignum256;

// Return values for bigcmp(). These all must be unsigned and <= 127.
#define BIGCMP_LESS			2
#define BIGCMP_EQUAL		0
#define BIGCMP_GREATER		1

extern u8 bigcmp_varsize(u8 *op1, u8 *op2, u8 size);
extern u8 bigcmp(bignum256 op1, bignum256 op2);
extern u8 bigiszero(bignum256 op1);
extern u8 bigiszero_varsize(u8 *op1, u8 size);
extern void bigsetzero(bignum256 r);
extern void bigassign(bignum256 r, bignum256 op1);
extern void bigsetfield(const u8 *in_n, const u8 *in_compn, const u8 in_sizecompn);
extern void bigmod(bignum256 r, bignum256 op1);
extern u8 bigsubtract_varsize(u8 *r, u8 *op1, u8 *op2, u8 size);
extern void bigadd(bignum256 r, bignum256 op1, bignum256 op2);
extern void bigsubtract(bignum256 r, bignum256 op1, bignum256 op2);
extern void bigmultiply(bignum256 r, bignum256 op1, bignum256 op2);
extern void biginvert(bignum256 r, bignum256 op1);

#endif // #ifndef BIGNUM256_H_INCLUDED

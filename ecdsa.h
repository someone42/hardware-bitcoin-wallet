// ***********************************************************************
// ecdsa.h
// ***********************************************************************
//
// This describes functions, types and constants exported and used by ecdsa.c
//
// This file is licensed as described by the file LICENCE.

#ifndef ECDSA_H_INCLUDED
#define ECDSA_H_INCLUDED

#include "common.h"
#include "bignum256.h"

// A point on the elliptic curve, in affine coordinates. Affine
// coordinates are the (x, y) that satisfy the elliptic curve
// equation y ^ 2 = x ^ 3 + a * x + b.
typedef struct point_affine_type
{
	u8 x[32];
	u8 y[32];
	// If is_point_at_infinity is non-zero, then this point represents the
	// point at infinity and all other structure members are considered
	// invalid.
	u8 is_point_at_infinity;
} point_affine;

extern void set_to_G(point_affine *p);
extern void set_field_to_p(void);
extern void point_multiply(point_affine *p, bignum256 k);
extern u8 ecdsa_sign(bignum256 r, bignum256 s, bignum256 hash, bignum256 privatekey, bignum256 k);

#endif // #ifndef ECDSA_H_INCLUDED

/** \file ecdsa.h
  *
  * \brief Describes functions, types and constants exported and used by
  *        ecdsa.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef ECDSA_H_INCLUDED
#define ECDSA_H_INCLUDED

#include "common.h"
#include "bignum256.h"

/** Maximum size, in bytes, of a serialised elliptic curve point, as is
  * written by ecdsaSerialise(). */
#define ECDSA_MAX_SERIALISE_SIZE	65

/** A point on the elliptic curve, in affine coordinates. Affine
  * coordinates are the (x, y) that satisfy the elliptic curve
  * equation y ^ 2 = x ^ 3 + a * x + b.
  */
typedef struct PointAffineStruct
{
	/** x component of a point in affine coordinates. */
	uint8_t x[32];
	/** y component of a point in affine coordinates. */
	uint8_t y[32];
	/** If is_point_at_infinity is non-zero, then this point represents the
	  * point at infinity and all other structure members are considered
	  * invalid. */
	uint8_t is_point_at_infinity;
} PointAffine;

extern const uint8_t secp256k1_n[];

extern void setFieldToN(void);
extern void setToG(PointAffine *p);
extern void pointMultiply(PointAffine *p, BigNum256 k);
extern void ecdsaSign(BigNum256 r, BigNum256 s, const BigNum256 hash, const BigNum256 privatekey);
extern uint8_t ecdsaSerialise(uint8_t *out, const PointAffine *point, const bool do_compress);

#endif // #ifndef ECDSA_H_INCLUDED

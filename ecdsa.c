/** \file ecdsa.c
  *
  * \brief Contains functions relevant to ECDSA signing.
  *
  * Functions relevant to ECDSA signing include those which perform group
  * operations on points of an elliptic curve (eg. pointAdd() and
  * pointDouble()) and the actual signing function, ecdsaSign().
  *
  * The elliptic curve used is secp256k1, from the document
  * "SEC 2: Recommended Elliptic Curve Domain Parameters" by Certicom
  * research, obtained 11-August-2011 from:
  * http://www.secg.org/collateral/sec2_final.pdf
  *
  * The operations here are written in a way as to encourage them to run in
  * (mostly) constant time. This provides some resistance against timing
  * attacks. However, the compiler may use optimisations which destroy this
  * property; inspection of the generated assembly code is the only way to
  * check. A disadvantage of this code is that point multiplication is slower
  * than it could be.
  * There are some data-dependent branches in here, but they're expected to
  * only make a difference (in timing) in exceptional cases.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifdef TEST_ECDSA
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "test_helpers.h"
#endif // #ifdef TEST_ECDSA

#include "common.h"
#include "bignum256.h"
#include "ecdsa.h"

/** A point on the elliptic curve, in Jacobian coordinates. The
  * Jacobian coordinates (x, y, z) are related to affine coordinates
  * (x_affine, y_affine) by:
  * (x_affine, y_affine) = (x / (z ^ 2), y / (z ^ 3)).
  *
  * Why use Jacobian coordinates? Because then point addition and
  * point doubling don't have to use inversion (division), which is very slow.
  */
typedef struct PointJacobianStruct
{
	/** x component of a point in Jacobian coordinates. */
	uint8_t x[32];
	/** y component of a point in Jacobian coordinates. */
	uint8_t y[32];
	/** z component of a point in Jacobian coordinates. */
	uint8_t z[32];
	/** If is_point_at_infinity is non-zero, then this point represents the
	  * point at infinity and all other structure members are considered
	  * invalid. */
	uint8_t is_point_at_infinity;
} PointJacobian;

/** The prime number used to define the prime finite field for secp256k1. */
static const uint8_t secp256k1_p[32] = {
0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/** 2s complement of #secp256k1_p. */
static const uint8_t secp256k1_complement_p[5] = {
0xd1, 0x03, 0x00, 0x00, 0x01};

/** The order of the base point used in secp256k1. */
static const uint8_t secp256k1_n[32] = {
0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf,
0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

/** 2s complement of #secp256k1_n. */
static const uint8_t secp256k1_complement_n[17] = {
0xbf, 0xbe, 0xc9, 0x2f, 0x73, 0xa1, 0x2d, 0x40,
0xc4, 0x5f, 0xb7, 0x50, 0x19, 0x23, 0x51, 0x45,
0x01};

/** The x component of the base point G used in secp256k1. */
static const uint8_t secp256k1_Gx[32] PROGMEM = {
0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59,
0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b, 0x02,
0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55,
0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66, 0xbe, 0x79};

/** The y component of the base point G used in secp256k1. */
static const uint8_t secp256k1_Gy[32] PROGMEM = {
0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c,
0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4, 0x17, 0xfd,
0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d,
0x65, 0xc4, 0xa3, 0x26, 0x77, 0xda, 0x3a, 0x48};

/** Convert a point from affine coordinates to Jacobian coordinates. This
  * is very fast.
  * \param out The destination point (in Jacobian coordinates).
  * \param in The source point (in affine coordinates).
  */
static void affineToJacobian(PointJacobian *out, PointAffine *in)
{
	out->is_point_at_infinity = in->is_point_at_infinity;
	// If out->is_point_at_infinity != 0, the rest of this function consists
	// of dummy operations.
	bigAssign(out->x, in->x);
	bigAssign(out->y, in->y);
	bigSetZero(out->z);
	out->z[0] = 1;
}

/** Convert a point from Jacobian coordinates to affine coordinates. This
  * is very slow because it involves inversion (division).
  * \param out The destination point (in affine coordinates).
  * \param in The source point (in Jacobian coordinates).
  */
static NOINLINE void jacobianToAffine(PointAffine *out, PointJacobian *in)
{
	uint8_t s[32];
	uint8_t t[32];

	out->is_point_at_infinity = in->is_point_at_infinity;
	// If out->is_point_at_infinity != 0, the rest of this function consists
	// of dummy operations.
	bigMultiply(s, in->z, in->z);
	bigMultiply(t, s, in->z);
	// Now s = z ^ 2 and t = z ^ 3.
	bigInvert(s, s);
	bigInvert(t, t);
	bigMultiply(out->x, in->x, s);
	bigMultiply(out->y, in->y, t);
}

/** Double (p = 2 x p) the point p (which is in Jacobian coordinates), placing
  * the result back into p.
  * The formulae for this function were obtained from the article:
  * "Software Implementation of the NIST Elliptic Curves Over Prime Fields",
  * obtained from:
  * http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.25.8619&rep=rep1&type=pdf
  * on 16-August-2011. See equations (2) ("doubling in Jacobian coordinates")
  * from section 4 of that article.
  * \param p The point (in Jacobian coordinates) to double.
  */
static NOINLINE void pointDouble(PointJacobian *p)
{
	uint8_t t[32];
	uint8_t u[32];

	// If p->is_point_at_infinity != 0, then the rest of this function will
	// consist of dummy operations. Nothing else needs to be done since
	// 2O = O.

	// If y is zero then the tangent line is vertical and never hits the
	// curve, therefore the result should be O. If y is zero, the rest of this
	// function will consist of dummy operations.
	p->is_point_at_infinity |= bigIsZero(p->y);

	bigMultiply(p->z, p->z, p->y);
	bigAdd(p->z, p->z, p->z);
	bigMultiply(p->y, p->y, p->y);
	bigMultiply(t, p->y, p->x);
	bigAdd(t, t, t);
	bigAdd(t, t, t);
	// t is now 4.0 * p->x * p->y ^ 2.
	bigMultiply(p->x, p->x, p->x);
	bigAssign(u, p->x);
	bigAdd(u, u, u);
	bigAdd(u, u, p->x);
	// u is now 3.0 * p->x ^ 2.
	// For curves with a != 0, a * p->z ^ 4 needs to be added to u.
	// But since a == 0 in secp256k1, we save 2 squarings and 1
	// multiplication.
	bigMultiply(p->x, u, u);
	bigSubtract(p->x, p->x, t);
	bigSubtract(p->x, p->x, t);
	bigSubtract(t, t, p->x);
	bigMultiply(t, t, u);
	bigMultiply(p->y, p->y, p->y);
	bigAdd(p->y, p->y, p->y);
	bigAdd(p->y, p->y, p->y);
	bigAdd(p->y, p->y, p->y);
	bigSubtract(p->y, t, p->y);
}

/** Add (p1 = p1 + p2) the point p2 to the point p1, storing the result back
  * into p1.
  * Mixed coordinates are used because it reduces the number of squarings and
  * multiplications from 16 to 11.
  * See equations (3) ("addition in mixed Jacobian-affine coordinates") from
  * section 4 of that article described in the comments to pointDouble().
  * junk must point at some memory area to redirect dummy writes to. The dummy
  * writes are used to encourage this function's completion time to be
  * independent of its parameters.
  * \param p1 The point (in Jacobian coordinates) to add p2 to.
  * \param junk Pointer to a dummy variable which may receive dummy writes.
  * \param p2 The point (in affine coordinates) to add to p1.
  */
static NOINLINE void pointAdd(PointJacobian *p1, PointJacobian *junk, PointAffine *p2)
{
	uint8_t s[32];
	uint8_t t[32];
	uint8_t u[32];
	uint8_t v[32];
	uint8_t is_O;
	uint8_t is_O2;
	uint8_t cmp_xs;
	uint8_t cmp_yt;
	PointJacobian *lookup[2];

	lookup[0] = p1;
	lookup[1] = junk;

	// O + p2 == p2.
	// If p1 is O, then copy p2 into p1 and redirect all writes to the dummy
	// write area.
	// The following line does: "is_O = p1->is_point_at_infinity ? 1 : 0;".
	is_O = (uint8_t)((((uint16_t)(-(int)p1->is_point_at_infinity)) >> 8) & 1);
	affineToJacobian(lookup[1 - is_O], p2);
	p1 = lookup[is_O];
	lookup[0] = p1; // p1 might have changed

	// p1 + O == p1.
	// If p2 is O, then redirect all writes to the dummy write area. This
	// preserves the value of p1.
	// The following line does: "is_O2 = p2->is_point_at_infinity ? 1 : 0;".
	is_O2 = (uint8_t)((((uint16_t)(-(int)p2->is_point_at_infinity)) >> 8) & 1);
	p1 = lookup[is_O2];
	lookup[0] = p1; // p1 might have changed

	bigMultiply(s, p1->z, p1->z);
	bigMultiply(t, s, p1->z);
	bigMultiply(t, t, p2->y);
	bigMultiply(s, s, p2->x);
	// The following two lines do: "cmp_xs = bigCompare(p1->x, s) == BIGCMP_EQUAL ? 0 : 0xff;".
	cmp_xs = (uint8_t)(bigCompare(p1->x, s) ^ BIGCMP_EQUAL);
	cmp_xs = (uint8_t)(((uint16_t)(-(int)cmp_xs)) >> 8);
	// The following two lines do: "cmp_yt = bigCompare(p1->y, t) == BIGCMP_EQUAL ? 0 : 0xff;".
	cmp_yt = (uint8_t)(bigCompare(p1->y, t) ^ BIGCMP_EQUAL);
	cmp_yt = (uint8_t)(((uint16_t)(-(int)cmp_yt)) >> 8);
	// The following branch can never be taken when calling pointMultiply(),
	// so its existence doesn't compromise timing regularity.
	if ((cmp_xs | cmp_yt | is_O | is_O2) == 0)
	{
		// Points are actually the same; use point doubling.
		pointDouble(p1);
		return;
	}
	// p2 == -p1 when p1->x == s and p1->y != t.
	// If p1->is_point_at_infinity is set, then all subsequent operations in
	// this function become dummy operations.
	p1->is_point_at_infinity = (uint8_t)(p1->is_point_at_infinity | (~cmp_xs & cmp_yt & 1));
	bigSubtract(s, s, p1->x);
	// s now contains p2->x * p1->z ^ 2 - p1->x.
	bigSubtract(t, t, p1->y);
	// t now contains p2->y * p1->z ^ 3 - p1->y.
	bigMultiply(p1->z, p1->z, s);
	bigMultiply(v, s, s);
	bigMultiply(u, v, p1->x);
	bigMultiply(p1->x, t, t);
	bigMultiply(s, s, v);
	bigSubtract(p1->x, p1->x, s);
	bigSubtract(p1->x, p1->x, u);
	bigSubtract(p1->x, p1->x, u);
	bigSubtract(u, u, p1->x);
	bigMultiply(u, u, t);
	bigMultiply(s, s, p1->y);
	bigSubtract(p1->y, u, s);
}

/** Set field parameters to be those defined by the prime number p which
  * is used in secp256k1. */
static void setFieldToP(void)
{
	bigSetField(secp256k1_p, secp256k1_complement_p, sizeof(secp256k1_complement_p));
}

/** Set field parameters to be those defined by the prime number n which
  * is used in secp256k1. */
static void setFieldToN(void)
{
	bigSetField(secp256k1_n, secp256k1_complement_n, sizeof(secp256k1_complement_n));
}

/** Perform scalar multiplication (p = k x p) of the point p by the scalar k.
  * The result will be stored back into p. The multiplication is
  * accomplished by repeated point doubling and adding of the
  * original point. All multi-precision integer operations are done under
  * the prime finite field specified by #secp256k1_p.
  * \param p The point (in affine coordinates) to multiply.
  * \param k The 32 byte multi-precision scalar to multiply p by.
  */
void pointMultiply(PointAffine *p, BigNum256 k)
{
	PointJacobian accumulator;
	PointJacobian junk;
	PointAffine always_point_at_infinity; // for dummy operations
	uint8_t i;
	uint8_t j;
	uint8_t one_byte;
	uint8_t one_bit;
	PointAffine *lookup_affine[2];

	memset(&accumulator, 0, sizeof(PointJacobian));
	memset(&junk, 0, sizeof(PointJacobian));
	memset(&always_point_at_infinity, 0, sizeof(PointAffine));
	setFieldToP();
	// The Montgomery ladder method can't be used here because it requires
	// point addition to be done in pure Jacobian coordinates. Point addition
	// in pure Jacobian coordinates would make point multiplication about
	// 26% slower. Instead, dummy operations are used to make point
	// multiplication a constant time operation. However, the use of dummy
	// operations does make this code more susceptible to fault analysis -
	// by introducing faults where dummy operations may occur, an attacker
	// can determine whether bits in the private key are set or not.
	// So the use of this code is not appropriate in situations where fault
	// analysis can occur.
	accumulator.is_point_at_infinity = 1;
	always_point_at_infinity.is_point_at_infinity = 1;
	lookup_affine[1] = p;
	lookup_affine[0] = &always_point_at_infinity;
	for (i = 31; i < 32; i--)
	{
		one_byte = k[i];
		for (j = 0; j < 8; j++)
		{
			pointDouble(&accumulator);
			one_bit = (uint8_t)((one_byte & 0x80) >> 7);
			pointAdd(&accumulator, &junk, lookup_affine[one_bit]);
			one_byte = (uint8_t)(one_byte << 1);
		}
	}
	jacobianToAffine(p, &accumulator);
}

/** Set a point to the base point of secp256k1.
  * \param p The point to set.
  */
void setToG(PointAffine *p)
{
	uint8_t buffer[32];
	uint8_t i;

	p->is_point_at_infinity = 0;
	for (i = 0; i < 32; i++)
	{
		buffer[i] = LOOKUP_BYTE(secp256k1_Gx[i]);
	}
	bigAssign(p->x, (BigNum256)buffer);
	for (i = 0; i < 32; i++)
	{
		buffer[i] = LOOKUP_BYTE(secp256k1_Gy[i]);
	}
	bigAssign(p->y, (BigNum256)buffer);
}

/** Attempt to sign the message with a given message digest.
  * This is an implementation of the algorithm described in the document
  * "SEC 1: Elliptic Curve Cryptography" by Certicom research, obtained
  * 15-August-2011 from: http://www.secg.org/collateral/sec1_final.pdf
  * section 4.1.3 ("Signing Operation").
  * \param r The "r" component of the signature will be written to here (upon
  *          successful completion), as a 32 byte multi-precision number.
  * \param s The "s" component of the signature will be written to here, (upon
  *          successful completion), as a 32 byte multi-precision number.
  * \param hash The message digest of the message to sign, represented as a
  *          32 byte multi-precision number.
  * \param private_key The private key to use in the signing operation,
  *                    represented as a 32 byte multi-precision number.
  * \param k A (truly) random 32 byte multi-precision number. This must be
  *          different for each call to this function.
  *
  * \return 0 and fills r and s with the signature upon success; 1 upon
  *         failure. If this function returns 1, an appropriate course of
  *         action is to pick another random integer k and try again. If a
  *         random number generator is truly random, failure should only occur
  *         if you are extremely unlucky.
  */
uint8_t ecdsaSign(BigNum256 r, BigNum256 s, BigNum256 hash, BigNum256 private_key, BigNum256 k)
{
	PointAffine big_r;

	// This is one of many data-dependent branches in this function. They do
	// not compromise timing attack resistance because these branches are
	// expected to occur extremely infrequently.
	if (bigIsZero(k))
	{
		return 1;
	}
	if (bigCompare(k, (BigNum256)secp256k1_n) != BIGCMP_LESS)
	{
		return 1;
	}

	// Compute ephemeral elliptic curve key pair (k, big_r).
	setToG(&big_r);
	pointMultiply(&big_r, k);
	// big_r now contains k * G.
	setFieldToN();
	bigModulo(r, big_r.x);
	// r now contains (k * G).x (mod n).
	if (bigIsZero(r))
	{
		return 1;
	}
	bigMultiply(s, r, private_key);
	bigModulo(big_r.y, hash); // use big_r.y as temporary
	bigAdd(s, s, big_r.y);
	bigInvert(big_r.y, k);
	bigMultiply(s, s, big_r.y);
	// s now contains (hash + (r * private_key)) / k (mod n).
	if (bigIsZero(s))
	{
		return 1;
	}

	return 0;
}

#ifdef TEST_ECDSA

/** The curve parameter b of secp256k1. The other parameter, a, is zero. */
static const uint8_t secp256k1_b[32] = {
0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** Check if a point is on the elliptic curve. This signals success/failure
  * by calling reportSuccess() or reportFailure().
  * \param p The point to check.
  */
static void checkPointIsOnCurve(PointAffine *p)
{
	uint8_t y_squared[32];
	uint8_t x_cubed[32];

	if (p->is_point_at_infinity)
	{
		// O is always on the curve.
		reportSuccess();
		return;
	}
	bigMultiply(y_squared, p->y, p->y);
	bigMultiply(x_cubed, p->x, p->x);
	bigMultiply(x_cubed, x_cubed, p->x);
	bigAdd(x_cubed, x_cubed, (BigNum256)secp256k1_b);
	if (bigCompare(y_squared, x_cubed) != BIGCMP_EQUAL)
	{
		printf("Point is not on curve\n");
		printf("x = ");
		printLittleEndian32(p->x);
		printf("\n");
		printf("y = ");
		printLittleEndian32(p->y);
		printf("\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
}

/** Read hex string containing a little-endian 256 bit integer from a file.
  * \param r Where the number will be stored into after it is read. This must
  *          be a byte array with space for 32 bytes.
  * \param f The file to read from.
  */
static void bigFRead(BigNum256 r, FILE *f)
{
	int i;
	int value;

	for (i = 0; i < 32; i++)
	{
		fscanf(f, "%02x", &value);
		r[i] = (uint8_t)value;
	}
}

/** Verify an ECDSA signature.
  * \param r One half of the signature (see ecdsaSign()).
  * \param s The other half of the signature (see ecdsaSign()).
  * \param hash The message digest of the message that was signed, represented
  *             as a 32 byte little-endian multi-precision integer.
  * \param public_key_x x component of public key, represented as a 32 byte
  *                     little-endian multi-precision integer.
  * \param public_key_y y component of public key, represented as a 32 byte
  *                     little-endian multi-precision integer.
  * \return 0 if signature is good, 1 otherwise.
  * \warning Use this for testing only. It's called "crappy" for a reason.
  */
static int crappyVerifySignature(BigNum256 r, BigNum256 s, BigNum256 hash, BigNum256 public_key_x, BigNum256 public_key_y)
{
	PointAffine p;
	PointAffine p2;
	PointJacobian pj;
	PointJacobian junk;
	PointAffine result;
	uint8_t temp1[32];
	uint8_t temp2[32];
	uint8_t k1[32];
	uint8_t k2[32];

	setFieldToN();
	bigModulo(temp1, hash);
	bigInvert(temp2, s);
	bigMultiply(k1, temp2, temp1);
	bigMultiply(k2, temp2, r);
	setFieldToP();
	bigModulo(k1, k1);
	bigModulo(k2, k2);
	setToG(&p);
	pointMultiply(&p, k1);
	p2.is_point_at_infinity = 0;
	bigAssign(p2.x, public_key_x);
	bigAssign(p2.y, public_key_y);
	pointMultiply(&p2, k2);
	affineToJacobian(&pj, &p);
	pointAdd(&pj, &junk, &p2);
	jacobianToAffine(&result, &pj);
	setFieldToN();
	bigModulo(result.x, result.x);
	if (bigCompare(result.x, r) == BIGCMP_EQUAL)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

int main(void)
{
	PointAffine p;
	PointJacobian p2;
	PointJacobian junk;
	PointAffine compare;
	uint8_t temp[32];
	uint8_t r[32];
	uint8_t s[32];
	uint8_t private_key[32];
	uint8_t public_key_x[32];
	uint8_t public_key_y[32];
	uint8_t hash[32];
	int i;
	int j;
	FILE *f;

	initTests(__FILE__);

	setFieldToP();

	// Check that G is on the curve.
	setToG(&p);
	checkPointIsOnCurve(&p);

	// Check that point at infinity ("O") actually acts as identity element.
	p2.is_point_at_infinity = 1;
	// 2O = O.
	pointDouble(&p2);
	if (!p2.is_point_at_infinity)
	{
		printf("Point double doesn't handle 2O properly\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	// O + O = O.
	p.is_point_at_infinity = 1;
	pointAdd(&p2, &junk, &p);
	if (!p2.is_point_at_infinity)
	{
		printf("Point add doesn't handle O + O properly\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	// P + O = P.
	setToG(&p);
	affineToJacobian(&p2, &p);
	p.is_point_at_infinity = 1;
	pointAdd(&p2, &junk, &p);
	jacobianToAffine(&p, &p2);
	if ((p.is_point_at_infinity) 
		|| (bigCompare(p.x, (BigNum256)secp256k1_Gx) != BIGCMP_EQUAL)
		|| (bigCompare(p.y, (BigNum256)secp256k1_Gy) != BIGCMP_EQUAL))
	{
		printf("Point add doesn't handle P + O properly\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	// O + P = P.
	p2.is_point_at_infinity = 1;
	setToG(&p);
	pointAdd(&p2, &junk, &p);
	jacobianToAffine(&p, &p2);
	if ((p.is_point_at_infinity) 
		|| (bigCompare(p.x, (BigNum256)secp256k1_Gx) != BIGCMP_EQUAL)
		|| (bigCompare(p.y, (BigNum256)secp256k1_Gy) != BIGCMP_EQUAL))
	{
		printf("Point add doesn't handle O + P properly\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Test that P + P produces the same result as 2P.
	setToG(&p);
	affineToJacobian(&p2, &p);
	pointAdd(&p2, &junk, &p);
	jacobianToAffine(&compare, &p2);
	affineToJacobian(&p2, &p);
	pointDouble(&p2);
	jacobianToAffine(&p, &p2);
	if ((p.is_point_at_infinity != compare.is_point_at_infinity) 
		|| (bigCompare(p.x, compare.x) != BIGCMP_EQUAL)
		|| (bigCompare(p.y, compare.y) != BIGCMP_EQUAL))
	{
		printf("P + P != 2P\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	checkPointIsOnCurve(&compare);

	// Test that P + -P = O.
	setToG(&p);
	affineToJacobian(&p2, &p);
	bigSetZero(temp);
	bigSubtract(p.y, temp, p.y);
	checkPointIsOnCurve(&p);
	pointAdd(&p2, &junk, &p);
	if (!p2.is_point_at_infinity) 
	{
		printf("P + -P != O\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Test that 2P + P gives a point on curve.
	setToG(&p);
	affineToJacobian(&p2, &p);
	pointDouble(&p2);
	pointAdd(&p2, &junk, &p);
	jacobianToAffine(&p, &p2);
	checkPointIsOnCurve(&p);

	// Test that pointMultiply by 0 gives O.
	setToG(&p);
	bigSetZero(temp);
	pointMultiply(&p, temp);
	if (!p.is_point_at_infinity) 
	{
		printf("pointMultiply not starting at O\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Test that pointMultiply by 1 gives P back.
	setToG(&p);
	bigSetZero(temp);
	temp[0] = 1;
	pointMultiply(&p, temp);
	if ((p.is_point_at_infinity) 
		|| (bigCompare(p.x, (BigNum256)secp256k1_Gx) != BIGCMP_EQUAL)
		|| (bigCompare(p.y, (BigNum256)secp256k1_Gy) != BIGCMP_EQUAL))
	{
		printf("1 * P != P\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Test that pointMultiply by 2 gives 2P back.
	setToG(&p);
	bigSetZero(temp);
	temp[0] = 2;
	pointMultiply(&p, temp);
	setToG(&compare);
	affineToJacobian(&p2, &compare);
	pointDouble(&p2);
	jacobianToAffine(&compare, &p2);
	if ((p.is_point_at_infinity != compare.is_point_at_infinity) 
		|| (bigCompare(p.x, compare.x) != BIGCMP_EQUAL)
		|| (bigCompare(p.y, compare.y) != BIGCMP_EQUAL))
	{
		printf("2 * P != 2P\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Test that pointMultiply by various constants gives a point on curve.
	for (i = 0; i < 300; i++)
	{
		setToG(&p);
		bigSetZero(temp);
		temp[0] = (uint8_t)i;
		temp[1] = (uint8_t)(i >> 8);
		pointMultiply(&p, temp);
		checkPointIsOnCurve(&p);
	}

	// Test that n * G = O.
	setToG(&p);
	pointMultiply(&p, (BigNum256)secp256k1_n);
	if (!p.is_point_at_infinity) 
	{
		printf("n * P != O\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Test against some point multiplication test vectors.
	// It's hard to find such test vectors for secp256k1. But they can be
	// generated using OpenSSL. Using the command:
	// openssl ecparam -name secp256k1 -outform DER -out out.der -genkey
	// will generate an ECDSA private/public keypair. ECDSA private keys
	// are random integers and public keys are the coordinates of the point
	// that results from multiplying the private key by the base point (G).
	// So these keypairs can also be used to test point multiplication.
	//
	// Using OpenSSL 0.9.8h, the private key should be located within out.der
	// at offsets 0x0E to 0x2D (zero-based, inclusive), the x-component of
	// the public key at 0x3D to 0x5C and the y-component at 0x5D to 0x7C.
	// They are 256 bit integers stored big-endian.
	//
	// These tests require that the private and public keys be little-endian
	// hex strings within keypairs.txt, where each keypair is represented by
	// 3 lines. The first line is the private key, the second line the
	// x-component of the public key and the third line the y-component of
	// the public key. This also expects 300 tests (stored sequentially), so
	// keypairs.txt should have 900 lines in total. Each line should have
	// 64 non-whitespace characters on it.
	f = fopen("keypairs.txt", "r");
	if (f == NULL)
	{
		printf("Could not open keypairs.txt for reading\n");
		printf("Please generate it using the instructions in the source\n");
		exit(1);
	}
	for (i = 0; i < 300; i++)
	{
		skipWhiteSpace(f);
		bigFRead(temp, f);
		skipWhiteSpace(f);
		bigFRead(compare.x, f);
		skipWhiteSpace(f);
		bigFRead(compare.y, f);
		skipWhiteSpace(f);
		setToG(&p);
		pointMultiply(&p, temp);
		checkPointIsOnCurve(&p);
		if ((p.is_point_at_infinity != compare.is_point_at_infinity) 
			|| (bigCompare(p.x, compare.x) != BIGCMP_EQUAL)
			|| (bigCompare(p.y, compare.y) != BIGCMP_EQUAL))
		{
			printf("Keypair test vector %d failed\n", i);
			reportFailure();
		}
		else
		{
			reportSuccess();
		}
	}
	fclose(f);

	// ecdsaSign() should fail when k == 0 or k >= n.
	bigSetZero(temp);
	if (!ecdsaSign(r, s, temp, temp, temp))
	{
		printf("ecdsaSign() accepts k == 0\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	bigAssign(temp, (BigNum256)secp256k1_n);
	if (!ecdsaSign(r, s, temp, temp, temp))
	{
		printf("ecdsaSign() accepts k == n\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	memset(temp, 0xff, 32);
	if (!ecdsaSign(r, s, temp, temp, temp))
	{
		printf("ecdsaSign() accepts k > n\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// But it should succeed for k == n - 1.
	bigAssign(temp, (BigNum256)secp256k1_n);
	temp[0] = 0x40;
	if (ecdsaSign(r, s, temp, temp, temp))
	{
		printf("ecdsaSign() does not accept k == n - 1\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Test signatures by signing and then verifying. For keypairs, just
	// use the ones generated for the pointMultiply test.
	srand(42);
	f = fopen("keypairs.txt", "r");
	if (f == NULL)
	{
		printf("Could not open keypairs.txt for reading\n");
		printf("Please generate it using the instructions in the source\n");
		exit(1);
	}
	for (i = 0; i < 300; i++)
	{
		if ((i & 3) == 0)
		{
			// Use all ones for hash.
			memset(hash, 0xff, 32);
		}
		else if ((i & 3) == 1)
		{
			// Use all zeroes for hash.
			bigSetZero(hash);
		}
		else
		{
			// Use a pseudo-random hash.
			for (j = 0; j < 32; j++)
			{
				hash[j] = (uint8_t)rand();
			}
		}
		skipWhiteSpace(f);
		bigFRead(private_key, f);
		skipWhiteSpace(f);
		bigFRead(public_key_x, f);
		skipWhiteSpace(f);
		bigFRead(public_key_y, f);
		skipWhiteSpace(f);
		do
		{
			for (j = 0; j < 32; j++)
			{
				temp[j] = (uint8_t)rand();
			}
		} while (ecdsaSign(r, s, hash, private_key, temp));
		if (crappyVerifySignature(r, s, hash, public_key_x, public_key_y))
		{
			printf("Signature verify failed\n");
			printf("private_key = ");
			printLittleEndian32(private_key);
			printf("\n");
			printf("public_key_x = ");
			printLittleEndian32(public_key_x);
			printf("\n");
			printf("public_key_y = ");
			printLittleEndian32(public_key_y);
			printf("\n");
			printf("r = ");
			printLittleEndian32(r);
			printf("\n");
			printf("s = ");
			printLittleEndian32(s);
			printf("\n");
			printf("hash = ");
			printLittleEndian32(hash);
			printf("\n");
			printf("k = ");
			printLittleEndian32(temp);
			printf("\n");
			reportFailure();
		}
		else
		{
			reportSuccess();
		}
	}
	fclose(f);

	finishTests();

	exit(0);
}

#endif // #ifdef TEST_ECDSA


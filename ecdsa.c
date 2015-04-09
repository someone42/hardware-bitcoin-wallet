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
  * References to RFC 6979 refer to the version dated August 2013, obtained
  * http://tools.ietf.org/html/rfc6979 on 4 April 2015.
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
#include "endian.h"
#include "hmac_drbg.h"

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
const uint8_t secp256k1_n[32] = {
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
void setFieldToN(void)
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

/** Create a deterministic ECDSA signature of a given message (digest) and
  * private key.
  * This is an implementation of the algorithm described in the document
  * "SEC 1: Elliptic Curve Cryptography" by Certicom research, obtained
  * 15-August-2011 from: http://www.secg.org/collateral/sec1_final.pdf
  * section 4.1.3 ("Signing Operation"). The ephemeral private key "k" will
  * be deterministically generated according to RFC 6979.
  * \param r The "r" component of the signature will be written to here as
  *          a 32 byte multi-precision number.
  * \param s The "s" component of the signature will be written to here, as
  *          a 32 byte multi-precision number.
  * \param hash The message digest of the message to sign, represented as a
  *             32 byte multi-precision number.
  * \param private_key The private key to use in the signing operation,
  *                    represented as a 32 byte multi-precision number.
  */
void ecdsaSign(BigNum256 r, BigNum256 s, const BigNum256 hash, const BigNum256 private_key)
{
	PointAffine big_r;
	uint8_t k[32];
	uint8_t seed_material[32 + SHA256_HASH_LENGTH];
	HMACDRBGState state;

	// From RFC 6979, section 3.3a:
	// seed_material = int2octets(private_key) || bits2octets(hash)
	// int2octets and bits2octets both interpret the number as big-endian.
	// However, both the private_key and hash parameters are BigNum256, which
	// is little-endian.
	bigAssign(seed_material, private_key);
	swapEndian256(seed_material); // little-endian -> big-endian
	bigAssign(&(seed_material[32]), hash);
	swapEndian256(&(seed_material[32])); // little-endian -> big-endian
	drbgInstantiate(&state, seed_material, sizeof(seed_material));

	while (true)
	{
		drbgGenerate(k, &state, 32, NULL, 0);
		// From RFC 6979, section 3.3b, the output of the DRBG is run through
		// the bits2int function, which interprets the output as a big-endian
		// integer. However, functions in bignum256.c expect a little-endian
		// integer.
		swapEndian256(k); // big-endian -> little-endian

		// This is one of many data-dependent branches in this function. They do
		// not compromise timing attack resistance because these branches are
		// expected to occur extremely infrequently.
		if (bigIsZero(k))
		{
			continue;
		}
		if (bigCompare(k, (BigNum256)secp256k1_n) != BIGCMP_LESS)
		{
			continue;
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
			continue;
		}
		bigMultiply(s, r, private_key);
		bigModulo(big_r.y, hash); // use big_r.y as temporary
		bigAdd(s, s, big_r.y);
		bigInvert(big_r.y, k);
		bigMultiply(s, s, big_r.y);
		// s now contains (hash + (r * private_key)) / k (mod n).
		if (bigIsZero(s))
		{
			continue;
		}

		// Canonicalise s by negating it if s > secp256k1_n / 2.
		// See https://github.com/bitcoin/bitcoin/pull/3016 for more info.
		bigShiftRightNoModulo(k, (const BigNum256)secp256k1_n); // use k as temporary
		if (bigCompare(s, k) == BIGCMP_GREATER)
		{
			bigSubtractNoModulo(s, (BigNum256)secp256k1_n, s);
		}
		break;
	}
}

/** Serialise an elliptic curve point in a manner which is Bitcoin-compatible.
  * This means using the serialisation rules in:
  * "SEC 1: Elliptic Curve Cryptography" by Certicom research, obtained
  * 15-August-2011 from: http://www.secg.org/collateral/sec1_final.pdf
  * sections 2.3.2 ("OctetString-to-BitString Conversion") and
  * 2.3.3 ("EllipticCurvePoint-to-OctetString Conversion").
  * The document basically says that integers should be represented big-endian
  * and that a prefix byte should be prepended to indicate that the public key
  * is compressed or not.
  * \param out Where the serialised point will be written to. This must be a
  *            byte array with space for at least #ECDSA_MAX_SERIALISE_SIZE
  *            bytes.
  * \param point The elliptic point curve to serialise.
  * \param do_compress Whether to apply point compression - this will reduce
  *                    the size of public keys and hence transactions.
  *                    As of 2014, all Bitcoin clients out there are able to
  *                    decompress points, so it should be safe to always
  *                    compress points.
  * \return The number of bytes written to out.
  */
uint8_t ecdsaSerialise(uint8_t *out, const PointAffine *point, const bool do_compress)
{
	PointAffine temp;

	memcpy(&temp, point, sizeof(temp)); // need temp for endian reversing
	if (temp.is_point_at_infinity)
	{
		// Special case for point at infinity.
		out[0] = 0x00;
		return 1;
	}
	else if (!do_compress)
	{
		// Uncompressed point.
		out[0] = 0x04;
		swapEndian256(temp.x);
		swapEndian256(temp.y);
		memcpy(&(out[1]), temp.x, 32);
		memcpy(&(out[33]), temp.y, 32);
		return 65;
	}
	else
	{
		// Compressed point.
		if ((temp.y[0] & 1) != 0)
		{
			out[0] = 0x03; // is odd
		}
		else
		{
			out[0] = 0x02; // is not odd
		}
		swapEndian256(temp.x);
		memcpy(&(out[1]), temp.x, 32);
		return 33;
	}
}

#ifdef TEST_ECDSA

/** The curve parameter b of secp256k1. The other parameter, a, is zero. */
static const uint8_t secp256k1_b[32] = {
0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** This is #secp256k1_p plus 1, then divided by 4. It is a constant used for
  * decompressing elliptic curve points. */
static const uint8_t secp256k1_p_plus1over4[32] = {
0x0c, 0xff, 0xff, 0xbf, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f};

/** Test vector generated using https://brainwallet.github.io/, which is a
  * convenient way to generate serialised public keys. */
struct BrainwalletTestCase
{
	/** Private key (brainwallet.org calls this the private exponent. This is
	  * big-endian. */
	uint8_t private_exponent[32];
	/** Whether the public key should be compressed. */
	bool is_compressed;
	/** Serialised public key. */
	uint8_t serialised[ECDSA_MAX_SERIALISE_SIZE];
	/** Size of serialised public key, in bytes. */
	uint8_t serialised_size;
};

static const struct BrainwalletTestCase brainwallet_test_cases[] = {

{ // uncompressed example 1
{0x9f, 0x79, 0xfd, 0x6c, 0xdc, 0x88, 0x0e, 0x39, // private exponent
0x14, 0xac, 0x75, 0xb5, 0x0d, 0x71, 0x22, 0x2d,
0x29, 0xd4, 0xe5, 0xe8, 0x68, 0x0b, 0xc1, 0x4e,
0x18, 0xe5, 0xef, 0x28, 0xc1, 0x98, 0x14, 0x84},
false, // is compressed?
{0x04, 0x99, 0xf9, 0xe0, 0x0e, 0x30, 0x53, 0x1d, // public key
0x93, 0x12, 0x72, 0x8c, 0x37, 0x7a, 0x56, 0x5c,
0x8f, 0xef, 0x86, 0x2a, 0x6e, 0xbc, 0x10, 0x77,
0x33, 0x27, 0x70, 0xae, 0x79, 0xf5, 0xd6, 0x82,
0xfb, 0xae, 0x86, 0x1a, 0x5e, 0x55, 0x55, 0xc0,
0x1f, 0x65, 0x37, 0x3d, 0xd6, 0xea, 0xb4, 0x7b,
0xee, 0xe0, 0x2d, 0x7a, 0xb7, 0x62, 0x6a, 0x00,
0xd3, 0x82, 0xd4, 0x34, 0xfa, 0xba, 0x84, 0xfe,
0x60},
65 // public key length
},

{ // uncompressed example 2 (only 1 different from above)
{0x9f, 0x79, 0xfd, 0x6c, 0xdc, 0x88, 0x0e, 0x39, // private exponent
0x14, 0xac, 0x75, 0xb5, 0x0d, 0x71, 0x22, 0x2d,
0x29, 0xd4, 0xe5, 0xe8, 0x68, 0x0b, 0xc1, 0x4e,
0x18, 0xe5, 0xef, 0x28, 0xc1, 0x98, 0x14, 0x85},
false, // is compressed?
{0x04, 0x3b, 0x70, 0x76, 0x2c, 0xfa, 0xda, 0xbd, // public key
0x45, 0x03, 0xdc, 0x5b, 0x71, 0x8c, 0xae, 0x17,
0xff, 0xa0, 0x9e, 0x0c, 0xc8, 0xd8, 0x0b, 0xa7,
0xb9, 0xf8, 0x6a, 0x4a, 0x7c, 0xe5, 0xc8, 0x72,
0x55, 0x65, 0x2c, 0xd6, 0x5d, 0x60, 0xc7, 0x30,
0x8f, 0x27, 0x61, 0xd1, 0xca, 0xdd, 0x2a, 0x0c,
0x69, 0x23, 0xfa, 0x24, 0x11, 0x9d, 0x03, 0xb5,
0x5e, 0xf6, 0xb2, 0xd5, 0xbc, 0x9a, 0xeb, 0x1f,
0xdf},
65 // public key length
},

{ // compressed example with 0x02 prefix
{0x9f, 0x79, 0xfd, 0x6c, 0xdc, 0x88, 0x0e, 0x39, // private exponent
0x14, 0xac, 0x75, 0xb5, 0x0d, 0x71, 0x22, 0x2d,
0x29, 0xd4, 0xe5, 0xe8, 0x68, 0x0b, 0xc1, 0x4e,
0x18, 0xe5, 0xef, 0x28, 0xc1, 0x98, 0x14, 0x84},
true, // is compressed?
{0x02, 0x99, 0xf9, 0xe0, 0x0e, 0x30, 0x53, 0x1d, // public key
0x93, 0x12, 0x72, 0x8c, 0x37, 0x7a, 0x56, 0x5c,
0x8f, 0xef, 0x86, 0x2a, 0x6e, 0xbc, 0x10, 0x77,
0x33, 0x27, 0x70, 0xae, 0x79, 0xf5, 0xd6, 0x82,
0xfb},
33 // public key length
},

{ // compressed example with 0x03 prefix
{0x9f, 0x79, 0xfd, 0x6c, 0xdc, 0x88, 0x0e, 0x39, // private exponent
0x14, 0xac, 0x75, 0xb5, 0x0d, 0x71, 0x22, 0x2d,
0x29, 0xd4, 0xe5, 0xe8, 0x68, 0x0b, 0xc1, 0x4e,
0x18, 0xe5, 0xef, 0x28, 0xc1, 0x98, 0x14, 0x85},
true, // is compressed?
{0x03, 0x3b, 0x70, 0x76, 0x2c, 0xfa, 0xda, 0xbd, // public key
0x45, 0x03, 0xdc, 0x5b, 0x71, 0x8c, 0xae, 0x17,
0xff, 0xa0, 0x9e, 0x0c, 0xc8, 0xd8, 0x0b, 0xa7,
0xb9, 0xf8, 0x6a, 0x4a, 0x7c, 0xe5, 0xc8, 0x72,
0x55},
33 // public key length
},

{ // another compressed example with 0x03 prefix
{0x9a, 0xbf, 0x38, 0x28, 0xda, 0xad, 0xb8, 0x73, // private exponent
0xea, 0xc9, 0xff, 0x3a, 0xeb, 0x79, 0xc9, 0x3e,
0x03, 0xca, 0x9c, 0x28, 0x6c, 0x63, 0x44, 0xf9,
0x37, 0x62, 0x27, 0x99, 0x04, 0x0c, 0x5d, 0x74},
true, // is compressed?
{0x03, 0x68, 0xd6, 0xaf, 0xa4, 0xe1, 0x62, 0xa1, // public key
0xa2, 0x46, 0x94, 0x30, 0xf9, 0x2d, 0xee, 0x74,
0x10, 0xf9, 0x4d, 0xd9, 0x9c, 0xa8, 0xca, 0x29,
0x8a, 0x2b, 0xcc, 0x6c, 0x5a, 0xb7, 0x92, 0xfc,
0xa3},
33 // public key length
},

{ // another compressed example with 0x02 prefix
{0x3c, 0x01, 0xb9, 0xbf, 0x95, 0x9a, 0x97, 0x35, // private exponent
0x35, 0x06, 0x81, 0xdc, 0xba, 0x7b, 0xe7, 0xe6,
0x62, 0xc2, 0x43, 0x9c, 0x1b, 0xa7, 0xb5, 0x9a,
0xc0, 0x71, 0x32, 0x44, 0xf3, 0x03, 0x95, 0x24},
true, // is compressed?
{0x02, 0xdc, 0x07, 0x31, 0xa3, 0x17, 0x61, 0x9c,
0xfd, 0x7c, 0x40, 0xf1, 0x7f, 0xa2, 0x0e, 0x7b,
0xd4, 0x4f, 0x2b, 0x5c, 0x68, 0x52, 0x5c, 0x1a,
0x09, 0xdb, 0x54, 0x41, 0xa4, 0xfb, 0xb6, 0xd6,
0xa6},
33 // public key length
}
};

/** Test vectors for RFC 6979 (deterministic signatures) test cases. */
struct RFC6979TestCase
{
	/** Private key. This is big-endian. */
	uint8_t private_key[32];
	/** Message to sign. */
	const char *message;
	/** Expected signature, as r concatenated with s, big-endian. */
	uint8_t expected_signature[32 + 32];
	/** Whether to hash message twice or not. */
	bool double_hash;
};

static const struct RFC6979TestCase rfc6979_test_cases[] = {
// These next 5 test vectors are from user fpgaminer on the bitcointalk
// forums. These were obtained from
// https://bitcointalk.org/index.php?topic=285142.msg3299061#msg3299061
// on 9 April 2015.
{ // fpgaminer test vector 1
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // private key
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
"Satoshi Nakamoto", // message
{0x93, 0x4b, 0x1e, 0xa1, 0x0a, 0x4b, 0x3c, 0x17, // expected signature: r || s
0x57, 0xe2, 0xb0, 0xc0, 0x17, 0xd0, 0xb6, 0x14,
0x3c, 0xe3, 0xc9, 0xa7, 0xe6, 0xa4, 0xa4, 0x98,
0x60, 0xd7, 0xa6, 0xab, 0x21, 0x0e, 0xe3, 0xd8,
0x24, 0x42, 0xce, 0x9d, 0x2b, 0x91, 0x60, 0x64,
0x10, 0x80, 0x14, 0x78, 0x3e, 0x92, 0x3e, 0xc3,
0x6b, 0x49, 0x74, 0x3e, 0x2f, 0xfa, 0x1c, 0x44,
0x96, 0xf0, 0x1a, 0x51, 0x2a, 0xaf, 0xd9, 0xe5},
false // use SHA-256 once
},
{ // fpgaminer test vector 2
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // private key
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
"All those moments will be lost in time, like tears in rain. Time to die...", // message
{0x86, 0x00, 0xdb, 0xd4, 0x1e, 0x34, 0x8f, 0xe5, // expected signature: r || s
0xc9, 0x46, 0x5a, 0xb9, 0x2d, 0x23, 0xe3, 0xdb,
0x8b, 0x98, 0xb8, 0x73, 0xbe, 0xec, 0xd9, 0x30,
0x73, 0x64, 0x88, 0x69, 0x64, 0x38, 0xcb, 0x6b,
0x54, 0x7f, 0xe6, 0x44, 0x27, 0x49, 0x6d, 0xb3,
0x3b, 0xf6, 0x60, 0x19, 0xda, 0xcb, 0xf0, 0x03,
0x9c, 0x04, 0x19, 0x9a, 0xbb, 0x01, 0x22, 0x91,
0x86, 0x01, 0xdb, 0x38, 0xa7, 0x2c, 0xfc, 0x21},
false // use SHA-256 once
},
{ // fpgaminer test vector 3
{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // private key
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x40},
"Satoshi Nakamoto", // message
{0xfd, 0x56, 0x7d, 0x12, 0x1d, 0xb6, 0x6e, 0x38, // expected signature: r || s
0x29, 0x91, 0x53, 0x4a, 0xda, 0x77, 0xa6, 0xbd,
0x31, 0x06, 0xf0, 0xa1, 0x09, 0x8c, 0x23, 0x1e,
0x47, 0x99, 0x34, 0x47, 0xcd, 0x6a, 0xf2, 0xd0,
0x6b, 0x39, 0xcd, 0x0e, 0xb1, 0xbc, 0x86, 0x03,
0xe1, 0x59, 0xef, 0x5c, 0x20, 0xa5, 0xc8, 0xad,
0x68, 0x5a, 0x45, 0xb0, 0x6c, 0xe9, 0xbe, 0xbe,
0xd3, 0xf1, 0x53, 0xd1, 0x0d, 0x93, 0xbe, 0xd5},
false // use SHA-256 once
},
{ // fpgaminer test vector 4
{0xf8, 0xb8, 0xaf, 0x8c, 0xe3, 0xc7, 0xcc, 0xa5, // private key
0xe3, 0x00, 0xd3, 0x39, 0x39, 0x54, 0x0c, 0x10,
0xd4, 0x5c, 0xe0, 0x01, 0xb8, 0xf2, 0x52, 0xbf,
0xbc, 0x57, 0xba, 0x03, 0x42, 0x90, 0x41, 0x81},
"Alan Turing", // message
{0x70, 0x63, 0xae, 0x83, 0xe7, 0xf6, 0x2b, 0xbb, // expected signature: r || s
0x17, 0x17, 0x98, 0x13, 0x1b, 0x4a, 0x05, 0x64,
0xb9, 0x56, 0x93, 0x00, 0x92, 0xb3, 0x3b, 0x07,
0xb3, 0x95, 0x61, 0x5d, 0x9e, 0xc7, 0xe1, 0x5c,
0x58, 0xdf, 0xcc, 0x1e, 0x00, 0xa3, 0x5e, 0x15,
0x72, 0xf3, 0x66, 0xff, 0xe3, 0x4b, 0xa0, 0xfc,
0x47, 0xdb, 0x1e, 0x71, 0x89, 0x75, 0x9b, 0x9f,
0xb2, 0x33, 0xc5, 0xb0, 0x5a, 0xb3, 0x88, 0xea},
false // use SHA-256 once
},
{ // fpgaminer test vector 5
{0xe9, 0x16, 0x71, 0xc4, 0x62, 0x31, 0xf8, 0x33, // private key
0xa6, 0x40, 0x6c, 0xcb, 0xea, 0x0e, 0x3e, 0x39,
0x2c, 0x76, 0xc1, 0x67, 0xba, 0xc1, 0xcb, 0x01,
0x3f, 0x6f, 0x10, 0x13, 0x98, 0x04, 0x55, 0xc2},
"There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!", // message
{0xb5, 0x52, 0xed, 0xd2, 0x75, 0x80, 0x14, 0x1f, // expected signature: r || s
0x3b, 0x2a, 0x54, 0x63, 0x04, 0x8c, 0xb7, 0xcd,
0x3e, 0x04, 0x7b, 0x97, 0xc9, 0xf9, 0x80, 0x76,
0xc3, 0x2d, 0xbd, 0xf8, 0x5a, 0x68, 0x71, 0x8b,
0x27, 0x9f, 0xa7, 0x2d, 0xd1, 0x9b, 0xfa, 0xe0,
0x55, 0x77, 0xe0, 0x6c, 0x7c, 0x0c, 0x19, 0x00,
0xc3, 0x71, 0xfc, 0xd5, 0x89, 0x3f, 0x7e, 0x1d,
0x56, 0xa3, 0x7d, 0x30, 0x17, 0x46, 0x71, 0xf6},
false // use SHA-256 once
},

// These next 2 test vectors are from user plaprade on the bitcointalk
// forums. These were obtained from
// https://bitcointalk.org/index.php?topic=285142.msg3300992#msg3300992
// on 9 April 2015. One requires s to be negated and the other doesn't.
{ // plaprade test vector 1
{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // private key
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x40},
"Equations are more important to me, because politics is for the present, but an equation is something for eternity.", // message
{0x54, 0xc4, 0xa3, 0x3c, 0x64, 0x23, 0xd6, 0x89, // expected signature: r || s
0x37, 0x8f, 0x16, 0x0a, 0x7f, 0xf8, 0xb6, 0x13,
0x30, 0x44, 0x4a, 0xbb, 0x58, 0xfb, 0x47, 0x0f,
0x96, 0xea, 0x16, 0xd9, 0x9d, 0x4a, 0x2f, 0xed,
0x07, 0x08, 0x23, 0x04, 0x41, 0x0e, 0xfa, 0x6b,
0x29, 0x43, 0x11, 0x1b, 0x6a, 0x4e, 0x0a, 0xaa,
0x7b, 0x7d, 0xb5, 0x5a, 0x07, 0xe9, 0x86, 0x1d,
0x1f, 0xb3, 0xcb, 0x1f, 0x42, 0x10, 0x44, 0xa5},
false // use SHA-256 once
},
{ // plaprade test vector 2
{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // private key
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x69, 0x16,
0xd0, 0xf9, 0xb3, 0x1d, 0xc9, 0xb6, 0x37, 0xf3},
"The question of whether computers can think is like the question of whether submarines can swim.", // message
{0xcd, 0xe1, 0x30, 0x2d, 0x83, 0xf8, 0xdd, 0x83, // expected signature: r || s
0x5d, 0x89, 0xae, 0xf8, 0x03, 0xc7, 0x4a, 0x11,
0x9f, 0x56, 0x1f, 0xba, 0xef, 0x3e, 0xb9, 0x12,
0x9e, 0x45, 0xf3, 0x0d, 0xe8, 0x6a, 0xbb, 0xf9,
0x06, 0xce, 0x64, 0x3f, 0x50, 0x49, 0xee, 0x1f,
0x27, 0x89, 0x04, 0x67, 0xb7, 0x7a, 0x6a, 0x8e,
0x11, 0xec, 0x46, 0x61, 0xcc, 0x38, 0xcd, 0x8b,
0xad, 0xf9, 0x01, 0x15, 0xfb, 0xd0, 0x3c, 0xef},
false // use SHA-256 once
},

// These next 2 test vectors are from Bitcoin Core's test suite. They were
// obtained from:
// https://github.com/bitcoin/bitcoin/blob/master/src/test/key_tests.cpp
// on 10 April 2015.
// Commit: 92fd887fd42a61e95f716d3193104827f60f856c
{ // Bitcoin Core: strSecret1
{0x12, 0xb0, 0x04, 0xff, 0xf7, 0xf4, 0xb6, 0x9e, // private key = 5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj
0xf8, 0x65, 0x0e, 0x76, 0x7f, 0x18, 0xf1, 0x1e,
0xde, 0x15, 0x81, 0x48, 0xb4, 0x25, 0x66, 0x07,
0x23, 0xb9, 0xf9, 0xa6, 0x6e, 0x61, 0xf7, 0x47},
"Very deterministic message", // message
{0x5d, 0xbb, 0xdd, 0xda, 0x71, 0x77, 0x2d, 0x95, // expected signature: r || s
0xce, 0x91, 0xcd, 0x2d, 0x14, 0xb5, 0x92, 0xcf,
0xbc, 0x1d, 0xd0, 0xaa, 0xbd, 0x6a, 0x39, 0x4b,
0x6c, 0x2d, 0x37, 0x7b, 0xbe, 0x59, 0xd3, 0x1d,
0x14, 0xdd, 0xda, 0x21, 0x49, 0x4a, 0x4e, 0x22,
0x1f, 0x08, 0x24, 0xf0, 0xb8, 0xb9, 0x24, 0xc4,
0x3f, 0xa4, 0x3c, 0x0a, 0xd5, 0x7d, 0xcc, 0xda,
0xa1, 0x1f, 0x81, 0xa6, 0xbd, 0x45, 0x82, 0xf6},
true // use SHA-256 twice
},
{ // Bitcoin Core: strSecret2
{0xb5, 0x24, 0xc2, 0x8b, 0x61, 0xc9, 0xb2, 0xc4, // private key = 5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3
0x9b, 0x2c, 0x7d, 0xd4, 0xc2, 0xd7, 0x58, 0x87,
0xab, 0xb7, 0x87, 0x68, 0xc0, 0x54, 0xbd, 0x7c,
0x01, 0xaf, 0x40, 0x29, 0xf6, 0xc0, 0xd1, 0x17},
"Very deterministic message", // message
{0x52, 0xd8, 0xa3, 0x20, 0x79, 0xc1, 0x1e, 0x79, // expected signature: r || s
0xdb, 0x95, 0xaf, 0x63, 0xbb, 0x96, 0x00, 0xc5,
0xb0, 0x4f, 0x21, 0xa9, 0xca, 0x33, 0xdc, 0x12,
0x9c, 0x2b, 0xfa, 0x8a, 0xc9, 0xdc, 0x1c, 0xd5,
0x61, 0xd8, 0xae, 0x5e, 0x0f, 0x6c, 0x1a, 0x16,
0xbd, 0xe3, 0x71, 0x9c, 0x64, 0xc2, 0xfd, 0x70,
0xe4, 0x04, 0xb6, 0x42, 0x8a, 0xb9, 0xa6, 0x95,
0x66, 0x96, 0x2e, 0x87, 0x71, 0xb5, 0x94, 0x4d},
true // use SHA-256 twice
}

};

/** Order ("n") divided by 2. Obtained from BIP 0062, from the
  * section "Low S values in signatures". */
static const uint8_t halforder[32] = {
0xA0, 0x20, 0x1B, 0x68, 0x46, 0x2F, 0xE9, 0xDF,
0x1D, 0x50, 0xA4, 0x57, 0x73, 0x6E, 0x57, 0x5D,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F};

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

/** Decompress an elliptic curve point - that is, given only the x value of
  * a point, this will calculate the y value. This means that only the x value
  * needs to be stored, which decreases memory use at the expense of time.
  * \param point The point to decompress. Only the x field needs to be filled
  *              in - the y field will be ignored and overwritten.
  * \param is_odd For any x value, there are two valid y values - one odd and
  *               one even. This parameter instructs the function to pick
  *               one of them. Use 0 to pick the even one, 1 to pick the odd
  *               one.
  * \return false on success, true if point could not be decompressed.
  */
static bool ecdsaPointDecompress(PointAffine *point, uint8_t is_odd)
{
	uint8_t temp[32];
	uint8_t sqrt_y_squared[32];
	uint8_t x_cubed_plus_b[32];
	uint8_t is_sqrt_y_squared_odd;
	uint8_t supposed_to_be_odd;
	BigNum256 lookup[2];
	unsigned int i;
	unsigned int byte_num;
	unsigned int bit_num;

	setFieldToP();
	bigMultiply(x_cubed_plus_b, point->x, point->x);
	bigMultiply(x_cubed_plus_b, x_cubed_plus_b, point->x);
	bigAdd(x_cubed_plus_b, x_cubed_plus_b, (BigNum256)secp256k1_b); // x_cubed_plus_b = x^3 + b = y^2
	// Since y^2 = x^3 + b in secp256k1, y = sqrt(x^3 + b). The square
	// root can be performed using the Tonelli-Shanks algorithm. Here, a special
	// case is used, which only works for p = 3 (mod 4) - this is satisfied for
	// the secp256k1 curve. For more information see:
	// http://point-at-infinity.org/ecc/Algorithm_of_Shanks_&_Tonelli.html
	// Exponentiation is done by a standard binary square-and-multiply
	// algorithm.
	bigSetZero(sqrt_y_squared);
	sqrt_y_squared[0] = 1;
	for (i = 255; i < 256; i--)
	{
		bigMultiply(sqrt_y_squared, sqrt_y_squared, sqrt_y_squared);
		byte_num = i >> 3;
		bit_num = i & 7;
		// Yes, this is a data-dependent branch, but it is based on
		// secp256k1_p_plus1over4, which is a (public) constant.
		if (((secp256k1_p_plus1over4[byte_num] >> bit_num) & 1) != 0)
		{
			bigMultiply(sqrt_y_squared, sqrt_y_squared, x_cubed_plus_b);
		}
	}
	// sqrt(y^2) has two solutions ("positive" and "negative"). One of the
	// solutions is odd and the other even. The is_odd parameter controls
	// which one is picked.
	bigSubtractNoModulo(temp, (BigNum256)secp256k1_p, sqrt_y_squared); // temp = -sqrt_y_squared
	is_sqrt_y_squared_odd = (uint8_t)(sqrt_y_squared[0] & 1);
	supposed_to_be_odd = (uint8_t)(is_odd & 1);
	lookup[0] = sqrt_y_squared; // sqrt_y_squared has correct least significant bit
	lookup[1] = temp; // sqrt_y_squared has incorrect least significant bit; use -sqrt_y_squared
	memcpy(point->y, lookup[is_sqrt_y_squared_odd ^ supposed_to_be_odd], sizeof(point->y));

	// Check that y^2 does actually equal x^3 + b (i.e. the point is on the
	// curve).
	bigMultiply(temp, point->y, point->y);
	if (bigCompare(temp, x_cubed_plus_b) == BIGCMP_EQUAL)
	{
		return false; // success
	}
	else
	{
		return true; // could not decompress (resulting point is not on curve)
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
	uint8_t r_again[32];
	uint8_t s_again[32];
	uint8_t private_key[32];
	uint8_t public_key_x[32];
	uint8_t public_key_y[32];
	uint8_t hash[32];
	uint8_t serialised[ECDSA_MAX_SERIALISE_SIZE + 10];
	uint8_t serialised_sentinel[10]; // used to detect writes beyond serialised[ECDSA_MAX_SERIALISE_SIZE]
	uint8_t serialised_size;
	uint8_t is_odd;
	int fail_count;
	int i;
	unsigned int j;
	FILE *f;
	HashState hs;

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

	// Test that those points can be serialised and decompressed.
	for (i = 1; i < 300; i++)
	{
		fillWithRandom(serialised_sentinel, sizeof(serialised_sentinel));
		memcpy(&compare, &p, sizeof(compare));
		memcpy(&(serialised[ECDSA_MAX_SERIALISE_SIZE]), serialised_sentinel, sizeof(serialised_sentinel));
		ecdsaSerialise(serialised, &p, true);
		if (memcmp(serialised_sentinel, &(serialised[ECDSA_MAX_SERIALISE_SIZE]), sizeof(serialised_sentinel)) != 0)
		{
			printf("Serialisation of public key %d wrote beyond end of ECDSA_MAX_SERIALISE_SIZE\n", i);
			reportFailure();
		}
		else if (serialised[0] == 0x02)
		{
			is_odd = 0;
			reportSuccess();
		}
		else if (serialised[0] == 0x03)
		{
			is_odd = 1;
			reportSuccess();
		}
		else
		{
			printf("Serialisation of public key %d gave unexpected prefix\n", i);
			reportFailure();
		}
		memset(compare.y, 42, sizeof(compare.y)); // invalidate y component
		if(ecdsaPointDecompress(&compare, is_odd))
		{
			printf("ecdsaPointDecompress() failed to decompress public key %d\n", i);
			reportFailure();
		}
		else if (memcmp(&compare, &p, sizeof(compare)) != 0) // was the y component recovered?
		{
			printf("Decompressed public key %d does not match original\n", i);
			reportFailure();
		}
		else
		{
			reportSuccess();
		}
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

	// Test that ecdsaPointDecompress() doesn't always succeed.
	fail_count = 0;
	for (i = 0; i < 100; i++)
	{
		// Statistically, about 50% of x values can't be decompressed as an
		// appropriate quadratic residue does not exist.
		p.is_point_at_infinity = 0;
		fillWithRandom(p.x, sizeof(p.x));
		if (ecdsaPointDecompress(&p, false))
		{
			fail_count++;
		}
	}
	if (fail_count == 0)
	{
		printf("ecdsaPointDecompress() always succeeds");
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
			fillWithRandom(hash, sizeof(hash));
		}
		skipWhiteSpace(f);
		bigFRead(private_key, f);
		skipWhiteSpace(f);
		bigFRead(public_key_x, f);
		skipWhiteSpace(f);
		bigFRead(public_key_y, f);
		skipWhiteSpace(f);
		ecdsaSign(r, s, hash, private_key);
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

	// Test serialisation/decompression against vectors in pointMultiply test
	// (the ones generated by OpenSSL).
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
		skipWhiteSpace(f);
		bigFRead(private_key, f);
		skipWhiteSpace(f);
		bigFRead(p.x, f);
		skipWhiteSpace(f);
		bigFRead(p.y, f);
		skipWhiteSpace(f);
		p.is_point_at_infinity = 0;
		fillWithRandom(serialised_sentinel, sizeof(serialised_sentinel));
		memcpy(&compare, &p, sizeof(compare));
		memcpy(&(serialised[ECDSA_MAX_SERIALISE_SIZE]), serialised_sentinel, sizeof(serialised_sentinel));
		ecdsaSerialise(serialised, &p, true);
		if (memcmp(serialised_sentinel, &(serialised[ECDSA_MAX_SERIALISE_SIZE]), sizeof(serialised_sentinel)) != 0)
		{
			printf("Serialisation of OpenSSL public key %d wrote beyond end of ECDSA_MAX_SERIALISE_SIZE\n", i);
			reportFailure();
		}
		else if (serialised[0] == 0x02)
		{
			is_odd = 0;
			reportSuccess();
		}
		else if (serialised[0] == 0x03)
		{
			is_odd = 1;
			reportSuccess();
		}
		else
		{
			printf("Serialisation of OpenSSL public key %d gave unexpected prefix\n", i);
			reportFailure();
		}
		memset(compare.y, 1, sizeof(compare.y)); // invalidate y component
		if (ecdsaPointDecompress(&compare, is_odd))
		{
			printf("ecdsaPointDecompress() failed to decompress OpenSSL public key %d\n", i);
			reportFailure();
		}
		else if (memcmp(&compare, &p, sizeof(compare)) != 0) // was the y component recovered?
		{
			printf("Decompressed OpenSSL public key %d does not match original\n", i);
			reportFailure();
		}
		else
		{
			reportSuccess();
		}
		// Also check that uncompressed serialisation doesn't write beyond
		// end of array.
		fillWithRandom(serialised_sentinel, sizeof(serialised_sentinel));
		memcpy(&(serialised[ECDSA_MAX_SERIALISE_SIZE]), serialised_sentinel, sizeof(serialised_sentinel));
		ecdsaSerialise(serialised, &p, false);
		if (memcmp(serialised_sentinel, &(serialised[ECDSA_MAX_SERIALISE_SIZE]), sizeof(serialised_sentinel)) != 0)
		{
			printf("Uncompressed serialisation of OpenSSL public key %d wrote beyond end of ECDSA_MAX_SERIALISE_SIZE\n", i);
			reportFailure();
		}
		else if (serialised[0] == 0x02)
		{
			reportSuccess();
		}
	}
	fclose(f);

	// Test that serialisation produces the same results as
	// https://brainwallet.github.io/ and that point decompression also
	// recovers the public key.
	// These tests are mainly to ensure the 0x02/0x03 prefixes are round the
	// right way.
	for (i = 0; i < (sizeof(brainwallet_test_cases) / sizeof(struct BrainwalletTestCase)); i++)
	{
		fillWithRandom(serialised_sentinel, sizeof(serialised_sentinel));
		memcpy(private_key, brainwallet_test_cases[i].private_exponent, sizeof(private_key));
		swapEndian256(private_key); // private_exponent is big-endian, pointMultiply() expects little-endian
		setToG(&p);
		pointMultiply(&p, private_key);
		// Test serialisation
		memcpy(&(serialised[ECDSA_MAX_SERIALISE_SIZE]), serialised_sentinel, sizeof(serialised_sentinel));
		serialised_size = ecdsaSerialise(serialised, &p, brainwallet_test_cases[i].is_compressed);
		if (memcmp(serialised_sentinel, &(serialised[ECDSA_MAX_SERIALISE_SIZE]), sizeof(serialised_sentinel)) != 0)
		{
			printf("Brainwallet test case %d causes write beyond end of ECDSA_MAX_SERIALISE_SIZE", i);
			reportFailure();
		}
		else if (serialised_size != brainwallet_test_cases[i].serialised_size)
		{
			printf("Brainwallet test case %d produced mismatching serialised size", i);
			reportFailure();
		}
		else if (memcmp(serialised, brainwallet_test_cases[i].serialised, serialised_size) != 0)
		{
			printf("Brainwallet test case %d produced mismatching serialised contents", i);
			reportFailure();
		}
		else
		{
			reportSuccess();
		}

		// Test decompression
		memcpy(&compare, &p, sizeof(compare));
		memset(compare.y, 0, sizeof(compare.y)); // invalidate y component
		if (brainwallet_test_cases[i].is_compressed)
		{
			is_odd = brainwallet_test_cases[i].serialised[0] & 1; // get is_odd from prefix
		}
		else
		{
			is_odd = brainwallet_test_cases[i].serialised[33] & 1; // get is_odd from test case y component
		}
		if (ecdsaPointDecompress(&compare, is_odd))
		{
			printf("ecdsaPointDecompress() failed to decompress brainwallet public key %d\n", i);
			reportFailure();
		}
		else if (memcmp(&compare, &p, sizeof(compare)) != 0) // was the y component recovered?
		{
			printf("Decompressed brainwallet public key %d does not match original\n", i);
			reportFailure();
		}
		else
		{
			reportSuccess();
		}
	}

	// Test that ecdsaSign() produces deterministic signatures which match
	// other implementations.
	for (i = 0; i < (sizeof(rfc6979_test_cases) / sizeof(struct RFC6979TestCase)); i++)
	{
		sha256Begin(&hs);
		for (j = 0; j < strlen(rfc6979_test_cases[i].message); j++)
		{
			sha256WriteByte(&hs, rfc6979_test_cases[i].message[j]);
		}
		if (rfc6979_test_cases[i].double_hash)
		{
			sha256FinishDouble(&hs);
		}
		else
		{
			sha256Finish(&hs);
		}
		writeHashToByteArray(hash, &hs, false);
		memcpy(private_key, rfc6979_test_cases[i].private_key, 32);
		swapEndian256(private_key); // big-endian -> little-endian
		ecdsaSign(r, s, hash, private_key);
		swapEndian256(r); // little-endian -> big-endian
		swapEndian256(s); // little-endian -> big-endian
		if (memcmp(r, rfc6979_test_cases[i].expected_signature, 32)
			|| memcmp(s, &(rfc6979_test_cases[i].expected_signature[32]), 32))
		{
			printf("RFC6979 test case %d mismatch\n", i);
			printf("Expected:\n r = ");
			bigPrintVariableSize((const BigNum256)rfc6979_test_cases[i].expected_signature, 32, true);
			printf("\n s = ");
			bigPrintVariableSize((const BigNum256)&(rfc6979_test_cases[i].expected_signature[32]), 32, true);
			printf("\n");
			printf("Got:\n r = ");
			bigPrintVariableSize(r, 32, true);
			printf("\n s = ");
			bigPrintVariableSize(s, 32, true);
			printf("\n");
			reportFailure();
		}
		else
		{
			reportSuccess();
		}
		// Test that the signature actually is deterministic (is always the
		// same).
		ecdsaSign(r_again, s_again, hash, private_key);
		swapEndian256(r_again); // little-endian -> big-endian
		swapEndian256(s_again); // little-endian -> big-endian
		if (memcmp(r, r_again, 32)
			|| memcmp(s, s_again, 32))
		{
			printf("RFC6979 test case %d appears to be non-deterministic\n", i);
			reportFailure();
		}
		else
		{
			reportSuccess();
		}
	}

	// Test that signatures always have s <= order/2 (i.e. are canonical).
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
		skipWhiteSpace(f);
		bigFRead(private_key, f);
		skipWhiteSpace(f);
		bigFRead(p.x, f);
		skipWhiteSpace(f);
		bigFRead(p.y, f);
		skipWhiteSpace(f);
		p.is_point_at_infinity = 0;
		fillWithRandom(hash, sizeof(hash));
		ecdsaSign(r, s, hash, private_key);
		if (bigCompare(s, (const BigNum256)halforder) == BIGCMP_GREATER)
		{
			printf("Signature generated using private key %d not canonical\n", i);
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


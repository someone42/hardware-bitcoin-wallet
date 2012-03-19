// ***********************************************************************
// ecdsa.c
// ***********************************************************************
//
// Containes functions which perform group operations on points of an
// elliptic curve and sign a hash using those operations.
//
// The elliptic curve used is secp256k1, from the document
// "SEC 2: Recommended Elliptic Curve Domain Parameters" by Certicom
// research, obtained 11-August-2011 from:
// http://www.secg.org/collateral/sec2_final.pdf
//
// The operations here are written in a way as to encourage them to run in
// constant time. This provides some resistance against timing attacks.
// However, the compiler may use optimisations which destroy this property;
// inspection of the generated assembly code is the only way to check. A
// disadvantage of this code is that point multiplication is slower than
// it could be.
// There are some data-dependent branches in here, but they're expected to
// only make a difference (in timing) in exceptional cases.
//
// This file is licensed as described by the file LICENCE.

// Defining this will facilitate testing
//#define TEST

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#endif // #ifdef TEST

#if defined(AVR) && defined(__GNUC__)
#include <avr/io.h>
#include <avr/pgmspace.h>
#define LOOKUP_BYTE(x)		(pgm_read_byte_near(x))
#else
#define PROGMEM
#define LOOKUP_BYTE(x)		(*(x))
#endif // #if defined(AVR) && defined(__GNUC__)

#include "common.h"
#include "bignum256.h"
#include "ecdsa.h"

// A point on the elliptic curve, in Jacobian coordinates. Jacobian
// coordinates (x, y, z) are related to affine coordinates
// (x_affine, y_affine) by:
// (x_affine, y_affine) = (x / (z ^ 2), y / (z ^ 3)).
// Why use Jacobian coordinates? Because then point addition and point
// doubling don't have to use inversion (division), which is very slow.
typedef struct point_jacobian_type
{
	u8 x[32];
	u8 y[32];
	u8 z[32];
	// If is_point_at_infinity is non-zero, then this point represents the
	// point at infinity and all other structure members are considered
	// invalid.
	u8 is_point_at_infinity;
} point_jacobian;

// The prime number used to define the prime field for secp256k1
static const u8 secp256k1_p[32] = {
0x2f, 0xfc, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static const u8 secp256k1_compp[5] = {
0xd1, 0x03, 0x00, 0x00, 0x01};

// The order of the base point used in secp256k1
static const u8 secp256k1_n[32] = {
0x41, 0x41, 0x36, 0xd0, 0x8c, 0x5e, 0xd2, 0xbf,
0x3b, 0xa0, 0x48, 0xaf, 0xe6, 0xdc, 0xae, 0xba,
0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static const u8 secp256k1_compn[17] = {
0xbf, 0xbe, 0xc9, 0x2f, 0x73, 0xa1, 0x2d, 0x40,
0xc4, 0x5f, 0xb7, 0x50, 0x19, 0x23, 0x51, 0x45,
0x01};

// The x component of the base point G used in secp256k1
static const u8 secp256k1_Gx[32] PROGMEM = {
0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59,
0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b, 0x02,
0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55,
0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66, 0xbe, 0x79};

// The y component of the base point G used in secp256k1
static const u8 secp256k1_Gy[32] PROGMEM = {
0xb8, 0xd4, 0x10, 0xfb, 0x8f, 0xd0, 0x47, 0x9c,
0x19, 0x54, 0x85, 0xa6, 0x48, 0xb4, 0x17, 0xfd,
0xa8, 0x08, 0x11, 0x0e, 0xfc, 0xfb, 0xa4, 0x5d,
0x65, 0xc4, 0xa3, 0x26, 0x77, 0xda, 0x3a, 0x48};

#ifdef TEST
static void bigprint(bignum256 number)
{
	u8 i;
	for (i = 31; i < 32; i--)
	{
		printf("%02x", number[i]);
	}
}
#endif // #ifdef TEST

// Convert a point from affine coordinates to Jacobian coordinates. This
// is very fast.
static void affine_to_jacobian(point_jacobian *out, point_affine *in)
{
	out->is_point_at_infinity = in->is_point_at_infinity;
	// If out->is_point_at_infinity != 0, the rest of this function consists
	// of dummy operations.
	bigassign(out->x, in->x);
	bigassign(out->y, in->y);
	bigsetzero(out->z);
	out->z[0] = 1;
}

// Convert a point from Jacobian coordinates to affine coordinates. This
// is very slow because it involves inversion (division).
static NOINLINE void jacobian_to_affine(point_affine *out, point_jacobian *in)
{
	u8 s[32];
	u8 t[32];

	out->is_point_at_infinity = in->is_point_at_infinity;
	// If out->is_point_at_infinity != 0, the rest of this function consists
	// of dummy operations.
	bigmultiply(s, in->z, in->z);
	bigmultiply(t, s, in->z);
	// Now s = z ^ 2 and t = z ^ 3
	biginvert(s, s);
	biginvert(t, t);
	bigmultiply(out->x, in->x, s);
	bigmultiply(out->y, in->y, t);
}

// Double the point p (which is in Jacobian coordinates), placing the
// result back into p.
// The formulae for this function were obtained from the article:
// "Software Implementation of the NIST Elliptic Curves Over Prime Fields",
// obtained from:
// http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.25.8619&rep=rep1&type=pdf
// on 16-August-2011. See equations (2) ("doubling in Jacobian coordinates")
// from section 4 of that article.
static NOINLINE void point_double(point_jacobian *p)
{
	u8 t[32];
	u8 u[32];

	// If p->is_point_at_infinity != 0, then the rest of this function will
	// consist of dummy operations. Nothing else needs to be done since
	// 2O = O.

	// If y is zero then the tangent line is vertical and never hits the
	// curve, therefore the result should be O. If y is zero, the rest of this
	// function will consist of dummy operations.
	p->is_point_at_infinity |= bigiszero(p->y);

	bigmultiply(p->z, p->z, p->y);
	bigadd(p->z, p->z, p->z);
	bigmultiply(p->y, p->y, p->y);
	bigmultiply(t, p->y, p->x);
	bigadd(t, t, t);
	bigadd(t, t, t);
	// t is now 4.0 * p->x * p->y ^ 2
	bigmultiply(p->x, p->x, p->x);
	bigassign(u, p->x);
	bigadd(u, u, u);
	bigadd(u, u, p->x);
	// u is now 3.0 * p->x ^ 2
	// For curves with a != 0, a * p->z ^ 4 needs to be added to u.
	// But since a == 0 in secp256k1, we save 2 squarings and 1
	// multiplication.
	bigmultiply(p->x, u, u);
	bigsubtract(p->x, p->x, t);
	bigsubtract(p->x, p->x, t);
	bigsubtract(t, t, p->x);
	bigmultiply(t, t, u);
	bigmultiply(p->y, p->y, p->y);
	bigadd(p->y, p->y, p->y);
	bigadd(p->y, p->y, p->y);
	bigadd(p->y, p->y, p->y);
	bigsubtract(p->y, t, p->y);
}

// Add the point p2 (which is in affine coordinates) to the point p1 (which
// is in Jacobian coordinates), storing the result back into p1.
// Mixed coordinates are used because it reduces the number of squarings and
// multiplications from 16 to 11.
// See equations (3) ("addition in mixed Jacobian-affine coordinates") from
// section 4 of that article described in the comments to point_double().
// junk must point at some memory area to redirect dummy writes to.
static NOINLINE void point_add(point_jacobian *p1, point_jacobian *junk, point_affine *p2)
{
	u8 s[32];
	u8 t[32];
	u8 u[32];
	u8 v[32];
	u8 is_O;
	u8 is_O2;
	u8 cmp_xs;
	u8 cmp_yt;
	point_jacobian *lookup[2];

	lookup[0] = p1;
	lookup[1] = junk;

	// O + p2 == p2
	// If p1 is O, then copy p2 into p1 and redirect all writes to the dummy
	// write area.
	// The following line does: "is_O = p1->is_point_at_infinity ? 1 : 0;"
	is_O = (u8)((((u16)(-(int)p1->is_point_at_infinity)) >> 8) & 1);
	affine_to_jacobian(lookup[1 - is_O], p2);
	p1 = lookup[is_O];
	lookup[0] = p1; // p1 might have changed

	// p1 + O == p1
	// If p2 is O, then redirect all writes to the dummy write area. This
	// preserves the value of p1.
	// The following line does: "is_O2 = p2->is_point_at_infinity ? 1 : 0;"
	is_O2 = (u8)((((u16)(-(int)p2->is_point_at_infinity)) >> 8) & 1);
	p1 = lookup[is_O2];
	lookup[0] = p1; // p1 might have changed

	bigmultiply(s, p1->z, p1->z);
	bigmultiply(t, s, p1->z);
	bigmultiply(t, t, p2->y);
	bigmultiply(s, s, p2->x);
	// The following two lines do: "cmp_xs = bigcmp(p1->x, s) == BIGCMP_EQUAL ? 0 : 0xff;"
	cmp_xs = (u8)(bigcmp(p1->x, s) ^ BIGCMP_EQUAL);
	cmp_xs = (u8)(((u16)(-(int)cmp_xs)) >> 8);
	// The following two lines do: "cmp_yt = bigcmp(p1->y, t) == BIGCMP_EQUAL ? 0 : 0xff;"
	cmp_yt = (u8)(bigcmp(p1->y, t) ^ BIGCMP_EQUAL);
	cmp_yt = (u8)(((u16)(-(int)cmp_yt)) >> 8);
	// The following branch can never be taken when calling point_multiply(),
	// so its existence doesn't compromise timing regularity.
	if ((cmp_xs | cmp_yt | is_O | is_O2) == 0)
	{
		// Points are actually the same; use point doubling
		point_double(p1);
		return;
	}
	// p2 == -p1 when p1->x == s and p1->y != t.
	// If p1->is_point_at_infinity is set, then all subsequent operations in
	// this function become dummy operations.
	p1->is_point_at_infinity = (u8)(p1->is_point_at_infinity | (~cmp_xs & cmp_yt & 1));
	bigsubtract(s, s, p1->x);
	// s now contains p2->x * p1->z ^ 2 - p1->x
	bigsubtract(t, t, p1->y);
	// t now contains p2->y * p1->z ^ 3 - p1->y
	bigmultiply(p1->z, p1->z, s);
	bigmultiply(v, s, s);
	bigmultiply(u, v, p1->x);
	bigmultiply(p1->x, t, t);
	bigmultiply(s, s, v);
	bigsubtract(p1->x, p1->x, s);
	bigsubtract(p1->x, p1->x, u);
	bigsubtract(p1->x, p1->x, u);
	bigsubtract(u, u, p1->x);
	bigmultiply(u, u, t);
	bigmultiply(s, s, p1->y);
	bigsubtract(p1->y, u, s);
}

// Perform scalar multiplication of the point p by the scalar k.
// The result will be stored back into p. The multiplication is
// accomplished by repeated point doubling and adding of the
// original point.
void point_multiply(point_affine *p, bignum256 k)
{
	point_jacobian accumulator;
	point_jacobian junk;
	point_affine always_point_at_infinity;
	u8 i;
	u8 j;
	u8 onebyte;
	u8 onebit;
	point_affine *lookup_affine[2];

	accumulator.is_point_at_infinity = 1;
	always_point_at_infinity.is_point_at_infinity = 1;
	lookup_affine[1] = p;
	lookup_affine[0] = &always_point_at_infinity;
	for (i = 31; i < 32; i--)
	{
		onebyte = k[i];
		for (j = 0; j < 8; j++)
		{
			point_double(&accumulator);
			onebit = (u8)((onebyte & 0x80) >> 7);
			point_add(&accumulator, &junk, lookup_affine[onebit]);
			onebyte = (u8)(onebyte << 1);
		}
	}
	jacobian_to_affine(p, &accumulator);
}

// Set the point p to the base point of secp256k1.
void set_to_G(point_affine *p)
{
	u8 buffer[32];
	u8 i;

	p->is_point_at_infinity = 0;
	for (i = 0; i < 32; i++)
	{
		buffer[i] = LOOKUP_BYTE(&(secp256k1_Gx[i]));
	}
	bigassign(p->x, (bignum256)buffer);
	for (i = 0; i < 32; i++)
	{
		buffer[i] = LOOKUP_BYTE(&(secp256k1_Gy[i]));
	}
	bigassign(p->y, (bignum256)buffer);
}

// Set field parameters to be those defined by the prime number p which
// is used in secp256k1.
void set_field_to_p(void)
{
	bigsetfield(secp256k1_p, secp256k1_compp, sizeof(secp256k1_compp));
}

// Attempt to sign the message with message digest specified by hash. The
// signature will be done using the private key specified by privatekey and
// the integer k. k must be random (not pseudo-random) and must be different
// for each call to this function.
// hash, privatekey and k are all expected to be 256-bit integers in
// little-endian format.
// This function will return 0 and fill r and s with the signature upon
// success. This function will return 1 upon failure. If this function returns
// 1, an appropriate course of action is to pick another random integer k and
// try again. If a random number generator is truly random, failure should
// only occur if you are extremely unlucky.
// This is an implementation of the algorithm described in the document
// "SEC 1: Elliptic Curve Cryptography" by Certicom research, obtained
// 15-August-2011 from: http://www.secg.org/collateral/sec1_final.pdf,
// section 4.1.3 ("Signing Operation").
u8 ecdsa_sign(bignum256 r, bignum256 s, bignum256 hash, bignum256 privatekey, bignum256 k)
{
	point_affine bigR;

	// This is one of many data-dependent branches in this function. They do
	// not compromise timing attack resistance because these branches are
	// expected to occur extremely infrequently.
	if (bigiszero(k))
	{
		return 1;
	}
	if (bigcmp(k, (bignum256)secp256k1_n) != BIGCMP_LESS)
	{
		return 1;
	}

	// Compute ephemeral elliptic curve key pair (k, bigR)
	set_field_to_p();
	set_to_G(&bigR);
	point_multiply(&bigR, k);
	// bigR now contains k * G
	bigsetfield(secp256k1_n, secp256k1_compn, sizeof(secp256k1_compn));
	bigmod(r, bigR.x);
	// r now contains (k * G).x (mod n)
	if (bigiszero(r))
	{
		return 1;
	}
	bigmultiply(s, r, privatekey);
	bigmod(bigR.y, hash); // use bigR.y as temporary
	bigadd(s, s, bigR.y);
	biginvert(bigR.y, k);
	bigmultiply(s, s, bigR.y);
	// s now contains (hash + (r * privatekey)) / k (mod n)
	if (bigiszero(s))
	{
		return 1;
	}

	return 0;
}

#ifdef TEST

// The curve parameter b of secp256k1. The other parameter, a, is zero.
static const u8 secp256k1_b[32] = {
0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static int succeeded;
static int failed;

static void check_point_is_on_curve(point_affine *p)
{
	u8 ysquared[32];
	u8 xcubed[32];

	if (p->is_point_at_infinity)
	{
		// O is always on the curve
		succeeded++;
		return;
	}
	bigmultiply(ysquared, p->y, p->y);
	bigmultiply(xcubed, p->x, p->x);
	bigmultiply(xcubed, xcubed, p->x);
	bigadd(xcubed, xcubed, (bignum256)secp256k1_b);
	if (bigcmp(ysquared, xcubed) != BIGCMP_EQUAL)
	{
		printf("Point is not on curve\n");
		printf("x = ");
		bigprint(p->x);
		printf("\n");
		printf("y = ");
		bigprint(p->y);
		printf("\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
}

// Read little-endian hex string containing 256-bit integer and store into r
static void bigfread(bignum256 r, FILE *f)
{
	int i;
	int val;

	for (i = 0; i < 32; i++)
	{
		fscanf(f, "%02x", &val);
		r[i] = (u8)(val & 0xff);
	}
}

static void skipwhitespace(FILE *f)
{
	int onechar;
	do
	{
		onechar = fgetc(f);
	} while ((onechar == ' ') || (onechar == '\t') || (onechar == '\n') || (onechar == '\r'));
	ungetc(onechar, f);
}

// For testing only.
// Returns 0 if signature is good, 1 otherwise.
// (r, s) is the signature. hash is the message digest of the message that was
// signed. (pubkey_x, pubkey_y) is the public key. All are supposed to be
// little-endian 256-bit integers.
static int crappy_verify_signature(bignum256 r, bignum256 s, bignum256 hash, bignum256 pubkey_x, bignum256 pubkey_y)
{
	point_affine p;
	point_affine p2;
	point_jacobian pj;
	point_jacobian junk;
	point_affine result;
	u8 temp1[32];
	u8 temp2[32];
	u8 k1[32];
	u8 k2[32];

	bigsetfield(secp256k1_n, secp256k1_compn, sizeof(secp256k1_compn));
	bigmod(temp1, hash);
	biginvert(temp2, s);
	bigmultiply(k1, temp2, temp1);
	bigmultiply(k2, temp2, r);
	set_field_to_p();
	bigmod(k1, k1);
	bigmod(k2, k2);
	set_to_G(&p);
	point_multiply(&p, k1);
	p2.is_point_at_infinity = 0;
	bigassign(p2.x, pubkey_x);
	bigassign(p2.y, pubkey_y);
	point_multiply(&p2, k2);
	affine_to_jacobian(&pj, &p);
	point_add(&pj, &junk, &p2);
	jacobian_to_affine(&result, &pj);
	bigsetfield(secp256k1_n, secp256k1_compn, sizeof(secp256k1_compn));
	bigmod(result.x, result.x);
	if (bigcmp(result.x, r) == BIGCMP_EQUAL)
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
	point_affine p;
	point_jacobian p2;
	point_jacobian junk;
	point_affine compare;
	u8 temp[32];
	u8 r[32];
	u8 s[32];
	u8 privkey[32];
	u8 pubkey_x[32];
	u8 pubkey_y[32];
	u8 hash[32];
	int i;
	int j;
	FILE *f;

	succeeded = 0;
	failed = 0;

	set_field_to_p();

	// Check that G is on the curve
	set_to_G(&p);
	check_point_is_on_curve(&p);

	// Check that point at infinity ("O") actually acts as identity element
	p2.is_point_at_infinity = 1;
	// 2O = O
	point_double(&p2);
	if (!p2.is_point_at_infinity)
	{
		printf("Point double doesn't handle 2O properly\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	// O + O = O
	p.is_point_at_infinity = 1;
	point_add(&p2, &junk, &p);
	if (!p2.is_point_at_infinity)
	{
		printf("Point add doesn't handle O + O properly\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	// P + O = P
	set_to_G(&p);
	affine_to_jacobian(&p2, &p);
	p.is_point_at_infinity = 1;
	point_add(&p2, &junk, &p);
	jacobian_to_affine(&p, &p2);
	if ((p.is_point_at_infinity) 
		|| (bigcmp(p.x, (bignum256)secp256k1_Gx) != BIGCMP_EQUAL)
		|| (bigcmp(p.y, (bignum256)secp256k1_Gy) != BIGCMP_EQUAL))
	{
		printf("Point add doesn't handle P + O properly\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	// O + P = P
	p2.is_point_at_infinity = 1;
	set_to_G(&p);
	point_add(&p2, &junk, &p);
	jacobian_to_affine(&p, &p2);
	if ((p.is_point_at_infinity) 
		|| (bigcmp(p.x, (bignum256)secp256k1_Gx) != BIGCMP_EQUAL)
		|| (bigcmp(p.y, (bignum256)secp256k1_Gy) != BIGCMP_EQUAL))
	{
		printf("Point add doesn't handle O + P properly\n");
		failed++;
	}
	else
	{
		succeeded++;
	}

	// Test that P + P produces the same result as 2P
	set_to_G(&p);
	affine_to_jacobian(&p2, &p);
	point_add(&p2, &junk, &p);
	jacobian_to_affine(&compare, &p2);
	affine_to_jacobian(&p2, &p);
	point_double(&p2);
	jacobian_to_affine(&p, &p2);
	if ((p.is_point_at_infinity != compare.is_point_at_infinity) 
		|| (bigcmp(p.x, compare.x) != BIGCMP_EQUAL)
		|| (bigcmp(p.y, compare.y) != BIGCMP_EQUAL))
	{
		printf("P + P != 2P\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	check_point_is_on_curve(&compare);

	// Test that P + -P = O
	set_to_G(&p);
	affine_to_jacobian(&p2, &p);
	bigsetzero(temp);
	bigsubtract(p.y, temp, p.y);
	check_point_is_on_curve(&p);
	point_add(&p2, &junk, &p);
	if (!p2.is_point_at_infinity) 
	{
		printf("P + -P != O\n");
		failed++;
	}
	else
	{
		succeeded++;
	}

	// Test that 2P + P gives a point on curve
	set_to_G(&p);
	affine_to_jacobian(&p2, &p);
	point_double(&p2);
	point_add(&p2, &junk, &p);
	jacobian_to_affine(&p, &p2);
	check_point_is_on_curve(&p);

	// Test that point_multiply by 0 gives O
	set_to_G(&p);
	bigsetzero(temp);
	point_multiply(&p, temp);
	if (!p.is_point_at_infinity) 
	{
		printf("point_multiply not starting at O\n");
		failed++;
	}
	else
	{
		succeeded++;
	}

	// Test that point_multiply by 1 gives P back
	set_to_G(&p);
	bigsetzero(temp);
	temp[0] = 1;
	point_multiply(&p, temp);
	if ((p.is_point_at_infinity) 
		|| (bigcmp(p.x, (bignum256)secp256k1_Gx) != BIGCMP_EQUAL)
		|| (bigcmp(p.y, (bignum256)secp256k1_Gy) != BIGCMP_EQUAL))
	{
		printf("1 * P != P\n");
		failed++;
	}
	else
	{
		succeeded++;
	}

	// Test that point_multiply by 2 gives 2P back
	set_to_G(&p);
	bigsetzero(temp);
	temp[0] = 2;
	point_multiply(&p, temp);
	set_to_G(&compare);
	affine_to_jacobian(&p2, &compare);
	point_double(&p2);
	jacobian_to_affine(&compare, &p2);
	if ((p.is_point_at_infinity != compare.is_point_at_infinity) 
		|| (bigcmp(p.x, compare.x) != BIGCMP_EQUAL)
		|| (bigcmp(p.y, compare.y) != BIGCMP_EQUAL))
	{
		printf("2 * P != 2P\n");
		failed++;
	}
	else
	{
		succeeded++;
	}

	// Test that point_multiply by various constants gives a point on curve
	for (i = 0; i < 300; i++)
	{
		set_to_G(&p);
		bigsetzero(temp);
		temp[0] = (u8)(i & 0xff);
		temp[1] = (u8)((i >> 8) & 0xff);
		point_multiply(&p, temp);
		check_point_is_on_curve(&p);
	}

	// Test that n * G = O
	set_to_G(&p);
	point_multiply(&p, (bignum256)secp256k1_n);
	if (!p.is_point_at_infinity) 
	{
		printf("n * P != O\n");
		failed++;
	}
	else
	{
		succeeded++;
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
	// They are 256-bit integers stored big-endian.
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
		skipwhitespace(f);
		bigfread(temp, f);
		skipwhitespace(f);
		bigfread(compare.x, f);
		skipwhitespace(f);
		bigfread(compare.y, f);
		skipwhitespace(f);
		set_to_G(&p);
		point_multiply(&p, temp);
		check_point_is_on_curve(&p);
		if ((p.is_point_at_infinity != compare.is_point_at_infinity) 
			|| (bigcmp(p.x, compare.x) != BIGCMP_EQUAL)
			|| (bigcmp(p.y, compare.y) != BIGCMP_EQUAL))
		{
			printf("Keypair test vector %d failed\n", i);
			failed++;
		}
		else
		{
			succeeded++;
		}
	}
	fclose(f);

	// ecdsa_sign() should fail when k == 0 or k >= n
	bigsetzero(temp);
	if (!ecdsa_sign(r, s, temp, temp, temp))
	{
		printf("ecdsa_sign() accepts k == 0\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	bigassign(temp, (bignum256)secp256k1_n);
	if (!ecdsa_sign(r, s, temp, temp, temp))
	{
		printf("ecdsa_sign() accepts k == n\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	for (i = 0; i < 32; i++)
	{
		temp[i] = 0xff;
	}
	if (!ecdsa_sign(r, s, temp, temp, temp))
	{
		printf("ecdsa_sign() accepts k > n\n");
		failed++;
	}
	else
	{
		succeeded++;
	}

	// But it should succeed for k == n - 1
	bigassign(temp, (bignum256)secp256k1_n);
	temp[0] = 0x40;
	if (ecdsa_sign(r, s, temp, temp, temp))
	{
		printf("ecdsa_sign() does not accept k == n - 1\n");
		failed++;
	}
	else
	{
		succeeded++;
	}

	// Test signatures by signing and then verifying. For keypairs, just
	// use the ones generated for the point_multiply test.
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
			// Use all ones for hash
			for (j = 0; j < 32; j++)
			{
				hash[j] = 0xff;
			}
		}
		else if ((i & 3) == 1)
		{
			// Use all zeroes for hash
			for (j = 0; j < 32; j++)
			{
				hash[j] = 0x00;
			}
		}
		else
		{
			// Use a pseudo-random hash
			for (j = 0; j < 32; j++)
			{
				hash[j] = (u8)(rand() & 0xff);
			}
		}
		skipwhitespace(f);
		bigfread(privkey, f);
		skipwhitespace(f);
		bigfread(pubkey_x, f);
		skipwhitespace(f);
		bigfread(pubkey_y, f);
		skipwhitespace(f);
		do
		{
			for (j = 0; j < 32; j++)
			{
				temp[j] = (u8)(rand() & 0xff);
			}
		} while (ecdsa_sign(r, s, hash, privkey, temp));
		if (crappy_verify_signature(r, s, hash, pubkey_x, pubkey_y))
		{
			printf("Signature verify failed\n");
			printf("privkey = ");
			bigprint(privkey);
			printf("\n");
			printf("pubkey_x = ");
			bigprint(pubkey_x);
			printf("\n");
			printf("pubkey_y = ");
			bigprint(pubkey_y);
			printf("\n");
			printf("r = ");
			bigprint(r);
			printf("\n");
			printf("s = ");
			bigprint(s);
			printf("\n");
			printf("hash = ");
			bigprint(hash);
			printf("\n");
			printf("k = ");
			bigprint(temp);
			printf("\n");
			failed++;
		}
		else
		{
			succeeded++;
		}
	}
	fclose(f);

	printf("Tests which succeeded: %d\n", succeeded);
	printf("Tests which failed: %d\n", failed);

	exit(0);
}

#endif // #ifdef TEST


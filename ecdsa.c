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
// This file is licensed as described by the file LICENCE.

// Defining this will facilitate testing
//#define TEST

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#endif // #ifdef TEST

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
static const u8 secp256k1_Gx[32] = {
0x98, 0x17, 0xf8, 0x16, 0x5b, 0x81, 0xf2, 0x59,
0xd9, 0x28, 0xce, 0x2d, 0xdb, 0xfc, 0x9b, 0x02,
0x07, 0x0b, 0x87, 0xce, 0x95, 0x62, 0xa0, 0x55,
0xac, 0xbb, 0xdc, 0xf9, 0x7e, 0x66, 0xbe, 0x79};

// The y component of the base point G used in secp256k1
static const u8 secp256k1_Gy[32] = {
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
static void affine_to_jacobian(point_affine *in, point_jacobian *out)
{
	out->is_point_at_infinity = in->is_point_at_infinity;
	if (out->is_point_at_infinity == 0)
	{
		bigassign(out->x, in->x);
		bigassign(out->y, in->y);
		bigsetzero(out->z);
		out->z[0] = 1;
	}
}

// Convert a point from Jacobian coordinates to affine coordinates. This
// is very slow because it involves inversion (division).
static void jacobian_to_affine(point_jacobian *in, point_affine *out)
{
	u8 s[32];
	u8 t[32];

	out->is_point_at_infinity = in->is_point_at_infinity;
	if (out->is_point_at_infinity == 0)
	{
		bigmultiply(s, in->z, in->z);
		bigmultiply(t, s, in->z);
		// Now s = z ^ 2 and t = z ^ 3
		biginvert(s, s);
		biginvert(t, t);
		bigmultiply(out->x, in->x, s);
		bigmultiply(out->y, in->y, t);
	}
}

// Double the point p (which is in Jacobian coordinates), placing the
// result back into p.
// The formulae for this function were obtained from the article:
// "Software Implementation of the NIST Elliptic Curves Over Prime Fields",
// obtained from:
// http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.25.8619&rep=rep1&type=pdf
// on 16-August-2011. See equations (2) ("doubling in Jacobian coordinates")
// from section 4 of that article.
static void point_double(point_jacobian *p)
{
	u8 t[32];
	u8 u[32];

	if (p->is_point_at_infinity != 0)
	{
		// 2O = O
		return;
	}

	if (bigiszero(p->y) != 0)
	{
		// Tangent line is vertical and never hits curve
		p->is_point_at_infinity = 1;
		return;
	}
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
static void point_add(point_jacobian *p1, point_affine *p2)
{
	u8 s[32];
	u8 t[32];
	u8 u[32];
	u8 v[32];

	if (p1->is_point_at_infinity != 0)
	{
		// O + p2 == p2
		affine_to_jacobian(p2, p1);
		return;
	}
	else if(p2->is_point_at_infinity != 0)
	{
		// p1 + O == p1
		return;
	}

	bigmultiply(s, p1->z, p1->z);
	bigmultiply(t, s, p1->z);
	bigmultiply(t, t, p2->y);
	bigmultiply(s, s, p2->x);
	if (bigcmp(p1->x, s) == BIGCMP_EQUAL)
	{
		if (bigcmp(p1->y, t) == BIGCMP_EQUAL)
		{
			// Points are actually the same; use point doubling
			point_double(p1);
			return;
		}
		else
		{
			// p2 == -p1
			p1->is_point_at_infinity = 1;
			return;
		}
	}
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
	u8 i;
	u8 j;
	u8 onebyte;

	accumulator.is_point_at_infinity = 1;
	for (i = 31; i < 32; i--)
	{
		onebyte = k[i];
		for (j = 0; j < 8; j++)
		{
			point_double(&accumulator);
			if ((u8)(onebyte & 0x80) != 0)
			{
				point_add(&accumulator, p);
			}
			onebyte = (u8)(onebyte << 1);
		}
	}
	jacobian_to_affine(&accumulator, p);
}

// Set the point p to the base point of secp256k1.
void set_to_G(point_affine *p)
{
	p->is_point_at_infinity = 0;
	bigassign(p->x, (bignum256)secp256k1_Gx);
	bigassign(p->y, (bignum256)secp256k1_Gy);
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
// This function will return 1 and fill r and s with the signature upon
// success. This function will return 0 upon failure. If this function returns
// 0, an appropriate course of action is to pick another random integer k and
// try again. If a random number generator is truly random, failure should
// only occur if you are extremely unlucky.
// This is an implementation of the algorithm described in the document
// "SEC 1: Elliptic Curve Cryptography" by Certicom research, obtained
// 15-August-2011 from: http://www.secg.org/collateral/sec1_final.pdf,
// section 4.1.3 ("Signing Operation").
u8 ecdsa_sign(bignum256 r, bignum256 s, bignum256 hash, bignum256 privatekey, bignum256 k)
{
	point_affine bigR;

	if (bigiszero(k) != 0)
	{
		return 0;
	}
	if (bigcmp(k, (bignum256)secp256k1_n) != BIGCMP_LESS)
	{
		return 0;
	}

	// Compute ephemeral elliptic curve key pair (k, bigR)
	set_field_to_p();
	set_to_G(&bigR);
	point_multiply(&bigR, k);
	// bigR now contains k * G
	bigsetfield(secp256k1_n, secp256k1_compn, sizeof(secp256k1_compn));
	bigmod(r, bigR.x);
	// r now contains (k * G).x (mod n)
	if (bigiszero(r) != 0)
	{
		return 0;
	}
	bigmultiply(s, r, privatekey);
	bigmod(bigR.y, hash); // use bigR.y as temporary
	bigadd(s, s, bigR.y);
	biginvert(bigR.y, k);
	bigmultiply(s, s, bigR.y);
	// s now contains (hash + (r * privatekey)) / k (mod n)
	if (bigiszero(s) != 0)
	{
		return 0;
	}

	return 1;
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

	if (p->is_point_at_infinity != 0)
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

static void set_p_to_G(point_affine *p)
{
	p->is_point_at_infinity = 0;
	bigassign(p->x, (bignum256)secp256k1_Gx);
	bigassign(p->y, (bignum256)secp256k1_Gy);
}

// Read little-endian hex string containing 256-bit integer and store into r
static void bigfread(FILE *f, bignum256 r)
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
// Returns 1 if signature is good, 0 otherwise.
// (r, s) is the signature. hash is the message digest of the message that was
// signed. (pubkey_x, pubkey_y) is the public key. All are supposed to be
// little-endian 256-bit integers.
static int crappy_verify_signature(bignum256 r, bignum256 s, bignum256 hash, bignum256 pubkey_x, bignum256 pubkey_y)
{
	point_affine p;
	point_affine p2;
	point_jacobian pj;
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
	bigsetfield(secp256k1_p, secp256k1_compp, sizeof(secp256k1_compp));
	bigmod(k1, k1);
	bigmod(k2, k2);
	set_p_to_G(&p);
	point_multiply(&p, k1);
	p2.is_point_at_infinity = 0;
	bigassign(p2.x, pubkey_x);
	bigassign(p2.y, pubkey_y);
	point_multiply(&p2, k2);
	affine_to_jacobian(&p, &pj);
	point_add(&pj, &p2);
	jacobian_to_affine(&pj, &result);
	bigsetfield(secp256k1_n, secp256k1_compn, sizeof(secp256k1_compn));
	bigmod(result.x, result.x);
	if (bigcmp(result.x, r) == BIGCMP_EQUAL)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int main(int argc, char **argv)
{
	point_affine p;
	point_jacobian p2;
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

	// Reference argc and argv just to make certain compilers happy.
	if (argc == 2)
	{
		printf("%s\n", argv[1]);
	}

	succeeded = 0;
	failed = 0;

	bigsetfield(secp256k1_p, secp256k1_compp, sizeof(secp256k1_compp));

	// Check that G is on the curve
	set_p_to_G(&p);
	check_point_is_on_curve(&p);

	// Check that point at infinity ("O") actually acts as identity element
	p2.is_point_at_infinity = 1;
	// 2O = O
	point_double(&p2);
	if (p2.is_point_at_infinity == 0)
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
	point_add(&p2, &p);
	if (p2.is_point_at_infinity == 0)
	{
		printf("Point add doesn't handle O + O properly\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	// P + O = P
	set_p_to_G(&p);
	affine_to_jacobian(&p, &p2);
	p.is_point_at_infinity = 1;
	point_add(&p2, &p);
	jacobian_to_affine(&p2, &p);
	if ((p.is_point_at_infinity != 0) 
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
	set_p_to_G(&p);
	point_add(&p2, &p);
	jacobian_to_affine(&p2, &p);
	if ((p.is_point_at_infinity != 0) 
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
	set_p_to_G(&p);
	affine_to_jacobian(&p, &p2);
	point_add(&p2, &p);
	jacobian_to_affine(&p2, &compare);
	affine_to_jacobian(&p, &p2);
	point_double(&p2);
	jacobian_to_affine(&p2, &p);
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
	set_p_to_G(&p);
	affine_to_jacobian(&p, &p2);
	bigsetzero(temp);
	bigsubtract(p.y, temp, p.y);
	check_point_is_on_curve(&p);
	point_add(&p2, &p);
	if (p2.is_point_at_infinity == 0) 
	{
		printf("P + -P != O\n");
		failed++;
	}
	else
	{
		succeeded++;
	}

	// Test that 2P + P gives a point on curve
	set_p_to_G(&p);
	affine_to_jacobian(&p, &p2);
	point_double(&p2);
	point_add(&p2, &p);
	jacobian_to_affine(&p2, &p);
	check_point_is_on_curve(&p);

	// Test that point_multiply by 0 gives O
	set_p_to_G(&p);
	bigsetzero(temp);
	point_multiply(&p, temp);
	if (p.is_point_at_infinity == 0) 
	{
		printf("point_multiply not starting at O\n");
		failed++;
	}
	else
	{
		succeeded++;
	}

	// Test that point_multiply by 1 gives P back
	set_p_to_G(&p);
	bigsetzero(temp);
	temp[0] = 1;
	point_multiply(&p, temp);
	if ((p.is_point_at_infinity != 0) 
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
	set_p_to_G(&p);
	bigsetzero(temp);
	temp[0] = 2;
	point_multiply(&p, temp);
	set_p_to_G(&compare);
	affine_to_jacobian(&compare, &p2);
	point_double(&p2);
	jacobian_to_affine(&p2, &compare);
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
		set_p_to_G(&p);
		bigsetzero(temp);
		temp[0] = (u8)(i & 0xff);
		temp[1] = (u8)((i >> 8) & 0xff);
		point_multiply(&p, temp);
		check_point_is_on_curve(&p);
	}

	// Test that n * G = O
	set_p_to_G(&p);
	point_multiply(&p, (bignum256)secp256k1_n);
	if (p.is_point_at_infinity == 0) 
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
		bigfread(f, temp);
		skipwhitespace(f);
		bigfread(f, compare.x);
		skipwhitespace(f);
		bigfread(f, compare.y);
		skipwhitespace(f);
		set_p_to_G(&p);
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
	if (ecdsa_sign(r, s, temp, temp, temp) != 0)
	{
		printf("ecdsa_sign() accepts k == 0\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	bigassign(temp, (bignum256)secp256k1_n);
	if (ecdsa_sign(r, s, temp, temp, temp) != 0)
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
	if (ecdsa_sign(r, s, temp, temp, temp) != 0)
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
	if (ecdsa_sign(r, s, temp, temp, temp) == 0)
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
		bigfread(f, privkey);
		skipwhitespace(f);
		bigfread(f, pubkey_x);
		skipwhitespace(f);
		bigfread(f, pubkey_y);
		skipwhitespace(f);
		do
		{
			for (j = 0; j < 32; j++)
			{
				temp[j] = (u8)(rand() & 0xff);
			}
		} while (ecdsa_sign(r, s, hash, privkey, temp) == 0);
		if (crappy_verify_signature(r, s, hash, pubkey_x, pubkey_y) == 0)
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


/** \file baseconv.c
  *
  * \brief Performs multi-precision base conversion.
  *
  * At the moment this is restricted to converting from binary and can only
  * convert to base 58 or base 10. This is used to convert Bitcoin transaction
  * amounts and addresses to human-readable form. The format of
  * multi-precision numbers used in this file is identical to that of
  * bignum256.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

// Defining this will facilitate testing
//#define TEST

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#endif // #ifdef TEST

#include "common.h"
#include "endian.h"
#include "baseconv.h"
#include "bignum256.h"
#include "sha256.h"

/** Shift list for bigDivide() to have it do division by 58. */
static const uint8_t base58_shift_list[16] PROGMEM = {
0x00, 0x1d, 0x80, 0x0e, 0x40, 0x07, 0xa0, 0x03,
0xd0, 0x01, 0xe8, 0x00, 0x74, 0x00, 0x3a, 0x00};

/** Shift list for bigDivide() to have it do division by 10. */
static const uint8_t base10_shift_list[16] PROGMEM = {
0x00, 0x05, 0x80, 0x02, 0x40, 0x01, 0xa0, 0x00,
0x50, 0x00, 0x28, 0x00, 0x14, 0x00, 0x0a, 0x00};

/** Characters for the base 10 representation of numbers. */
static const char base10_char_list[10] PROGMEM = {
'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};

/** Characters for the base 58 representation of numbers. */
static const char base58_char_list[58] PROGMEM = {
'1', '2', '3', '4', '5', '6', '7', '8', '9', 'A',
'B', 'C', 'D', 'E', 'F', 'G', 'H', 'J', 'K', 'L',
'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q', 'r',
's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

#ifdef TEST
static void bigPrintVariableSize(uint8_t *number, uint8_t size, uint8_t big_endian)
{
	uint8_t i;
	if (big_endian)
	{
		for (i = 0; i < size; i++)
		{
			printf("%02x", number[i]);
		}
	}
	else
	{
		for (i = (uint8_t)(size - 1); i < size; i--)
		{
			printf("%02x", number[i]);
		}
	}
}
#endif // #ifdef TEST

/** Do a multi-precision division of op1 by an 8 bit unsigned integer n,
  * placing the quotient in r and the remainder in op1.
  * \param r The quotient will be placed here. This should be an array with
  *          space for size bytes.
  * \param op1 As an input, this is the dividend, a multi-precision number.
  *            But on output, this will be be remainder. This should be an
  *            array with space for size + 1 bytes.
  * \param temp A temporary work area. Its contents will be overwritten with
  *             junk. This should be an array with space for size + 1 bytes.
  * \param size The size of the division, in number of bytes.
  * \param shift_list Specifies the divisor (the 8 bit unsigned integer n).
  *                   This is actually an array of 8 little-endian 16 bit
  *                   unsigned integers which are:
  *                   n << 7, n << 6, n << 5, ..., n << 0.
  * \warning r, op1 and temp cannot alias each other.
  * \warning For platforms that use the PROGMEM attribute, the shift_list
  *          array must have that attribute.
  */
static void bigDivide(uint8_t *r, uint8_t *op1, uint8_t *temp, uint8_t size, const uint8_t *shift_list)
{
	uint8_t i;
	uint8_t j;
	uint8_t bit;

	for (i = 0; i < size; i++)
	{
		temp[i] = 0;
		r[i] = 0;
	}
	op1[size] = 0;
	temp[size] = 0;

	for (i = (uint8_t)(size - 1); i < size; i--)
	{
		bit = 0x80;
		for (j = 0; j < 8; j++)
		{
			temp[i] = LOOKUP_BYTE(&(shift_list[j * 2]));
			temp[i + 1] = LOOKUP_BYTE(&(shift_list[j * 2 + 1]));
			if (bigCompareVariableSize(temp, op1, (uint8_t)(size + 1)) != BIGCMP_GREATER)
			{
				bigSubtractVariableSizeNoModulo(op1, op1, temp, (uint8_t)(size + 1));
				r[i] |= bit;
			}
			bit >>= 1;
		}
		temp[i + 1] = 0;
	}
}

/** Convert a transaction amount (which is in 10 ^ -8 BTC) to a human-readable
  * value such as "0.05", contained in a null-terminated character string.
  * \param out Should point to a char array which has space for at least 22
  *            characters (including the terminating null).
  * \param in A 64 bit, unsigned, little-endian integer with the amount in
  *           10 ^ -8 BTC.
  */
void amountToText(char *out, uint8_t *in)
{
	uint8_t op1[9];
	uint8_t temp[9];
	uint8_t r[8];
	uint8_t i;
	uint8_t j;
	uint8_t index;

	for (i = 0; i < 8; i++)
	{
		r[i] = in[i];
	}

	// Write amount into a string like: "000000000000.00000000".
	index = 20;
	for (i = 0; i < 20; i++)
	{
		for (j = 0; j < 8; j++)
		{
			op1[j] = r[j];
		}
		bigDivide(r, op1, temp, 8, base10_shift_list);
		if (i == 8)
		{
			out[index--] = '.';
		}
		out[index--] = LOOKUP_BYTE(&(base10_char_list[op1[0]]));
	}
	out[21] = '\0';

	// Truncate trailing zeroes up to the decimal point.
	for (i = 20; i > 11; i--)
	{
		if ((out[i] == '0') || (out[i] == '.'))
		{
			out[i] = '\0';
		}
		else
		{
			break;
		}
	}

	// Remove leading zeroes up to one zero before the decimal point.
	for (i = 0; i < 11; i++)
	{
		if (out[0] == '0')
		{
			for (j = 0; j < 21; j++)
			{
				out[j] = out[j + 1];
			}
		}
		else
		{
			break;
		}
	}
}

/** Convert 160 bit hash to a human-readable base 58 Bitcoin address such
  * as "1Dinox3mFw8yykpAZXFGEKeH4VX1Mzbcxe".
  * \param out The human-readable base 58 Bitcoin address will be written
  *            here in the form of a null-terminated string. This should
  *            point to a buffer with space for at least 36 chars
  *            including the terminating null).
  * \param in The 160 bit hash to convert. This should point to an array of
  *           20 bytes containing the hash in big-endian format (as is
  *           typical for hashes).
  */
void hashToAddr(char *out, uint8_t *in)
{
	uint8_t r[25];
	uint8_t op1[26];
	uint8_t temp[26];
	uint8_t index;
	uint8_t i;
	uint8_t j;
	uint8_t leading_zero_bytes;
	HashState hs;

	// Prepend address version and append checksum.
	sha256Begin(&hs);
	r[24] = ADDRESSVERSION;
	sha256WriteByte(&hs, ADDRESSVERSION);
	for (i = 0; i < 20; i++)
	{
		r[23 - i] = in[i];
		sha256WriteByte(&hs, in[i]);
	}
	sha256FinishDouble(&hs);
	writeU32LittleEndian(r, hs.h[0]);

	// Count number of leading zero bytes.
	leading_zero_bytes = 0;
	for (i = 24; i < 25; i--)
	{
		if (r[i] == 0)
		{
			leading_zero_bytes++;
		}
		else
		{
			break;
		}
	}

	// Convert to base 58.
	index = 34;
	for (i = 0; i < 35; i++)
	{
		for (j = 0; j < 25; j++)
		{
			op1[j] = r[j];
		}
		bigDivide(r, op1, temp, 25, base58_shift_list);
		out[index--] = LOOKUP_BYTE(&(base58_char_list[op1[0]]));
	}
	out[35] = '\0';

	// Remove leading zeroes.
	for (i = 0; i < 35; i++)
	{
		if (out[0] == '1')
		{
			for (j = 0; j < 35; j++)
			{
				out[j] = out[j + 1];
			}
		}
		else
		{
			break;
		}
	}

	// Insert leading zeroes equal in number to the number of input leading
	// zero bytes.
	for (i = 0; i < leading_zero_bytes; i++)
	{
		for (j = 34; j < 35; j--)
		{
			out[j + 1] = out[j];
		}
		out[0] = '1';
	}
}

#ifdef TEST

/** Stores one test case for amountToText(). */
struct Base10TestStruct
{
	uint8_t value[8];
	char *text;
};

/** Stores one test case for hashToAddr(). */
struct Base58TestStruct
{
	uint8_t hash[20];
	char *addr;
};

/** These test cases were constructed manually, by doing base conversion
  * on a calculator and trimming as appropriate. */
const struct Base10TestStruct base10_tests[] = {
{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "0"},
{{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "0.00000001"},
{{0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "0.0000001"},
{{0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "0.000001"},
{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, "184467440737.09551615"},
{{0x00, 0x41, 0x6e, 0xff, 0xff, 0xff, 0xff, 0xff}, "184467440737"},
{{0x40, 0x83, 0x7d, 0xff, 0xff, 0xff, 0xff, 0xff}, "184467440737.01"},
{{0x10, 0xaa, 0x5e, 0x05, 0x00, 0x00, 0x00, 0x00}, "0.9009"},
{{0x40, 0x2c, 0x42, 0x06, 0x00, 0x00, 0x00, 0x00}, "1.05"},
{{0x00, 0xf2, 0x05, 0x2a, 0x01, 0x00, 0x00, 0x00}, "50"},
{{0x00, 0xef, 0x1c, 0x0d, 0x00, 0x00, 0x00, 0x00}, "2.2"},
{{0xf0, 0xbc, 0x0b, 0x54, 0x02, 0x00, 0x00, 0x00}, "99.9999"},
{{0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00}, "1"},
{{0x00, 0x14, 0x07, 0x68, 0x09, 0x00, 0x00, 0x00}, "404"},
{{0x80, 0xaa, 0x9f, 0x68, 0x09, 0x00, 0x00, 0x00}, "404.1"},
{{0xb0, 0xaf, 0x7a, 0x0b, 0x5e, 0x07, 0x00, 0x00}, "81005.0091"},
{{0x60, 0xdf, 0x51, 0x13, 0x01, 0x00, 0x00, 0x00}, "46.191"},
{{0xc0, 0xea, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00}, "0.19"},
{{0xad, 0xc0, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00}, "0.02408621"},
{{0x80, 0x9b, 0x8b, 0x44, 0x00, 0x00, 0x00, 0x00}, "11.5"},
{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}, "92233720368.54775808"},
{{0xf0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, "92233720368.54775792"},
{{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, "92233720368.5477579"}};

/** Some of these are real Bitcoin addresses, obtained from blockexplorer
  * and from forums.
  * Others were generated using http://blockexplorer.com/q/hashtoaddress. */
const struct base58test_struct base58_tests[] = {
{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  "1111111111111111111114oLvT2"},
{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  "1QLbz7JHiBTspS962RLKV8GndWFwi5j6Qr"},
{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
  "11111111111111111111BZbvjr"},
{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
  "11111111111111111111HeBAGj"},
{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
  "1111111111111111111VxYUzGa"},
{{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
  "16HgC8KRBEhXYbF4riJyJFLSHtXyxfbTm"},
{{0x00, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00},
  "111114Z3siVpKyHpLfU1ftfegR3kJCAHn"},
{{0x22, 0xb5, 0x25, 0x17, 0x51, 0x11, 0x39, 0xc1, 0x30, 0x49,
  0xd4, 0xab, 0x32, 0x0d, 0xea, 0x8e, 0xe6, 0x24, 0x91, 0x1a},
  "14AWygzwD3f7TzjZrsseA9unjAbMJnyRsW"},
{{0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  "116HgC8KRBEhXYbF4riJyJFLSHt31kYasP"},
{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00},
  "1QLbz7JHiBTspS962RLKV8GndU4TwQTsg1"},
{{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  "1CfoVZ9eMbESQia3WiAfF4dtpFdUQ8uBUz"},
{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  "11111111111111Yjy1kTv4cvroL1D"},
{{0x92, 0x82, 0x6a, 0xbc, 0x31, 0x59, 0x3a, 0xb0, 0x0e, 0xd8,
  0x20, 0x86, 0xca, 0x4e, 0x00, 0x19, 0xf1, 0x24, 0x8d, 0xec},
  "1EMftY1fkLBeAFMu43SgLApzzuHsYtXD5r"},
{{0xf5, 0x6e, 0x31, 0xd2, 0xca, 0xce, 0xff, 0x6d, 0x79, 0x14,
  0x13, 0x32, 0xee, 0x50, 0xc2, 0xf1, 0xe2, 0xba, 0xc4, 0x37},
  "1PNiZTPqNPmjSJVMEWD2z6s5wcrfTXhtZC"},
{{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
  "16Jswqk47s9PUcyCc88MMVwzgvHPvtEpf"},
{{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
  "11111111111NQa6fJbZEgU3ZhRbYJ"},
{{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
  "16Jswqk47s9PUcxqCZ2h3uPm1TEu9bkRR"},
{{0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00, 0xff, 0x00,
  0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xff, 0x00, 0x00},
  "116GUytyVKvjPffEkce7bokPWF2kF7eLQj"},
{{0x04, 0xa5, 0xe9, 0x35, 0x91, 0x35, 0xcd, 0xca, 0x90, 0x9c,
  0x4e, 0x5e, 0xde, 0x23, 0x8e, 0x84, 0x5b, 0xcc, 0x59, 0x27},
  "1RaTTuSEN7jJUDiW1EGogHwtek7g9BiEn"},
{{0x8b, 0x88, 0xcd, 0xbc, 0x69, 0x00, 0x57, 0xe3, 0x4f, 0xf1,
  0x6f, 0xcd, 0x28, 0xd9, 0x44, 0x35, 0x05, 0xb9, 0xba, 0xfe},
  "1Dinox3mFw8yykpAZXFGEKeH4VX1Mzbcxe"}};

int main(void)
{
	char text[22];
	char addr[36];
	int num_tests;
	int i;
	int succeeded;
	int failed;

	succeeded = 0;
	failed = 0;

	num_tests = sizeof(base10_tests) / sizeof(struct Base10TestStruct);
	for (i = 0; i < num_tests; i++)
	{
		amountToText(text, (uint8_t *)base10_tests[i].value);
		if (strcmp(base10_tests[i].text, text))
		{
			printf("Base10 test number %d failed\n", i);
			printf("Input: ");
			bigPrintVariableSize((uint8_t *)base10_tests[i].value, 8, 0);
			printf("\n");
			printf("Got: %s\n", text);
			printf("Expected: %s\n", base10_tests[i].text);
			failed++;
		}
		else
		{
			succeeded++;
		}
	}

	num_tests = sizeof(base58tests) / sizeof(struct Base58TestStruct);
	for (i = 0; i < num_tests; i++)
	{
		hashToAddr(addr, (uint8_t *)base58tests[i].hash);
		if (strcmp(base58_tests[i].addr, addr))
		{
			printf("Base58 test number %d failed\n", i);
			printf("Input: ");
			bigPrintVariableSize((uint8_t *)base58_tests[i].hash, 20, 1);
			printf("\n");
			printf("Got:      %s\n", addr);
			printf("Expected: %s\n", base58_tests[i].addr);
			failed++;
		}
		else
		{
			succeeded++;
		}
	}

	printf("Tests which succeeded: %d\n", succeeded);
	printf("Tests which failed: %d\n", failed);

	exit(0);
}

#endif // #ifdef TEST


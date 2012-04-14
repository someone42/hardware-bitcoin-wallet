// ***********************************************************************
// xex.c
// ***********************************************************************
//
// Implements XEX mode for encryption of a random-access block device.
// For details, see "Efficient Instantiations of Tweakable Blockciphers and
// Refinements to Modes OCB and PMAC" (dated September 24, 2004) by Phillip
// Rogaway, obtained from
// http://www.cs.ucdavis.edu/~rogaway/papers/offsets.pdf
// on 5-February-2012.
// XEX mode combines the random-access ability of CTR mode with the
// bit-flipping attack resistance of ECB mode.
//
// This file is licensed as described by the file LICENCE.

// Defining this will facilitate testing
//#define TEST

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#endif // #ifdef TEST

#include "common.h"
#include "aes.h"
#include "prandom.h"
#include "hwinterface.h"
#include "endian.h"

static uint8_t nv_storage_tweak_key[16];
static uint8_t nv_storage_encrypt_key[16];

// Double the 128-bit number represented by op1 under GF(2 ^ 128) with
// reducing polynomial x ^ 128 + x ^ 7 + x ^ 2 + x + 1. This treats
// op1 as a little-endian number.
static void doubleInGF(uint8_t *op1)
{
	uint8_t i;
	uint8_t last_bit;
	uint8_t temp;

	last_bit = 0;
	for (i = 0; i < 16; i++)
	{
		temp = (uint8_t)(op1[i] & 0x80);
		op1[i] = (uint8_t)(op1[i] << 1);
		op1[i] |= last_bit;
		last_bit = (uint8_t)(temp >> 7);
	}
	last_bit = (uint8_t)(-(int)last_bit);
	// last_bit is now 0 if most-significant bit is 0, 0xff if most-significant
	// bit is 1.
	op1[0] = (uint8_t)(op1[0] ^ (0x87 & last_bit));
}

// Combined XEX mode encrypt/decrypt, since they're almost the same.
// See xex_encrypt() for what description of what this does and what each
// argument refers to.
static void xexEnDecrypt(uint8_t *out, uint8_t *in, uint8_t *n, uint8_t seq, uint8_t *tweak_key, uint8_t *encrypt_key, uint8_t is_decrypt)
{
	uint8_t expanded_key[EXPANDED_KEY_SIZE];
	uint8_t delta[16];
	uint8_t buffer[16];
	uint8_t i;

	aesExpandKey(expanded_key, tweak_key);
	aesEncrypt(delta, n, expanded_key);
	for (i = 0; i < seq; i++)
	{
		doubleInGF(delta);
	}
	for (i = 0; i < 16; i++)
	{
		buffer[i] = in[i];
	}
	xor16Bytes(buffer, delta);
	aesExpandKey(expanded_key, encrypt_key);
	if (is_decrypt)
	{
		aesDecrypt(out, buffer, expanded_key);
	}
	else
	{
		aesEncrypt(out, buffer, expanded_key);
	}
	xor16Bytes(out, delta);
}

// Encrypt the 16-byte block specified by in using AES in XEX mode. The
// ciphertext will be placed in out. n is a 128-bit number which specifies the
// number of the data unit (whatever a data unit is defined to be) and seq
// specifies the block within the data unit. Don't use seq = 0, as this
// presents a security vulnerability (albeit a convoluted one). For more
// details about the seq = 0 issue, see section 6 ("Security of XEX") of
// Rogaway's paper (reference at the top of this file).
// n and seq don't need to be secret. tweak_key and encrypt_key are two
// independent 128-bit AES keys.
static void xexEncrypt(uint8_t *out, uint8_t *in, uint8_t *n, uint8_t seq, uint8_t *tweak_key, uint8_t *encrypt_key)
{
	xexEnDecrypt(out, in, n, seq, tweak_key, encrypt_key, 0);
}

// Decrypt the 16-byte block specified by in using AES in XEX mode. The
// plaintext will be placed in out.
// See xex_encrypt() for what description of what this does and what each
// argument refers to.
static void xexDecrypt(uint8_t *out, uint8_t *in, uint8_t *n, uint8_t seq, uint8_t *tweak_key, uint8_t *encrypt_key)
{
	xexEnDecrypt(out, in, n, seq, tweak_key, encrypt_key, 1);
}

// Set the 128-bit tweak key to the contents of in.
// The tweak key can be considered as a secondary, independent encryption key.
void setTweakKey(uint8_t *in)
{
	uint8_t i;
	for (i = 0; i < 16; i++)
	{
		nv_storage_tweak_key[i] = in[i];
	}
}

// Set the 128-bit encryption key to the contents of in.
void setEncryptionKey(uint8_t *in)
{
	uint8_t i;
	for (i = 0; i < 16; i++)
	{
		nv_storage_encrypt_key[i] = in[i];
	}
}

// Place encryption keys in the buffer pointed to by out. out must point
// to an array of 32 bytes. The (primary) encryption key is written to the
// first 16 bytes and the tweak key is written to the last 16 bytes.
void getEncryptionKeys(uint8_t *out)
{
	uint8_t i;
	for (i = 0; i < 16; i++)
	{
		out[i] = nv_storage_encrypt_key[i];
	}
	for (i = 0; i < 16; i++)
	{
		out[i + 16] = nv_storage_tweak_key[i];
	}
}

// Returns non-zero if any one of the encryption keys is non-zero.
uint8_t areEncryptionKeysNonZero(void)
{
	uint8_t r;
	uint8_t i;

	r = 0;
	for (i = 0; i < 16; i++)
	{
		r |= nv_storage_encrypt_key[i];
		r |= nv_storage_tweak_key[i];
	}
	return r;
}

// Clear out memory which stores encryption keys.
// In order to be sure that keys don't remain in RAM anywhere, you may also
// need to clear out the space between the heap and the stack.
void clearEncryptionKeys(void)
{
	uint8_t i;
	for (i = 0; i < 16; i++)
	{
		// Just to be sure
		nv_storage_tweak_key[i] = 0xff;
		nv_storage_encrypt_key[i] = 0xff;
	}
	for (i = 0; i < 16; i++)
	{
		nv_storage_tweak_key[i] = 0;
		nv_storage_encrypt_key[i] = 0;
	}
}

// Wrapper around nonvolatile_write() which also encrypts using the
// nv_storage_tweak_key/nv_storage_encrypt_key encryption keys.
NonVolatileReturn encryptedNonVolatileWrite(uint8_t *data, uint32_t address, uint8_t length)
{
	uint32_t block_start;
	uint32_t block_end;
	uint8_t block_offset;
	uint8_t ciphertext[16];
	uint8_t plaintext[16];
	uint8_t n[16];
	uint8_t i;
	NonVolatileReturn r;

	block_start = address & 0xfffffff0;
	block_offset = (uint8_t)(address & 0x0000000f);
	block_end = (address + length - 1) & 0xfffffff0;

	for (i = 0; i < 16; i++)
	{
		n[i] = 0;
	}
	for (; block_start <= block_end; block_start += 16)
	{
		r = nonVolatileRead(ciphertext, block_start, 16);
		if (r != NV_NO_ERROR)
		{
			return r;
		}
		writeU32LittleEndian(n, block_start);
		xexDecrypt(plaintext, ciphertext, n, 1, nv_storage_tweak_key, nv_storage_encrypt_key);
		while (length && block_offset < 16)
		{
			plaintext[block_offset++] = *data++;
			length--;
		}
		block_offset = 0;
		xexEncrypt(ciphertext, plaintext, n, 1, nv_storage_tweak_key, nv_storage_encrypt_key);
		r = nonVolatileWrite(ciphertext, block_start, 16);
		if (r != NV_NO_ERROR)
		{
			return r;
		}
	}

	return NV_NO_ERROR;
}

// Wrapper around nonVolatileRead() which also decrypts using the
// nv_storage_tweak_key/nv_storage_encrypt_key encryption keys.
NonVolatileReturn encryptedNonVolatileRead(uint8_t *data, uint32_t address, uint8_t length)
{
	uint32_t block_start;
	uint32_t block_end;
	uint8_t block_offset;
	uint8_t ciphertext[16];
	uint8_t plaintext[16];
	uint8_t n[16];
	uint8_t i;
	NonVolatileReturn r;

	block_start = address & 0xfffffff0;
	block_offset = (uint8_t)(address & 0x0000000f);
	block_end = (address + length - 1) & 0xfffffff0;

	for (i = 0; i < 16; i++)
	{
		n[i] = 0;
	}
	for (; block_start <= block_end; block_start += 16)
	{
		r = nonVolatileRead(ciphertext, block_start, 16);
		if (r != NV_NO_ERROR)
		{
			return r;
		}
		writeU32LittleEndian(n, block_start);
		xexDecrypt(plaintext, ciphertext, n, 1, nv_storage_tweak_key, nv_storage_encrypt_key);
		while (length && block_offset < 16)
		{
			*data++ = plaintext[block_offset++];
			length--;
		}
		block_offset = 0;
	}

	return NV_NO_ERROR;
}

#ifdef TEST

static int succeeded;
static int failed;

static void skipWhiteSpace(FILE *f)
{
	int onechar;
	do
	{
		onechar = fgetc(f);
	} while ((onechar == ' ') || (onechar == '\t') || (onechar == '\n') || (onechar == '\r'));
	ungetc(onechar, f);
}

static void skipLine(FILE *f)
{
	int one_char;
	do
	{
		one_char = fgetc(f);
	} while (one_char != '\n');
}

static void print16(uint8_t *buffer)
{
	int i;
	for (i = 0; i < 16; i++)
	{
		printf("%02x", (int)buffer[i]);
	}
}

// If is_data_unit_seq_number is non-zero, this expects data unit sequence
// numbers (look for "DataUnitSeqNumber =" in the file) as the tweak
// value. Otherwise, this expects "i =" to specify the tweak value.
static void scanTestVectors(char *filename, int is_data_unit_seq_number)
{
	FILE *f;
	int test_number;
	int data_unit_length;
	int is_encrypt;
	int i;
	int j;
	int value;
	int seen_count;
	int test_failed;
	char buffer[100];
	uint8_t tweak_key[16];
	uint8_t encrypt_key[16];
	uint8_t tweak_value[16];
	uint8_t *plaintext;
	uint8_t *ciphertext;
	uint8_t *compare;

	f = fopen(filename, "r");
	if (f == NULL)
	{
		printf("Could not open %s, please get it \
(\"AES Known Answer Test (KAT) Vectors\") \
from http://csrc.nist.gov/groups/STM/cavp/#08\n", filename);
		printf("There should be two versions: one with 128-bit hex strings as the tweak\n");
		printf("value, and one with a \"data unit sequence number\" as the tweak value.\n");
		printf("Rename the one with 128-bit hex string tweak values \"XTSGenAES128i.rsp\"\n");
		printf("and rename the one with data unit sequence numbers \"XTSGenAES128d.rsp\".\n");
		exit(1);
	}

	test_number = 1;
	for (i = 0; i < 11; i++)
	{
		skipLine(f);
	}
	is_encrypt = 1;
	while (!feof(f))
	{
		// Check for [DECRYPT].
		skipWhiteSpace(f);
		seen_count = 0;
		while (!seen_count)
		{
			fgets(buffer, 6, f);
			skipLine(f);
			skipWhiteSpace(f);
			if (!strcmp(buffer, "[DECR"))
			{
				is_encrypt = 0;
			}
			else if (!strcmp(buffer, "COUNT"))
			{
				seen_count = 1;
			}
			else
			{
				printf("Expected \"COUNT\" or \"[DECR\"\n");
				exit(1);
			}
		}

		// Get data length.
		fgets(buffer, 15, f);
		if (strcmp(buffer, "DataUnitLen = "))
		{
			printf("Parse error; expected \"DataUnitLen = \"\n");
			exit(1);
		}
		fscanf(f, "%d", &data_unit_length);
		if ((data_unit_length <= 0) || (data_unit_length > 10000000))
		{
			printf("Error: got absurd data unit length %d\n", data_unit_length);
			exit(1);
		}
		skipWhiteSpace(f);

		if (data_unit_length & 0x7f)
		{
			// Skip tests which require ciphertext stealing, since ciphertext
			// stealing isn't implemented here (because it's not necessary).
			for (i = 0; i < 6; i++)
			{
				skipLine(f);
			}
		}
		else
		{
			data_unit_length >>= 3; // number of bits to number of bytes

			// Get key.
			fgets(buffer, 7, f);
			if (strcmp(buffer, "Key = "))
			{
				printf("Parse error; expected \"Key = \"\n");
				exit(1);
			}
			for (i = 0; i < 16; i++)
			{
				fscanf(f, "%02x", &value);
				encrypt_key[i] = (uint8_t)value;
			}
			for (i = 0; i < 16; i++)
			{
				fscanf(f, "%02x", &value);
				tweak_key[i] = (uint8_t)value;
			}
			skipWhiteSpace(f);

			// Get tweak value.
			if (is_data_unit_seq_number)
			{
				int n;

				fgets(buffer, 21, f);
				if (strcmp(buffer, "DataUnitSeqNumber = "))
				{
					printf("Parse error; expected \"DataUnitSeqNumber = \"\n");
					exit(1);
				}
				fscanf(f, "%d", &n);
				memset(tweak_value, 0, 16);
				tweak_value[0] = (uint8_t)n;
				tweak_value[1] = (uint8_t)(n >> 8);
				tweak_value[2] = (uint8_t)(n >> 16);
				tweak_value[3] = (uint8_t)(n >> 24);
			}
			else
			{
				fgets(buffer, 5, f);
				if (strcmp(buffer, "i = "))
				{
					printf("Parse error; expected \"i = \"\n");
					exit(1);
				}
				for (i = 0; i < 16; i++)
				{
					fscanf(f, "%02x", &value);
					tweak_value[i] = (uint8_t)value;
				}
			}
			skipWhiteSpace(f);

			plaintext = malloc(data_unit_length);
			ciphertext = malloc(data_unit_length);
			compare = malloc(data_unit_length);

			// Get plaintext/ciphertext.
			// The order is: plaintext, then ciphertext for encrypt.
			// The order is: ciphertext, then plaintext for decrypt.
			for (j = 0; j < 2; j++)
			{
				if (((is_encrypt) && (j == 0))
					|| ((!is_encrypt) && (j != 0)))
				{
					fgets(buffer, 6, f);
					if (strcmp(buffer, "PT = "))
					{
						printf("Parse error; expected \"PT = \"\n");
						exit(1);
					}
					for (i = 0; i < data_unit_length; i++)
					{
						fscanf(f, "%02x", &value);
						plaintext[i] = (uint8_t)value;
					}
				}
				else
				{
					fgets(buffer, 6, f);
					if (strcmp(buffer, "CT = "))
					{
						printf("Parse error; expected \"CT = \"\n");
						exit(1);
					}
					for (i = 0; i < data_unit_length; i++)
					{
						fscanf(f, "%02x", &value);
						ciphertext[i] = (uint8_t)value;
					}
				}
				skipWhiteSpace(f);
			} // end for (j = 0; j < 2; j++)

			// Do encryption/decryption and compare
			test_failed = 0;
			if (is_encrypt)
			{
				for (i = 0; i < data_unit_length; i += 16)
				{
					xexEncrypt(&(compare[i]), &(plaintext[i]), tweak_value, (uint8_t)(i >> 4), tweak_key, encrypt_key);
					if (memcmp(&(compare[i]), &(ciphertext[i]), 16))
					{
						test_failed = 1;
						break;
					}
				}
			}
			else
			{
				for (i = 0; i < data_unit_length; i += 16)
				{
					xexDecrypt(&(compare[i]), &(ciphertext[i]), tweak_value, (uint8_t)(i >> 4), tweak_key, encrypt_key);
					if (memcmp(&(compare[i]), &(plaintext[i]), 16))
					{
						test_failed = 1;
						break;
					}
				}
			}
			if (!test_failed)
			{
				succeeded++;
			}
			else
			{
				printf("Test %d failed\n", test_number);
				printf("Key: ");
				print16(encrypt_key);
				print16(tweak_key);
				printf("\nFirst 16 bytes of plaintext: ");
				print16(plaintext);
				printf("\nFirst 16 bytes of ciphertext: ");
				print16(ciphertext);
				printf("\n");
				failed++;
			}
			test_number++;
			free(plaintext);
			free(ciphertext);
			free(compare);
		}
	}
	fclose(f);
}

// Maximum address that a write to non-volatile storage will be
// Must be multiple of 128
#define MAX_ADDRESS 1024
// Number of read/write tests to do
#define NUM_RW_TESTS 100000

extern void initWalletTest(void);

int main(void)
{
	uint8_t what_storage_should_be[MAX_ADDRESS];
	uint8_t buffer[256];
	uint8_t onekey[16];
	int i;
	int j;

	initWalletTest();
	clearEncryptionKeys();
	srand(42);
	succeeded = 0;
	failed = 0;
	scanTestVectors("XTSGenAES128i.rsp", 0);
	scanTestVectors("XTSGenAES128d.rsp", 1);

	for (i = 0; i < MAX_ADDRESS; i++)
	{
		what_storage_should_be[i] = (uint8_t)rand();
	}
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encryptedNonVolatileWrite(&(what_storage_should_be[i]), i, 128);
	}
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encryptedNonVolatileRead(buffer, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			printf("Storage mismatch in encryptedNonVolatileRead()\n");
			printf("Initial fill, address = 0x%08x, length = 128\n", i);
			failed++;
		}
		else
		{
			succeeded++;
		}
	}

	// Now read and write randomly, mirroring the reads and writes to the
	// what_storage_should_be array.
	for (i = 0; i < NUM_RW_TESTS; i++)
	{
		uint32_t address;
		uint8_t length;

		do
		{
			address = (uint32_t)(rand() & (MAX_ADDRESS - 1));
			length = (uint8_t)rand();
		} while ((address + length) > MAX_ADDRESS);
		if (rand() & 1)
		{
			// Write 50% of the time
			for (j = 0; j < length; j++)
			{
				buffer[j] = (uint8_t)rand();
			}
			memcpy(&(what_storage_should_be[address]), buffer, length);
			if (encryptedNonVolatileWrite(buffer, address, length) != NV_NO_ERROR)
			{
				printf("encryptedNonVolatileWrite() failed\n");
				printf("test number = %d, address = 0x%08x, length = %d\n", i, (int)address, (int)length);
				failed++;
			}
			else
			{
				succeeded++;
			}
		}
		else
		{
			// Read 50% of the time
			if (encryptedNonVolatileRead(buffer, address, length) != NV_NO_ERROR)
			{
				printf("encryptedNonVolatileRead() failed\n");
				printf("test number = %d, address = 0x%08x, length = %d\n", i, (int)address, (int)length);
				failed++;
			}
			else
			{
				if (memcmp(&(what_storage_should_be[address]), buffer, length))
				{
					printf("Storage mismatch in encryptedNonVolatileRead()\n");
					printf("test number = %d, address = 0x%08x, length = %d\n", i, (int)address, (int)length);
					failed++;
				}
				else
				{
					succeeded++;
				}
			}
		}
	}

	// Now change the encryption keys and try to obtain the contents of the
	// nonvolatile storage. The result should be mismatches everywhere.
	for (i = 0; i < 16; i++)
	{
		onekey[i] = 0;
	}
	onekey[0] = 1; // key is only slightly different

	// Change only tweak key.
	setTweakKey(onekey);
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encryptedNonVolatileRead(buffer, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			succeeded++;
		}
		else
		{
			printf("Storage match in encryptedNonVolatileRead() when using different tweak key\n");
			printf("Final run, address = 0x%08x, length = 128\n", i);
			failed++;
		}
	}

	// Change only (primary) encryption key.
	clearEncryptionKeys();
	setEncryptionKey(onekey);
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encryptedNonVolatileRead(buffer, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			succeeded++;
		}
		else
		{
			printf("Storage match in encryptedNonVolatileRead() when using different primary encryption key\n");
			printf("Final run, address = 0x%08x, length = 128\n", i);
			failed++;
		}
	}

	// Switch back to original, correct keys. All should be fine now.
	clearEncryptionKeys();
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encryptedNonVolatileRead(buffer, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			printf("Storage mismatch in encryptedNonVolatileRead() when keys are okay\n");
			printf("Final run, address = 0x%08x, length = 128\n", i);
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

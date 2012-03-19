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

static u8 nvstorage_tweak_key[16];
static u8 nvstorage_encrypt_key[16];

// Double the 128-bit number represented by op1 under GF(2 ^ 128) with
// reducing polynomial x ^ 128 + x ^ 7 + x ^ 2 + x + 1. This treats
// op1 as a little-endian number.
static void gfdouble(u8 *op1)
{
	u8 i;
	u8 lastbit;
	u8 temp;

	lastbit = 0;
	for (i = 0; i < 16; i++)
	{
		temp = (u8)(op1[i] & 0x80);
		op1[i] = (u8)(op1[i] << 1);
		op1[i] |= lastbit;
		lastbit = (u8)(temp >> 7);
	}
	lastbit = (u8)(-(int)lastbit);
	// lastbit is now 0 if most-significant bit is 0, 0xff if most-significant
	// bit is 1.
	op1[0] = (u8)(op1[0] ^ (0x87 & lastbit));
}

// Combined XEX mode encrypt/decrypt, since they're almost the same.
// See xex_encrypt() for what description of what this does and what each
// argument refers to.
static void xex_endecrypt(u8 *out, u8 *in, u8 *n, u8 seq, u8 *tweak_key, u8 *encrypt_key, u8 isdecrypt)
{
	u8 expkey[EXPKEY_SIZE];
	u8 delta[16];
	u8 buffer[16];
	u8 i;

	aes_expand_key(expkey, tweak_key);
	aes_encrypt(delta, n, expkey);
	for (i = 0; i < seq; i++)
	{
		gfdouble(delta);
	}
	for (i = 0; i < 16; i++)
	{
		buffer[i] = in[i];
	}
	xor16bytes(buffer, delta);
	aes_expand_key(expkey, encrypt_key);
	if (isdecrypt)
	{
		aes_decrypt(out, buffer, expkey);
	}
	else
	{
		aes_encrypt(out, buffer, expkey);
	}
	xor16bytes(out, delta);
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
static void xex_encrypt(u8 *out, u8 *in, u8 *n, u8 seq, u8 *tweak_key, u8 *encrypt_key)
{
	xex_endecrypt(out, in, n, seq, tweak_key, encrypt_key, 0);
}

// Decrypt the 16-byte block specified by in using AES in XEX mode. The
// plaintext will be placed in out.
// See xex_encrypt() for what description of what this does and what each
// argument refers to.
static void xex_decrypt(u8 *out, u8 *in, u8 *n, u8 seq, u8 *tweak_key, u8 *encrypt_key)
{
	xex_endecrypt(out, in, n, seq, tweak_key, encrypt_key, 1);
}

// Set the 128-bit tweak key to the contents of in.
// The tweak key can be considered as a secondary, independent encryption key.
void set_tweak_key(u8 *in)
{
	u8 i;
	for (i = 0; i < 16; i++)
	{
		nvstorage_tweak_key[i] = in[i];
	}
}

// Set the 128-bit encryption key to the contents of in.
void set_encryption_key(u8 *in)
{
	u8 i;
	for (i = 0; i < 16; i++)
	{
		nvstorage_encrypt_key[i] = in[i];
	}
}

// Place encryption keys in the buffer pointed to by out. out must point
// to an array of 32 bytes. The (primary) encryption key is written to the
// first 16 bytes and the tweak key is written to the last 16 bytes.
void get_encryption_keys(u8 *out)
{
	u8 i;
	for (i = 0; i < 16; i++)
	{
		out[i] = nvstorage_encrypt_key[i];
	}
	for (i = 0; i < 16; i++)
	{
		out[i + 16] = nvstorage_tweak_key[i];
	}
}

// Returns non-zero if any one of the encryption keys is non-zero.
u8 are_encryption_keys_nonzero(void)
{
	u8 r;
	u8 i;

	r = 0;
	for (i = 0; i < 16; i++)
	{
		r |= nvstorage_encrypt_key[i];
		r |= nvstorage_tweak_key[i];
	}
	return r;
}

// Clear out memory which stores encryption keys.
// In order to be sure that keys don't remain in RAM anywhere, you may also
// need to clear out the space between the heap and the stack.
void clear_keys(void)
{
	u8 i;
	for (i = 0; i < 16; i++)
	{
		// Just to be sure
		nvstorage_tweak_key[i] = 0xff;
		nvstorage_encrypt_key[i] = 0xff;
	}
	for (i = 0; i < 16; i++)
	{
		nvstorage_tweak_key[i] = 0;
		nvstorage_encrypt_key[i] = 0;
	}
}

// Wrapper around nonvolatile_write() which also encrypts using the
// nvstorage_tweak_key/nvstorage_encrypt_key encryption keys.
nonvolatile_return encrypted_nonvolatile_write(u8 *data, u32 address, u8 length)
{
	u32 block_start;
	u32 block_end;
	u8 block_offset;
	u8 ciphertext[16];
	u8 plaintext[16];
	u8 n[16];
	u8 i;
	nonvolatile_return r;

	block_start = address & 0xfffffff0;
	block_offset = (u8)(address & 0x0000000f);
	block_end = (address + length - 1) & 0xfffffff0;

	for (i = 0; i < 16; i++)
	{
		n[i] = 0;
	}
	for (; block_start <= block_end; block_start += 16)
	{
		r = nonvolatile_read(ciphertext, block_start, 16);
		if (r != NV_NO_ERROR)
		{
			return r;
		}
		write_u32_littleendian(n, block_start);
		xex_decrypt(plaintext, ciphertext, n, 1, nvstorage_tweak_key, nvstorage_encrypt_key);
		while (length && block_offset < 16)
		{
			plaintext[block_offset++] = *data++;
			length--;
		}
		block_offset = 0;
		xex_encrypt(ciphertext, plaintext, n, 1, nvstorage_tweak_key, nvstorage_encrypt_key);
		r = nonvolatile_write(ciphertext, block_start, 16);
		if (r != NV_NO_ERROR)
		{
			return r;
		}
	}

	return NV_NO_ERROR;
}

// Wrapper around nonvolatile_read() which also decrypts using the
// nvstorage_tweak_key/nvstorage_encrypt_key encryption keys.
nonvolatile_return encrypted_nonvolatile_read(u8 *data, u32 address, u8 length)
{
	u32 block_start;
	u32 block_end;
	u8 block_offset;
	u8 ciphertext[16];
	u8 plaintext[16];
	u8 n[16];
	u8 i;
	nonvolatile_return r;

	block_start = address & 0xfffffff0;
	block_offset = (u8)(address & 0x0000000f);
	block_end = (address + length - 1) & 0xfffffff0;

	for (i = 0; i < 16; i++)
	{
		n[i] = 0;
	}
	for (; block_start <= block_end; block_start += 16)
	{
		r = nonvolatile_read(ciphertext, block_start, 16);
		if (r != NV_NO_ERROR)
		{
			return r;
		}
		write_u32_littleendian(n, block_start);
		xex_decrypt(plaintext, ciphertext, n, 1, nvstorage_tweak_key, nvstorage_encrypt_key);
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

static void skipwhitespace(FILE *f)
{
	int onechar;
	do
	{
		onechar = fgetc(f);
	} while ((onechar == ' ') || (onechar == '\t') || (onechar == '\n') || (onechar == '\r'));
	ungetc(onechar, f);
}

static void skipline(FILE *f)
{
	int onechar;
	do
	{
		onechar = fgetc(f);
	} while (onechar != '\n');
}

static void print16(u8 *buffer)
{
	int i;
	for (i = 0; i < 16; i++)
	{
		printf("%02x", (int)buffer[i]);
	}
}

static void scantestvectors(char *filename, int isdataunitseqnumber)
{
	FILE *f;
	int testnumber;
	int dataunitlength;
	int isencrypt;
	int i;
	int j;
	int value;
	int seencount;
	int testfailed;
	char buffer[100];
	u8 tweak_key[16];
	u8 encrypt_key[16];
	u8 tweak_value[16];
	u8 *plaintext;
	u8 *ciphertext;
	u8 *compare;

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

	testnumber = 1;
	for (i = 0; i < 11; i++)
	{
		skipline(f);
	}
	isencrypt = 1;
	while (!feof(f))
	{
		// Check for [DECRYPT]
		skipwhitespace(f);
		seencount = 0;
		while (!seencount)
		{
			fgets(buffer, 6, f);
			skipline(f);
			skipwhitespace(f);
			if (!strcmp(buffer, "[DECR"))
			{
				isencrypt = 0;
			}
			else if (!strcmp(buffer, "COUNT"))
			{
				seencount = 1;
			}
			else
			{
				printf("Expected \"COUNT\" or \"[DECR\"\n");
				exit(1);
			}
		}

		// Get data length
		fgets(buffer, 15, f);
		if (strcmp(buffer, "DataUnitLen = "))
		{
			printf("Parse error; expected \"DataUnitLen = \"\n");
			exit(1);
		}
		fscanf(f, "%d", &dataunitlength);
		if ((dataunitlength <= 0) || (dataunitlength > 10000000))
		{
			printf("Error: got absurd data unit length %d\n", dataunitlength);
			exit(1);
		}
		skipwhitespace(f);

		if (dataunitlength & 0x7f)
		{
			// Skip tests which require ciphertext stealing, since ciphertext
			// stealing isn't implemented here (because it's not necessary).
			for (i = 0; i < 6; i++)
			{
				skipline(f);
			}
		}
		else
		{
			dataunitlength >>= 3; // number of bits to number of bytes

			// Get key
			fgets(buffer, 7, f);
			if (strcmp(buffer, "Key = "))
			{
				printf("Parse error; expected \"Key = \"\n");
				exit(1);
			}
			for (i = 0; i < 16; i++)
			{
				fscanf(f, "%02x", &value);
				encrypt_key[i] = (u8)value;
			}
			for (i = 0; i < 16; i++)
			{
				fscanf(f, "%02x", &value);
				tweak_key[i] = (u8)value;
			}
			skipwhitespace(f);

			// Get tweak value
			if (isdataunitseqnumber)
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
				tweak_value[0] = (u8)n;
				tweak_value[1] = (u8)(n >> 8);
				tweak_value[2] = (u8)(n >> 16);
				tweak_value[3] = (u8)(n >> 24);
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
					tweak_value[i] = (u8)value;
				}
			}
			skipwhitespace(f);

			plaintext = malloc(dataunitlength);
			ciphertext = malloc(dataunitlength);
			compare = malloc(dataunitlength);

			// Get plaintext/ciphertext
			// The order is: plaintext, then ciphertext for encrypt.
			// The order is: ciphertext, then plaintext for decrypt.
			for (j = 0; j < 2; j++)
			{
				if (((isencrypt) && (j == 0))
					|| ((!isencrypt) && (j != 0)))
				{
					fgets(buffer, 6, f);
					if (strcmp(buffer, "PT = "))
					{
						printf("Parse error; expected \"PT = \"\n");
						exit(1);
					}
					for (i = 0; i < dataunitlength; i++)
					{
						fscanf(f, "%02x", &value);
						plaintext[i] = (u8)value;
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
					for (i = 0; i < dataunitlength; i++)
					{
						fscanf(f, "%02x", &value);
						ciphertext[i] = (u8)value;
					}
				}
				skipwhitespace(f);
			} // end for (j = 0; j < 2; j++)

			// Do encryption/decryption and compare
			testfailed = 0;
			if (isencrypt)
			{
				for (i = 0; i < dataunitlength; i += 16)
				{
					xex_encrypt(&(compare[i]), &(plaintext[i]), tweak_value, (u8)(i >> 4), tweak_key, encrypt_key);
					if (memcmp(&(compare[i]), &(ciphertext[i]), 16))
					{
						testfailed = 1;
						break;
					}
				}
			}
			else
			{
				for (i = 0; i < dataunitlength; i += 16)
				{
					xex_decrypt(&(compare[i]), &(ciphertext[i]), tweak_value, (u8)(i >> 4), tweak_key, encrypt_key);
					if (memcmp(&(compare[i]), &(plaintext[i]), 16))
					{
						testfailed = 1;
						break;
					}
				}
			}
			if (!testfailed)
			{
				succeeded++;
			}
			else
			{
				printf("Test %d failed\n", testnumber);
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
			testnumber++;
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

extern void wallet_test_init(void);

int main(int argc, char **argv)
{
	u8 what_storage_should_be[MAX_ADDRESS];
	u8 buffer[256];
	u8 onekey[16];
	int i;
	int j;

	// Reference argc and argv just to make certain compilers happy.
	if (argc == 2)
	{
		printf("%s\n", argv[1]);
	}

	wallet_test_init();
	clear_keys();
	srand(42);
	succeeded = 0;
	failed = 0;
	scantestvectors("XTSGenAES128i.rsp", 0);
	scantestvectors("XTSGenAES128d.rsp", 1);

	for (i = 0; i < MAX_ADDRESS; i++)
	{
		what_storage_should_be[i] = (u8)rand();
	}
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encrypted_nonvolatile_write(&(what_storage_should_be[i]), i, 128);
	}
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encrypted_nonvolatile_read(buffer, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			printf("Storage mismatch in encrypted_nonvolatile_read()\n");
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
		u32 address;
		u8 length;

		do
		{
			address = (u32)(rand() & (MAX_ADDRESS - 1));
			length = (u8)(rand() & 0xff);
		} while ((address + length) > MAX_ADDRESS);
		if (rand() & 1)
		{
			// Write 50% of the time
			for (j = 0; j < length; j++)
			{
				buffer[j] = (u8)rand();
			}
			memcpy(&(what_storage_should_be[address]), buffer, length);
			if (encrypted_nonvolatile_write(buffer, address, length) != NV_NO_ERROR)
			{
				printf("encrypted_nonvolatile_write() failed\n");
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
			if (encrypted_nonvolatile_read(buffer, address, length) != NV_NO_ERROR)
			{
				printf("encrypted_nonvolatile_read() failed\n");
				printf("test number = %d, address = 0x%08x, length = %d\n", i, (int)address, (int)length);
				failed++;
			}
			else
			{
				if (memcmp(&(what_storage_should_be[address]), buffer, length))
				{
					printf("Storage mismatch in encrypted_nonvolatile_read()\n");
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
	set_tweak_key(onekey);
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encrypted_nonvolatile_read(buffer, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			succeeded++;
		}
		else
		{
			printf("Storage match in encrypted_nonvolatile_read() when using different tweak key\n");
			printf("Final run, address = 0x%08x, length = 128\n", i);
			failed++;
		}
	}

	// Change only (primary) encryption key.
	clear_keys();
	set_encryption_key(onekey);
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encrypted_nonvolatile_read(buffer, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			succeeded++;
		}
		else
		{
			printf("Storage match in encrypted_nonvolatile_read() when using different primary encryption key\n");
			printf("Final run, address = 0x%08x, length = 128\n", i);
			failed++;
		}
	}

	// Switch back to original, correct keys. All should be fine now.
	clear_keys();
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encrypted_nonvolatile_read(buffer, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			printf("Storage mismatch in encrypted_nonvolatile_read() when keys are okay\n");
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

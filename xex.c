/** \file xex.c
  *
  * \brief Implements XEX mode for encryption of a random-access block device.
  *
  * For details, see "Efficient Instantiations of Tweakable Blockciphers and
  * Refinements to Modes OCB and PMAC" (dated September 24, 2004) by Phillip
  * Rogaway, obtained from
  * http://www.cs.ucdavis.edu/~rogaway/papers/offsets.pdf
  * on 5-February-2012.
  * XEX mode combines the random-access ability of CTR mode with the
  * bit-flipping attack resistance of ECB mode.
  *
  * This uses AES (see aes.c) as the underlying block cipher. Using AES in XEX
  * mode, with ciphertext stealing and with independent keys is sometimes
  * called "XTS-AES". But as long as the length of a
  * wallet record (#WALLET_RECORD_LENGTH) is a multiple of 16 bytes,
  * ciphertext stealing is not necessary. Thus the use
  * of AES in XEX mode here is identical in operation to XTS-AES.
  * As in XTS-AES, independent "tweak" and "encryption" keys are used. This
  * means that the combined key is 256 bits in length. But since this 256 bit
  * key is composed of two 128 bit keys, the final cipher still only
  * has 128 bits of security.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifdef TEST_XEX
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "test_helpers.h"
#include "wallet.h"
#endif // #ifdef TEST_XEX

#include "common.h"
#include "aes.h"
#include "prandom.h"
#include "hwinterface.h"
#include "endian.h"

/** Primary encryption key. */
static uint8_t nv_storage_encrypt_key[16];
/** The tweak key can be considered as a secondary, independent encryption
  * key. */
static uint8_t nv_storage_tweak_key[16];

/** Double a 128 bit integer under GF(2 ^ 128) with
  * reducing polynomial x ^ 128 + x ^ 7 + x ^ 2 + x + 1.
  * \param op1 The 128 bit integer to double. This should be an array of
  *            16 bytes representing the 128 bit integer in unsigned,
  *            little-endian multi-precision format.
  */
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

/** Combined XEX mode encrypt/decrypt, since they're almost the same.
  * See xexEncryptInternal() and xexDecryptInternal() for a description of
  * what this does and what each parameter is.
  * \param out For encryption, this will be the resulting ciphertext. For
  *            decryption, this will be the resulting plaintext.
  * \param in For encryption, this will be the source plaintext. For
  *           decryption, this will be the source ciphertext.
  * \param n See xexEncryptInternal().
  * \param seq See xexEncryptInternal().
  * \param tweak_key See xexEncryptInternal().
  * \param encrypt_key See xexEncryptInternal().
  * \param is_decrypt To decrypt, use true. To encrypt, use false.
  */
static void xexEnDecrypt(uint8_t *out, uint8_t *in, uint8_t *n, uint8_t seq, uint8_t *tweak_key, uint8_t *encrypt_key, bool is_decrypt)
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
	memcpy(buffer, in, 16);
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

/** Encrypt one 16 byte block using AES in XEX mode. This uses an arbitrary
  * encryption key.
  * \param out The resulting ciphertext will be written to here. This must be
  *            a byte array with space for 16 bytes.
  * \param in The source plaintext. This must be a byte array containing the
  *           16 byte plaintext.
  * \param n A 128 bit number which specifies the number of the data
  *          unit (whatever a data unit is defined to be). This should be a
  *          byte array of 16 bytes, with the 128 bit number in unsigned,
  *          little-endian multi-precision format. This is one of the
  *          tweakable parameters.
  * \param seq Specifies the block within the data unit. This is the other
  *            tweakable parameter.
  * \param tweak_key A 128 bit AES key.
  * \param encrypt_key Another 128 bit AES key. This must be independent of
  *                    tweak_key.
  * \warning Don't use seq = 0, as this presents a security
  *          vulnerability (albeit a convoluted one). For more details about
  *          the seq = 0 issue, see section 6 ("Security of XEX") of
  *          Rogaway's paper (reference at the top of this file).
  */
static void xexEncryptInternal(uint8_t *out, uint8_t *in, uint8_t *n, uint8_t seq, uint8_t *tweak_key, uint8_t *encrypt_key)
{
	xexEnDecrypt(out, in, n, seq, tweak_key, encrypt_key, false);
}

/** Decrypt the 16 byte block using AES in XEX mode. This uses an arbitrary
  * encryption key.
  * \param out The resulting plaintext will be written to here. This must be
  *            a byte array with space for 16 bytes.
  * \param in The source ciphertext. This must be a byte array containing the
  *           16 byte ciphertext.
  * \param n See xexEncryptInternal().
  * \param seq See xexEncryptInternal().
  * \param tweak_key See xexEncryptInternal().
  * \param encrypt_key See xexEncryptInternal().
  */
static void xexDecryptInternal(uint8_t *out, uint8_t *in, uint8_t *n, uint8_t seq, uint8_t *tweak_key, uint8_t *encrypt_key)
{
	xexEnDecrypt(out, in, n, seq, tweak_key, encrypt_key, true);
}

/** Encrypt one 16 byte block using AES in XEX mode. This uses the encryption
  * key set by setEncryptionKey().
  * \param out The resulting ciphertext will be written to here. This must be
  *            a byte array with space for 16 bytes.
  * \param in The source plaintext. This must be a byte array containing the
  *           16 byte plaintext.
  * \param n See xexEncryptInternal().
  * \param seq See xexEncryptInternal().
  */
void xexEncrypt(uint8_t *out, uint8_t *in, uint8_t *n, uint8_t seq)
{
	xexEncryptInternal(out, in, n, seq, nv_storage_tweak_key, nv_storage_encrypt_key);
}

/** Decrypt the 16 byte block using AES in XEX mode. This uses the encryption
  * key set by setEncryptionKey().
  * \param out The resulting plaintext will be written to here. This must be
  *            a byte array with space for 16 bytes.
  * \param in The source ciphertext. This must be a byte array containing the
  *           16 byte ciphertext.
  * \param n See xexEncryptInternal().
  * \param seq See xexEncryptInternal().
  */
void xexDecrypt(uint8_t *out, uint8_t *in, uint8_t *n, uint8_t seq)
{
	xexDecryptInternal(out, in, n, seq, nv_storage_tweak_key, nv_storage_encrypt_key);
}

/** Set the combined encryption key.
  * This is compatible with getEncryptionKey().
  * \param in A #WALLET_ENCRYPTION_KEY_LENGTH byte array specifying the
  *           combined encryption key to use in XEX encryption/decryption
  *           operations.
  */
void setEncryptionKey(const uint8_t *in)
{
	memcpy(nv_storage_encrypt_key, in, 16);
	memcpy(nv_storage_tweak_key, &(in[16]), 16);
}

/** Get the combined encryption key.
  * This is compatible with setEncryptionKey().
  * \param out A #WALLET_ENCRYPTION_KEY_LENGTH byte array specifying where the
  *            current combined encryption key will be written to.
  */
void getEncryptionKey(uint8_t *out)
{
	memcpy(out, nv_storage_encrypt_key, 16);
	memcpy(&(out[16]), nv_storage_tweak_key, 16);
}

/** Check if the current combined encryption key is all zeroes. This has
  * implications for whether a wallet is considered encrypted or
  * not (see wallet.c).
  * \return true if the encryption key is not made up of all zeroes,
  *         false if the encryption key is made up of all zeroes.
  */
bool isEncryptionKeyNonZero(void)
{
	uint8_t r;
	uint8_t i;

	r = 0;
	for (i = 0; i < 16; i++)
	{
		r |= nv_storage_encrypt_key[i];
		r |= nv_storage_tweak_key[i];
	}
	if (r != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

/** Clear out memory which stores encryption keys.
  * In order to be sure that keys don't remain in RAM anywhere, you may also
  * need to clear out the space between the heap and the stack.
  */
void clearEncryptionKey(void)
{
	// Just to be sure, do two passes.
	memset(nv_storage_tweak_key, 0xff, 16);
	memset(nv_storage_encrypt_key, 0xff, 16);
	memset(nv_storage_tweak_key, 0, 16);
	memset(nv_storage_encrypt_key, 0, 16);
}

/** Wrapper around nonVolatileWrite() which also encrypts data
  * using xexEncrypt(). Because this uses encryption, it is much slower
  * than nonVolatileWrite(). The parameters and return values are identical
  * to that of nonVolatileWrite().
  * \param data A pointer to the data to be written.
  * \param partition The partition to write to. Must be one of #NVPartitions.
  * \param address Byte offset specifying where in the partition to
  *                start writing to.
  * \param length The number of bytes to write.
  * \return See #NonVolatileReturnEnum for return values.
  * \warning Writes may be buffered; use nonVolatileFlush() to be sure that
  *          data is actually written to non-volatile storage.
  */
NonVolatileReturn encryptedNonVolatileWrite(uint8_t *data, NVPartitions partition, uint32_t address, uint32_t length)
{
	uint32_t block_start;
	uint32_t block_end;
	uint8_t block_offset;
	uint8_t ciphertext[16];
	uint8_t plaintext[16];
	uint8_t n[16];
	NonVolatileReturn r;

	block_start = address & 0xfffffff0;
	block_offset = (uint8_t)(address & 0x0000000f);
	block_end = (address + length - 1) & 0xfffffff0;
	if ((address + length) < address)
	{
		// Overflow occurred.
		return NV_INVALID_ADDRESS;
	}

	memset(n, 0, 16);
	for (; block_start <= block_end; block_start += 16)
	{
		r = nonVolatileRead(ciphertext, partition, block_start, 16);
		if (r != NV_NO_ERROR)
		{
			return r;
		}
		writeU32LittleEndian(n, block_start);
		xexDecrypt(plaintext, ciphertext, n, 1);
		while (length && block_offset < 16)
		{
			plaintext[block_offset++] = *data++;
			length--;
		}
		block_offset = 0;
		xexEncrypt(ciphertext, plaintext, n, 1);
		r = nonVolatileWrite(ciphertext, partition, block_start, 16);
		if (r != NV_NO_ERROR)
		{
			return r;
		}
	}

	return NV_NO_ERROR;
}

/** Wrapper around nonVolatileRead() which also decrypts data
  * using xexDecrypt(). Because this uses encryption, it is much slower
  * than nonVolatileRead(). The parameters and return values are identical
  * to that of nonVolatileRead().
  * \param data A pointer to the buffer which will receive the data.
  * \param partition The partition to read from. Must be one of #NVPartitions.
  * \param address Byte offset specifying where in the partition to
  *                start reading from.
  * \param length The number of bytes to read.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn encryptedNonVolatileRead(uint8_t *data, NVPartitions partition, uint32_t address, uint32_t length)
{
	uint32_t block_start;
	uint32_t block_end;
	uint8_t block_offset;
	uint8_t ciphertext[16];
	uint8_t plaintext[16];
	uint8_t n[16];
	NonVolatileReturn r;

	block_start = address & 0xfffffff0;
	block_offset = (uint8_t)(address & 0x0000000f);
	block_end = (address + length - 1) & 0xfffffff0;
	if ((address + length) < address)
	{
		// Overflow occurred.
		return NV_INVALID_ADDRESS;
	}

	memset(n, 0, 16);
	for (; block_start <= block_end; block_start += 16)
	{
		r = nonVolatileRead(ciphertext, partition, block_start, 16);
		if (r != NV_NO_ERROR)
		{
			return r;
		}
		writeU32LittleEndian(n, block_start);
		xexDecrypt(plaintext, ciphertext, n, 1);
		while (length && block_offset < 16)
		{
			*data++ = plaintext[block_offset++];
			length--;
		}
		block_offset = 0;
	}

	return NV_NO_ERROR;
}

#ifdef TEST_XEX

/** Run unit tests using test vectors from a file. The file is expected to be
  * in the same format as the NIST "XTS-AES Test Vectors",
  * which can be obtained from: http://csrc.nist.gov/groups/STM/cavp/#08
  * \param filename The name of the file containing the test vectors.
  * \param is_data_unit_seq_number If this is non-zero, this function expects
  *                                data unit sequence numbers (look
  *                                for "DataUnitSeqNumber =" in the file) as
  *                                the tweak value. Otherwise, this function
  *                                expects "i =" to specify the tweak value.
  */
static void scanTestVectors(char *filename, int is_data_unit_seq_number)
{
	FILE *f;
	int test_number;
	unsigned int data_unit_length;
	bool is_encrypt;
	unsigned int i;
	int j;
	int value;
	bool seen_count;
	bool test_failed;
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
		printf("There should be two versions: one with 128 bit hex strings as the tweak\n");
		printf("value, and one with a \"data unit sequence number\" as the tweak value.\n");
		printf("Rename the one with 128 bit hex string tweak values \"XTSGenAES128i.rsp\"\n");
		printf("and rename the one with data unit sequence numbers \"XTSGenAES128d.rsp\".\n");
		exit(1);
	}

	test_number = 1;
	for (i = 0; i < 11; i++)
	{
		skipLine(f);
	}
	is_encrypt = true;
	while (!feof(f))
	{
		// Check for [DECRYPT].
		skipWhiteSpace(f);
		seen_count = false;
		while (!seen_count)
		{
			fgets(buffer, 6, f);
			skipLine(f);
			skipWhiteSpace(f);
			if (!strcmp(buffer, "[DECR"))
			{
				is_encrypt = false;
			}
			else if (!strcmp(buffer, "COUNT"))
			{
				seen_count = true;
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
		fscanf(f, "%u", &data_unit_length);
		if ((data_unit_length <= 0) || (data_unit_length > 10000000))
		{
			printf("Error: got absurd data unit length %u\n", data_unit_length);
			exit(1);
		}
		skipWhiteSpace(f);

		if ((data_unit_length & 0x7f) != 0)
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
			test_failed = false;
			if (is_encrypt)
			{
				for (i = 0; i < data_unit_length; i += 16)
				{
					xexEncryptInternal(&(compare[i]), &(plaintext[i]), tweak_value, (uint8_t)(i >> 4), tweak_key, encrypt_key);
					if (memcmp(&(compare[i]), &(ciphertext[i]), 16))
					{
						test_failed = true;
						break;
					}
				}
			}
			else
			{
				for (i = 0; i < data_unit_length; i += 16)
				{
					xexDecryptInternal(&(compare[i]), &(ciphertext[i]), tweak_value, (uint8_t)(i >> 4), tweak_key, encrypt_key);
					if (memcmp(&(compare[i]), &(plaintext[i]), 16))
					{
						test_failed = true;
						break;
					}
				}
			}
			if (!test_failed)
			{
				reportSuccess();
			}
			else
			{
				printf("Test %d failed\n", test_number);
				printf("Key: ");
				printBigEndian16(encrypt_key);
				printBigEndian16(tweak_key);
				printf("\nFirst 16 bytes of plaintext: ");
				printBigEndian16(plaintext);
				printf("\nFirst 16 bytes of ciphertext: ");
				printBigEndian16(ciphertext);
				printf("\n");
				reportFailure();
			}
			test_number++;
			free(plaintext);
			free(ciphertext);
			free(compare);
		}
	}
	fclose(f);
}

/** Maximum address that a write to non-volatile storage will be.
  * Must be multiple of 128. */
#define MAX_ADDRESS 1024
/** Number of read/write tests to do. */
#define NUM_RW_TESTS 100000

int main(void)
{
	uint8_t what_storage_should_be[MAX_ADDRESS];
	uint8_t buffer[512];
	uint8_t one_key[32];
	unsigned int i;
	unsigned int j;

	initTests(__FILE__);

	initWalletTest();
	clearEncryptionKey();

	scanTestVectors("XTSGenAES128i.rsp", 0);
	scanTestVectors("XTSGenAES128d.rsp", 1);

	for (i = 0; i < MAX_ADDRESS; i++)
	{
		what_storage_should_be[i] = (uint8_t)rand();
	}
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encryptedNonVolatileWrite(&(what_storage_should_be[i]), PARTITION_ACCOUNTS, i, 128);
	}
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encryptedNonVolatileRead(buffer, PARTITION_ACCOUNTS, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			printf("Storage mismatch in encryptedNonVolatileRead()\n");
			printf("Initial fill, address = 0x%08x, length = 128\n", i);
			reportFailure();
		}
		else
		{
			reportSuccess();
		}
	}

	// Now read and write randomly, mirroring the reads and writes to the
	// what_storage_should_be array.
	for (i = 0; i < NUM_RW_TESTS; i++)
	{
		uint32_t address;
		uint32_t length;

		do
		{
			address = (uint32_t)(rand() & (MAX_ADDRESS - 1));
			length = rand() % sizeof(buffer);
		} while ((address + length) > MAX_ADDRESS);
		if (rand() & 1)
		{
			// Write 50% of the time
			for (j = 0; j < length; j++)
			{
				buffer[j] = (uint8_t)rand();
			}
			memcpy(&(what_storage_should_be[address]), buffer, length);
			if (encryptedNonVolatileWrite(buffer, PARTITION_ACCOUNTS, address, length) != NV_NO_ERROR)
			{
				printf("encryptedNonVolatileWrite() failed\n");
				printf("test number = %u, address = 0x%08x, length = %d\n", i, (int)address, (int)length);
				reportFailure();
			}
			else
			{
				reportSuccess();
			}
		}
		else
		{
			// Read 50% of the time
			if (encryptedNonVolatileRead(buffer, PARTITION_ACCOUNTS, address, length) != NV_NO_ERROR)
			{
				printf("encryptedNonVolatileRead() failed\n");
				printf("test number = %u, address = 0x%08x, length = %d\n", i, (int)address, (int)length);
				reportFailure();
			}
			else
			{
				if (memcmp(&(what_storage_should_be[address]), buffer, length))
				{
					printf("Storage mismatch in encryptedNonVolatileRead()\n");
					printf("test number = %u, address = 0x%08x, length = %d\n", i, (int)address, (int)length);
					reportFailure();
				}
				else
				{
					reportSuccess();
				}
			}
		}
	}

	// Now change the encryption keys and try to obtain the contents of the
	// non-volatile storage. The result should be mismatches everywhere.

	// Change only tweak key.
	memset(one_key, 0, 32);
	one_key[16] = 1;
	setEncryptionKey(one_key);
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encryptedNonVolatileRead(buffer, PARTITION_ACCOUNTS, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			reportSuccess();
		}
		else
		{
			printf("Storage match in encryptedNonVolatileRead() when using different tweak key\n");
			printf("Final run, address = 0x%08x, length = 128\n", i);
			reportFailure();
		}
	}

	// Change only (primary) encryption key.
	memset(one_key, 0, 32);
	one_key[0] = 1;
	setEncryptionKey(one_key);
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encryptedNonVolatileRead(buffer, PARTITION_ACCOUNTS, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			reportSuccess();
		}
		else
		{
			printf("Storage match in encryptedNonVolatileRead() when using different primary encryption key\n");
			printf("Final run, address = 0x%08x, length = 128\n", i);
			reportFailure();
		}
	}

	// Switch back to original, correct keys. All should be fine now.
	clearEncryptionKey();
	for (i = 0; i < MAX_ADDRESS; i += 128)
	{
		encryptedNonVolatileRead(buffer, PARTITION_ACCOUNTS, i, 128);
		if (memcmp(&(what_storage_should_be[i]), buffer, 128))
		{
			printf("Storage mismatch in encryptedNonVolatileRead() when keys are okay\n");
			printf("Final run, address = 0x%08x, length = 128\n", i);
			reportFailure();
		}
		else
		{
			reportSuccess();
		}
	}

	finishTests();
	exit(0);
}

#endif // #ifdef TEST_XEX

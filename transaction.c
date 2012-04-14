// ***********************************************************************
// transaction.c
// ***********************************************************************
//
// Containes functions specific to Bitcoin transactions.
//
// This file is licensed as described by the file LICENCE.

// Defining this will facilitate testing
//#define TEST
// Defining this will provide useless stubs for interface functions, to stop
// linker errors from occuring
//#define INTERFACE_STUBS

// The maximum size of a transaction (in bytes) which parseTransaction()
// is prepared to handle.
#define MAX_TRANSACTION_SIZE	200000

#if defined(TEST) || defined(INTERFACE_STUBS)
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#endif // #if defined(TEST) || defined(INTERFACE_STUBS)

#include "common.h"
#include "endian.h"
#include "ecdsa.h"
#include "baseconv.h"
#include "sha256.h"
#include "bignum256.h"
#include "prandom.h"
#include "hwinterface.h"
#include "transaction.h"

static uint32_t transaction_data_index;
static uint32_t transaction_length;
static uint16_t transaction_num_inputs;
static uint8_t read_error_occurred;
static uint8_t suppress_transaction_hash;
static uint8_t suppress_both_hash;
static HashState sig_hash_hs;
static HashState transaction_hash_hs;

// Returns the number of inputs from the most recent transaction parsed by
// parseTransaction. Returns 0 if there was an error obtaining the number
// of inputs.
uint16_t getTransactionNumInputs(void)
{
	return transaction_num_inputs;
}

// Returns 0 on success and fills buffer with length bytes,
// otherwise returns 1 to indicate an unexpected end of transaction data.
static uint8_t getTransactionBytes(uint8_t *buffer, uint8_t length)
{
	uint8_t i;
	uint8_t one_byte;

	if (transaction_data_index + (uint32_t)length > transaction_length)
	{
		return 1; // trying to read past end of transaction
	}
	else
	{
		for (i = 0; i < length; i++)
		{
			if (streamGetOneByte(&one_byte))
			{
				read_error_occurred = 1;
				return 1; // error while trying to get byte from stream
			}
			buffer[i] = one_byte;
			if (!suppress_both_hash)
			{
				sha256WriteByte(&sig_hash_hs, one_byte);
				if (!suppress_transaction_hash)
				{
					sha256WriteByte(&transaction_hash_hs, one_byte);
				}
			}
			transaction_data_index++;
		}
		return 0;
	}
}

// Returns 0 if not at end of transaction data, otherwise returns 1.
static uint8_t isEndOfTransactionData(void)
{
	if (transaction_data_index >= transaction_length)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

// Read a variable-sized integer from the transaction data stream.
// Returns 0 on success and writes value of varint to out.
// Returns 1 to indicate an unexpected end of transaction data.
// Returns 2 to indicate that the varint is too large.
// This only supports varints up to 2 ^ 32 - 1.
static uint8_t getVarInt(uint32_t *out)
{
	uint8_t temp[4];

	if (getTransactionBytes(temp, 1))
	{
		return 1; // unexpected end of transaction data
	}
	if (temp[0] < 0xfd)
	{
		*out = temp[0];
	}
	else if (temp[0] == 0xfd)
	{
		if (getTransactionBytes(temp, 2))
		{
			return 1; // unexpected end of transaction data
		}
		*out = (uint32_t)(temp[0]) | ((uint32_t)(temp[1]) << 8);
	}
	else if (temp[0] == 0xfe)
	{
		if (getTransactionBytes(temp, 4))
		{
			return 1; // unexpected end of transaction data
		}
		*out = readU32LittleEndian(temp);
	}
	else
	{
		return 2; // varint is too large
	}
	return 0;
}

// See comments for parseTransaction() for description of what this does
// and return values.
static TransactionErrors parseTransactionInternal(BigNum256 sig_hash, BigNum256 transaction_hash, uint32_t length)
{
	uint8_t temp[20];
	uint32_t num_inputs;
	uint8_t num_outputs;
	uint32_t script_length;
	uint16_t i;
	uint8_t j;
	uint32_t i32;
	char text_amount[22];
	char text_address[36];

	transaction_num_inputs = 0;
	read_error_occurred = 0;
	transaction_data_index = 0;
	transaction_length = length;
	if (length > MAX_TRANSACTION_SIZE)
	{
		return TRANSACTION_TOO_LARGE; // transaction too large
	}

	sha256Begin(&sig_hash_hs);
	suppress_both_hash = 0;
	sha256Begin(&transaction_hash_hs);
	suppress_transaction_hash = 0;

	// Check version.
	if (getTransactionBytes(temp, 4))
	{
		return TRANSACTION_INVALID_FORMAT; // transaction truncated
	}
	if ((temp[0] != 0x01) || (temp[1] != 0x00)
		|| (temp[2] != 0x00) || (temp[3] != 0x00))
	{
		return TRANSACTION_INVALID_FORMAT; // unsupported transaction version
	}

	// Get number of inputs.
	if (getVarInt(&num_inputs))
	{
		return TRANSACTION_INVALID_FORMAT; // transaction truncated or varint too big
	}
	if (num_inputs == 0)
	{
		return TRANSACTION_INVALID_FORMAT; // invalid transaction
	}
	if (num_inputs >= 0xffff)
	{
		return TRANSACTION_TOO_MANY_INPUTS; // too many inputs
	}
	transaction_num_inputs = (uint16_t)num_inputs;

	// Process each input.
	for (i = 0; i < num_inputs; i++)
	{
		// Skip input transaction reference (hash and output number) because
		// it's useless here.
		for (j = 0; j < 9; j++)
		{
			if (getTransactionBytes(temp, 4))
			{
				return TRANSACTION_INVALID_FORMAT; // transaction truncated
			}
		}
		// The Bitcoin protocol for signing a transaction involves replacing
		// the corresponding input script with the output script that
		// the input references. This means that the transaction data parsed
		// here will be different depending on which input is being signed
		// for. The transaction hash is supposed to be the same regardless of
		// which input is being signed for, so the calculation of the
		// transaction hash ignores input scripts.
		suppress_transaction_hash = 1;
		// Get input script length.
		if (getVarInt(&script_length))
		{
			return TRANSACTION_INVALID_FORMAT; // transaction truncated or varint too big
		}
		// Skip the script because it's useless here.
		for (i32 = 0; i32 < script_length; i32++)
		{
			if (getTransactionBytes(temp, 1))
			{
				return TRANSACTION_INVALID_FORMAT; // transaction truncated
			}
		}
		suppress_transaction_hash = 0;
		// Skip sequence because it's useless here.
		if (getTransactionBytes(temp, 4))
		{
			return TRANSACTION_INVALID_FORMAT; // transaction truncated
		}
	}

	// Get number of outputs.
	if (getTransactionBytes(&num_outputs, 1))
	{
		return TRANSACTION_INVALID_FORMAT; // transaction truncated
	}
	if (num_outputs == 0)
	{
		return TRANSACTION_INVALID_FORMAT; // invalid transaction
	}
	if (num_outputs >= 0xfd)
	{
		return TRANSACTION_TOO_MANY_OUTPUTS; // too many outputs
	}

	// Process each output.
	for (i = 0; i < num_outputs; i++)
	{
		// Get output amount.
		if (getTransactionBytes(temp, 8))
		{
			return TRANSACTION_INVALID_FORMAT; // transaction truncated
		}
		amountToText(text_amount, temp);
		// Get output script length.
		if (getVarInt(&script_length))
		{
			return TRANSACTION_INVALID_FORMAT; // transaction truncated or varint too big
		}
		if (script_length != 0x19)
		{
			return TRANSACTION_NON_STANDARD; // nonstandard transaction
		}
		// Check for a standard, pay to address output script.
		// Look for: OP_DUP, OP_HASH160, (20 bytes of data).
		if (getTransactionBytes(temp, 3))
		{
			return TRANSACTION_INVALID_FORMAT; // transaction truncated
		}
		if ((temp[0] != 0x76) || (temp[1] != 0xa9) || (temp[2] != 0x14))
		{
			return TRANSACTION_NON_STANDARD; // nonstandard transaction
		}
		if (getTransactionBytes(temp, 20))
		{
			return TRANSACTION_INVALID_FORMAT; // transaction truncated
		}
		hashToAddr(text_address, temp);
		// Look for: OP_EQUALVERIFY OP_CHECKSIG.
		if (getTransactionBytes(temp, 2))
		{
			return TRANSACTION_INVALID_FORMAT; // transaction truncated
		}
		if ((temp[0] != 0x88) || (temp[1] != 0xac))
		{
			return TRANSACTION_NON_STANDARD; // nonstandard transaction
		}
		if (newOutputSeen(text_amount, text_address))
		{
			return TRANSACTION_TOO_MANY_OUTPUTS; // too many outputs
		}
	}

	// Check locktime.
	if (getTransactionBytes(temp, 4))
	{
		return TRANSACTION_INVALID_FORMAT; // transaction truncated
	}
	if ((temp[0] != 0x00) || (temp[1] != 0x00)
		|| (temp[2] != 0x00) || (temp[3] != 0x00))
	{
		return TRANSACTION_NON_STANDARD; // nonstandard transaction
	}

	// Check hashtype.
	if (getTransactionBytes(temp, 4))
	{
		return TRANSACTION_INVALID_FORMAT; // transaction truncated
	}
	if ((temp[0] != 0x01) || (temp[1] != 0x00)
		|| (temp[2] != 0x00) || (temp[3] != 0x00))
	{
		return TRANSACTION_NON_STANDARD; // nonstandard transaction
	}

	// Is there junk at the end of the transaction data?
	if (!isEndOfTransactionData())
	{
		return TRANSACTION_INVALID_FORMAT; // junk at end of transaction data
	}

	sha256FinishDouble(&sig_hash_hs);
	sha256Finish(&transaction_hash_hs);
	writeHashToByteArray(sig_hash, &sig_hash_hs, 0);
	writeHashToByteArray(transaction_hash, &transaction_hash_hs, 0);

	return 0;
}

// Parse a Bitcoin transaction, extracting the output amounts/addresses,
// validating the transaction (ensuring that it is "standard") and computing
// a double SHA-256 hash of the transaction. length should be the total length
// of the transaction data stream. If no read errors occur, then exactly
// length bytes should be read from the stream, even if the transaction is
// not parsed correctly. Upon success, the double SHA-256 hash will be written
// out to sig_hash (which should be a byte array which can hold 32 bytes) in
// little-endian format.
// In addition to sig_hash ("signature hash"), a transaction hash will be
// computed and written out to transaction_hash in little-endian format. The
// transaction hash is just like the signature hash, except input scripts
// are not included. The transaction hash can be used to determine
// if (when signing a transaction with multiple inputs) a bunch of
// transactions are "the same".
// Returns one of the values in TransactionErrors.
// This will always read the number of bytes specified by length from the
// input stream, even in the case of an invalid transaction.
TransactionErrors parseTransaction(BigNum256 sig_hash, BigNum256 transaction_hash, uint32_t length)
{
	TransactionErrors r;
	uint8_t junk;

	r = parseTransactionInternal(sig_hash, transaction_hash, length);
	if (!read_error_occurred)
	{
		// Always try to consume the entire stream.
		suppress_both_hash = 1;
		while (!isEndOfTransactionData())
		{
			if (getTransactionBytes(&junk, 1))
			{
				break;
			}
		}
	}
	else
	{
		// Read errors are more fundamental (in terms of cause and effect)
		// than other errors.
		return TRANSACTION_READ_ERROR;
	}
	return r;
}

// Swap endian representation of a 256-bit integer.
void swapEndian256(uint8_t *buffer)
{
	uint8_t i;
	uint8_t temp;

	for (i = 0; i < 16; i++)
	{
		temp = buffer[i];
		buffer[i] = buffer[31 - i];
		buffer[31 - i] = temp;
	}
}

// Initial offset of r in signature. It's 4 because 4 bytes are needed for
// the SEQUENCE/length and INTEGER/length bytes.
#define R_OFFSET	4
// Initial offset of s in signature. It's 39 because: r is initially 33
// bytes long, and 2 bytes are needed for INTEGER/length. 4 + 33 + 2 = 39.
#define S_OFFSET	39

// Sign the transaction with the (signature) hash specified by sig_hash, using
// the private key specified by private_key. Both sig_hash and private_key are
// little-endian 256-bit numbers. The resulting signature will be written
// out to signature in DER format, with the hash type appended. signature must
// have space for at least 73 bytes.
// The return value is the length of the signature (including the
// hash type byte).
uint8_t signTransaction(uint8_t *signature, BigNum256 sig_hash, BigNum256 private_key)
{
	uint8_t k[32];
	uint8_t sequence_length;
	uint8_t i;

	// Place an extra leading zero in front of r and s, just in case their
	// most significant bit is 1.
	// Integers in DER are always 2s-complement signed, but r and s are
	// non-negative. Thus if the most significant bit of r or s is 1,
	// a leading zero must be placed in front of the integer to signify that
	// it is non-negative.
	// If the most significant bit is not 1, the extraneous leading zero will
	// be removed in a check below.
	signature[R_OFFSET] = 0x00;
	signature[S_OFFSET] = 0x00;
	do
	{
		getRandom256(k);
	} while (ecdsaSign(
		(BigNum256)(&(signature[R_OFFSET + 1])),
		(BigNum256)(&(signature[S_OFFSET + 1])),
		sig_hash,
		private_key,
		k));
	swapEndian256(&(signature[R_OFFSET + 1]));
	swapEndian256(&(signature[S_OFFSET + 1]));

	sequence_length = 0x46; // 2 + 33 + 2 + 33
	signature[R_OFFSET - 2] = 0x02; // INTEGER
	signature[R_OFFSET - 1] = 0x21; // length of INTEGER
	signature[S_OFFSET - 2] = 0x02; // INTEGER
	signature[S_OFFSET - 1] = 0x21; // length of INTEGER
	signature[S_OFFSET + 33] = 0x01; // hashtype
	// According to DER, integers should be represented using the shortest
	// possible representation. This implies that leading zeroes should
	// always be removed. The exception to this is that if removing the
	// leading zero would cause the value of the integer to change (eg.
	// positive to negative), the leading zero should remain.

	// Remove unncecessary leading zeroes from s. s is pruned first
	// because pruning r will modify the offset where s begins.
	while ((signature[S_OFFSET] == 0) && ((signature[S_OFFSET + 1] & 0x80) == 0))
	{
		for (i = S_OFFSET; i < 72; i++)
		{
			signature[i] = signature[i + 1];
		}
		sequence_length--;
		signature[S_OFFSET - 1]--;
		if (signature[S_OFFSET - 1] == 1)
		{
			break;
		}
	}

	// Remove unnecessary leading zeroes from r.
	while ((signature[R_OFFSET] == 0) && ((signature[R_OFFSET + 1] & 0x80) == 0))
	{
		for (i = R_OFFSET; i < 72; i++)
		{
			signature[i] = signature[i + 1];
		}
		sequence_length--;
		signature[R_OFFSET - 1]--;
		if (signature[R_OFFSET - 1] == 1)
		{
			break;
		}
	}

	signature[0] = 0x30; // SEQUENCE
	signature[1] = sequence_length; // length of SEQUENCE
	// 3 extra bytes: SEQUENCE/length and hashtype
	return (uint8_t)(sequence_length + 3);
}

#if defined(TEST) || defined(INTERFACE_STUBS)

uint8_t newOutputSeen(char *text_amount, char *text_address)
{
	printf("Amount: %s\n", text_amount);
	printf("Address: %s\n", text_address);
	return 0; // success
}

void clearOutputsSeen(void)
{
}

#endif // #if defined(TEST) || defined(INTERFACE_STUBS)

#ifdef TEST

static const uint8_t test_tx1[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0x01, 0x00, 0x00, 0x00, // number in previous output
0x19, // script length
0x76, // OP_DUP
0xA9, // OP_HASH160
0x14, // 20 bytes of data follows
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, 0x00, 0x00,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, 0x00, 0x00,
0x88, // OP_EQUALVERIFY
0xAC, // OP_CHECKSIG
0xFF, 0xFF, 0xFF, 0xFF, // sequence
0x02, // number of outputs
0x00, 0x46, 0xc3, 0x23, 0x00, 0x00, 0x00, 0x00, // 6 BTC
0x19, // script length
0x76, // OP_DUP
0xA9, // OP_HASH160
0x14, // 20 bytes of data follows
// 11MXTrefsj1ZS3Q5e9D6DxGzZKHWALyo9
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
0x88, // OP_EQUALVERIFY
0xAC, // OP_CHECKSIG
0x87, 0xd6, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, // 0.01234567 BTC
0x19, // script length
0x76, // OP_DUP
0xA9, // OP_HASH160
0x14, // 20 bytes of data follows
// 16eCeyy63xi5yde9VrX4XCcRrCKZwtUZK
0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
0x88, // OP_EQUALVERIFY
0xAC, // OP_CHECKSIG
0x00, 0x00, 0x00, 0x00, // locktime
0x01, 0x00, 0x00, 0x00 // hashtype
};

static const uint8_t private_key[] = {
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee};

static uint8_t *transaction_data;

uint8_t streamGetOneByte(uint8_t *one_byte)
{
	*one_byte = transaction_data[transaction_data_index];
	return 0; // success
}

int main(void)
{
	size_t length;
	uint8_t sig_hash[32];
	uint8_t transaction_hash[32];
	uint8_t signature[73];
	int i;

	srand(42);

	length = sizeof(test_tx1);
	transaction_data = malloc(length);
	memcpy(transaction_data, test_tx1, lwngth);
	printf("parseTransaction() returned: %d\n", (int)parseTransaction(sig_hash, transaction_hash, length));
	printf("Signature hash: ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", (int)sig_hash[i]);
	}
	printf("\n");
	printf("Transaction hash: ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", (int)transaction_hash[i]);
	}
	printf("\n");
	printf("signTransaction() returned: %d\n", (int)signTransaction(signature, sig_hash, (BigNum256)private_key));
	for (i = 0; i < 73; i++)
	{
		printf("%02x", (int)signature[i]);
	}

	exit(0);
}

#endif // #ifdef TEST

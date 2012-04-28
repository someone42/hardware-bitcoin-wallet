/** \file transaction.c
  *
  * \brief Contains functions specific to Bitcoin transactions.
  *
  * There are two main things which are dealt with in this file.
  * The first is the parsing of Bitcoin transactions. During the parsing
  * process, useful stuff (such as output addresses and amounts) is
  * extracted. See the code of parseTransactionInternal() for the guts.
  *
  * The second is the generation of Bitcoin-compatible signatures. Bitcoin
  * uses OpenSSL to generate signatures, and OpenSSL insists on encapsulating
  * the "r" and "s" values (see ecdsaSign()) in DER format. See the code of
  * signTransaction() for the guts.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#endif // #ifdef TEST

#ifdef TEST_TRANSACTION
#include "test_helpers.h"
#include "stream_comm.h"
#endif // #ifdef TEST_TRANSACTION

#include "common.h"
#include "endian.h"
#include "ecdsa.h"
#include "baseconv.h"
#include "sha256.h"
#include "bignum256.h"
#include "prandom.h"
#include "hwinterface.h"
#include "transaction.h"

/** The maximum size of a transaction (in bytes) which parseTransaction()
  * is prepared to handle. */
#define MAX_TRANSACTION_SIZE	200000

/** Where the transaction parser is within a transaction. 0 = first byte,
  * 1 = second byte etc. */
static uint32_t transaction_data_index;
/** The total length of the transaction being parsed, in number of bytes. */
static uint32_t transaction_length;
/** The number of inputs for the transaction being parsed. */
static uint16_t transaction_num_inputs;
/** If this is non-zero, then as the transaction contents are read from the
  * stream device, they will not be included in the calculation of the
  * transaction hash (see parseTransaction() for what this is all about).
  * If this is zero, then they will be included. */
static uint8_t suppress_transaction_hash;
/** If this is zero, then as the transaction contents are read from the
  * stream device, they will not be included in the calculation of the
  * transaction hash or the signature hash. If this is non-zero, then they
  * will be included. This is used to stop #sig_hash_hs_ptr
  * and #transaction_hash_hs_ptr from being written to if they don't point
  * to a valid hash state. */
static uint8_t hs_ptr_valid;
/** Pointer to hash state used to calculate the signature
  * hash (see parseTransaction() for what this is all about).
  * \warning If this does not point to a valid hash state structure, ensure
  *          that #hs_ptr_valid is set to zero to
  *          stop getTransactionBytes() from attempting to dereference this.
  */
static HashState *sig_hash_hs_ptr;
/** Pointer to hash state used to calculate the transaction
  * hash (see parseTransaction() for what this is all about).
  * \warning If this does not point to a valid hash state structure, ensure
  *          that #hs_ptr_valid is set to zero to
  *          stop getTransactionBytes() from attempting to dereference this.
  */
static HashState *transaction_hash_hs_ptr;

/** Get the number of inputs from the most recent transaction parsed by
  * parseTransaction().
  * \returns The number of inputs on success or 0 if there was an error
  *          obtaining the number of inputs.
  */
uint16_t getTransactionNumInputs(void)
{
	return transaction_num_inputs;
}

/** Get transaction data by reading from the stream device, checking that
  * the read operation won't go beyond the end of the transaction data.
  * 
  * Since all transaction data is read using this function, the updating
  * of #sig_hash_hs_ptr and #transaction_hash_hs_ptr is also done.
  * \param buffer An array of bytes which will be filled with the transaction
  *               data (if everything goes well). It must have space for
  *               length bytes.
  * \param length The number of bytes to read from the stream device.
  * \return 0 on success, 1 if a stream read error occurred or if the read
  *         would go beyond the end of the transaction data.
  */
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
			one_byte = streamGetOneByte();
			buffer[i] = one_byte;
			if (hs_ptr_valid)
			{
				sha256WriteByte(sig_hash_hs_ptr, one_byte);
				if (!suppress_transaction_hash)
				{
					sha256WriteByte(transaction_hash_hs_ptr, one_byte);
				}
			}
			transaction_data_index++;
		}
		return 0;
	}
}

/** Checks whether the transaction parser is at the end of the transaction
  * data.
  * \return 0 if not at the end of the transaction data, 1 if at the end of
  *         the transaction data.
  */
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

/** Parse a variable-sized integer within a transaction. Variable sized
  * integers are commonly used to represent counts or sizes in Bitcoin
  * transactions.
  * This only supports unsigned variable-sized integers up to a maximum
  * value of 2 ^ 32 - 1.
  * \param out The value of the integer will be written to here.
  * \return 0 on success, 1 to indicate an unexpected end of transaction
  *         data or 2 to indicate that the value of the integer is too large.
  */
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

/** See comments for parseTransaction() for description of what this does
  * and return values. However, the guts of the transaction parser are in
  * the code to this function.
  * \param sig_hash See parseTransaction().
  * \param transaction_hash See parseTransaction().
  * \param length See parseTransaction().
  * \return See parseTransaction().
  */
static TransactionErrors parseTransactionInternal(BigNum256 sig_hash, BigNum256 transaction_hash, uint32_t length)
{
	uint8_t temp[20];
	uint32_t num_inputs;
	uint8_t num_outputs;
	uint32_t script_length;
	uint16_t i;
	uint8_t j;
	uint32_t i32;
	char text_amount[TEXT_AMOUNT_LENGTH];
	char text_address[TEXT_ADDRESS_LENGTH];
	HashState sig_hash_hs;
	HashState transaction_hash_hs;

	transaction_num_inputs = 0;
	transaction_data_index = 0;
	transaction_length = length;
	if (length > MAX_TRANSACTION_SIZE)
	{
		return TRANSACTION_TOO_LARGE; // transaction too large
	}

	sig_hash_hs_ptr = &sig_hash_hs;
	transaction_hash_hs_ptr = &transaction_hash_hs;
	hs_ptr_valid = 1;
	sha256Begin(&sig_hash_hs);
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

/** Parse a Bitcoin transaction, extracting the output amounts/addresses,
  * validating the transaction (ensuring that it is "standard") and computing
  * a double SHA-256 hash of the transaction. This double SHA-256 hash is the
  * "signature hash" because it is the hash which is passed on to the signing
  * function signTransaction().
  *
  * The Bitcoin protocol for signing a transaction involves replacing
  * the corresponding input script with the output script that
  * the input references. This means that for a transaction with n
  * inputs, there will be n different signature hashes - one for each input.
  * Requiring the user to approve a transaction n times would be very
  * annoying, so there needs to be a way to determine whether a bunch of
  * transactions are actually "the same".
  * So in addition to the signature hash, a "transaction hash" will be
  * computed. The transaction hash is just like the signature hash, except
  * input scripts are not included. Also, the transaction hash is done using
  * a single SHA-256 hash instead of a double SHA-256 hash.
  *
  * \param sig_hash The signature hash will be written here (if everything
  *                 goes well), as a 32 byte little-endian multi-precision
  *                 number.
  * \param transaction_hash The transaction hash will be written here (if
  *                         everything goes well), as a 32 byte little-endian
  *                         multi-precision number.
  * \param length The total length of the transaction. If no stream read
  *               errors occured, then exactly length bytes will be read from
  *               the stream, even if the transaction was not parsed
  *               correctly.
  * \return One of the values in #TransactionErrorsEnum.
  */
TransactionErrors parseTransaction(BigNum256 sig_hash, BigNum256 transaction_hash, uint32_t length)
{
	TransactionErrors r;
	uint8_t junk;

	r = parseTransactionInternal(sig_hash, transaction_hash, length);
	hs_ptr_valid = 0;

	// Always try to consume the entire stream.
	while (!isEndOfTransactionData())
	{
		if (getTransactionBytes(&junk, 1))
		{
			break;
		}
	}
	return r;
}

/** Swap endian representation of a 256 bit integer.
  * \param buffer An array of 32 bytes representing the integer to change.
  */
void swapEndian256(BigNum256 buffer)
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

/**
 * \defgroup DEROffsets Offsets for DER signature encapsulation.
 *
 * @{
 */
/** Initial offset of r in signature. It's 4 because 4 bytes are needed for
  * the SEQUENCE/length and INTEGER/length bytes. */
#define R_OFFSET	4
/** Initial offset of s in signature. It's 39 because: r is initially 33
  * bytes long, and 2 bytes are needed for INTEGER/length. 4 + 33 + 2 = 39. */
#define S_OFFSET	39
/**@}*/

/** Sign a transaction. This should be called after the transaction is parsed
  * and a signature hash has been computed. The primary purpose of this
  * function is to call ecdsaSign() and encapsulate the ECDSA signature in
  * the DER format which OpenSSL uses.
  * \param signature The encapsulated signature will be written here. This
  *                  must be a byte array with space for
  *                  at least #MAX_SIGNATURE_LENGTH bytes.
  * \param sig_hash The signature hash of the transaction (see
  *                 parseTransaction()).
  * \param private_key The private key to sign the transaction with. This must
  *                    be a 32 byte little-endian multi-precision integer.
  * \return The length of the signature (including the hash type byte). This
  *         function cannot fail.
  */
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

#ifdef TEST

uint8_t newOutputSeen(char *text_amount, char *text_address)
{
	printf("Amount: %s\n", text_amount);
	printf("Address: %s\n", text_address);
	return 0; // success
}

void clearOutputsSeen(void)
{
}

#endif // #ifdef TEST

#ifdef TEST_TRANSACTION

/** A test transaction. */
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

/** Private key to sign test transaction with. */
static const uint8_t private_key[] = {
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee};

int main(void)
{
	size_t length;
	uint8_t sig_hash[32];
	uint8_t transaction_hash[32];
	uint8_t signature[MAX_SIGNATURE_LENGTH];

	initTests(__FILE__);

	length = sizeof(test_tx1);
	setTestInputStream(test_tx1, length);
	printf("parseTransaction() returned: %d\n", (int)parseTransaction(sig_hash, transaction_hash, (uint32_t)length));
	printf("Signature hash: ");
	printLittleEndian32(sig_hash);
	printf("\n");
	printf("Transaction hash: ");
	printLittleEndian32(transaction_hash);
	printf("\n");
	printf("signTransaction() returned: %d\n", (int)signTransaction(signature, sig_hash, (BigNum256)private_key));
	printf("Here's the signature: ");
	bigPrintVariableSize(signature, MAX_SIGNATURE_LENGTH, 1);
	printf("\n");

	finishTests();
	exit(0);
}

#endif // #ifdef TEST_TRANSACTION

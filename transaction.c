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
#include "wallet.h"
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
#define MAX_TRANSACTION_SIZE	400000
/** The maximum number of inputs that the transaction parser is prepared
  * to handle. This should be small enough that a transaction with the
  * maximum number of inputs is still less than #MAX_TRANSACTION_SIZE bytes in
  * size.
  * \warning This must be < 65536, otherwise an integer overflow may occur.
  */
#define MAX_INPUTS				5000
/** The maximum number of outputs that the transaction parser is prepared
  * to handle. This should be small enough that a transaction with the
  * maximum number of outputs is still less than #MAX_TRANSACTION_SIZE bytes
  * in size.
  * \warning This must be < 65536, otherwise an integer overflow may occur.
  */
#define MAX_OUTPUTS				2000

/** The maximum amount that can appear in an output, stored as a little-endian
  * multi-precision integer. This represents 21 million BTC. */
static const uint8_t max_money[] = {
0x00, 0x40, 0x07, 0x5A, 0xF0, 0x75, 0x07, 0x00};

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

	if (transaction_data_index > (0xffffffff - (uint32_t)length))
	{
		// transaction_data_index + (uint32_t)length will overflow.
		// Since transaction_length <= 0xffffffff, this implies that the read
		// will go past the end of the transaction.
		return 1; // trying to read past end of transaction
	}
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
	uint32_t num_outputs;
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
	if (readU32LittleEndian(temp) != 0x00000001)
	{
		return TRANSACTION_NON_STANDARD; // unsupported transaction version
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
	if (num_inputs > MAX_INPUTS)
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
		// Check sequence. Since locktime is checked below, this check
		// is probably superfluous. But it's better to be safe than sorry.
		if (getTransactionBytes(temp, 4))
		{
			return TRANSACTION_INVALID_FORMAT; // transaction truncated
		}
		if (readU32LittleEndian(temp) != 0xFFFFFFFF)
		{
			return TRANSACTION_NON_STANDARD; // replacement not supported
		}
	}

	// Get number of outputs.
	if (getVarInt(&num_outputs))
	{
		return TRANSACTION_INVALID_FORMAT; // transaction truncated or varint too big
	}
	if (num_outputs == 0)
	{
		return TRANSACTION_INVALID_FORMAT; // invalid transaction
	}
	if (num_outputs > MAX_OUTPUTS)
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
		if (bigCompareVariableSize(temp, (uint8_t *)max_money, 8) == BIGCMP_GREATER)
		{
			return TRANSACTION_INVALID_AMOUNT; // amount too high
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
	if (readU32LittleEndian(temp) != 0x00000000)
	{
		return TRANSACTION_NON_STANDARD; // replacement not supported
	}

	// Check hashtype.
	if (getTransactionBytes(temp, 4))
	{
		return TRANSACTION_INVALID_FORMAT; // transaction truncated
	}
	if (readU32LittleEndian(temp) != 0x00000001)
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

/** Encapsulate the ECDSA signature in the DER format which OpenSSL uses.
  * This function does not fail.
  * \param signature This must be a byte array with space for at
  *                  least #MAX_SIGNATURE_LENGTH bytes. On exit, the
  *                  encapsulated signature will be written here.
  * \param r The r value of the ECDSA signature. This should be a 32 byte
  *          little-endian multi-precision integer.
  * \param s The s value of the ECDSA signature. This should be a 32 byte
  *          little-endian multi-precision integer.
  * \return The length of the signature, in number of bytes.
  */
uint8_t encapsulateSignature(uint8_t *signature, BigNum256 r, BigNum256 s)
{
	uint8_t sequence_length;
	uint8_t i;

	memcpy(&(signature[R_OFFSET + 1]), r, 32);
	memcpy(&(signature[S_OFFSET + 1]), s, 32);
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

	// Integers in DER are big-endian.
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

/** Sign a transaction. This should be called after the transaction is parsed
  * and a signature hash has been computed. The primary purpose of this
  * function is to call ecdsaSign() and encapsulate the ECDSA signature in
  * the DER format which OpenSSL uses.
  * \param signature The encapsulated signature will be written here. This
  *                  must be a byte array with space for
  *                  at least #MAX_SIGNATURE_LENGTH bytes.
  * \param out_length The length of the signature, in number of bytes, will be
  *                   written here (on success). This length includes the hash
  *                   type byte.
  * \param sig_hash The signature hash of the transaction (see
  *                 parseTransaction()).
  * \param private_key The private key to sign the transaction with. This must
  *                    be a 32 byte little-endian multi-precision integer.
  * \return Zero on success, or non-zero if an error occurred while trying to
  *         obtain a random number.
  */
uint8_t signTransaction(uint8_t *signature, uint8_t *out_length, BigNum256 sig_hash, BigNum256 private_key)
{
	uint8_t k[32];
	uint8_t r[32];
	uint8_t s[32];

	*out_length = 0;
	do
	{
		if (getRandom256(k))
		{
			return 1; // problem with RNG system
		}
	} while (ecdsaSign(r, s, sig_hash, private_key, k));

	*out_length = encapsulateSignature(signature, r, s);
	return 0; // success
}

#ifdef TEST

/** Number of outputs seen. */
static int num_outputs_seen;

uint8_t newOutputSeen(char *text_amount, char *text_address)
{
	printf("Amount: %s\n", text_amount);
	printf("Address: %s\n", text_address);
	num_outputs_seen++;
	return 0; // success
}

void clearOutputsSeen(void)
{
	num_outputs_seen = 0;
}

#endif // #ifdef TEST

#ifdef TEST_TRANSACTION

/** A known good test transaction. This one was intercepted from the original
  * Bitcoin client during the signing of a live transaction. The input
  * references and addresses have been changed to protect privacy. */
static const uint8_t good_test_transaction[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
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

/** The known good test transaction, #good_test_transaction, with the inputs
  * removed. */
static const uint8_t inputs_removed_transaction[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
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

/** One input for a transaction. This was extracted
  * from #good_test_transaction. */
static const uint8_t one_input[] = {
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
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
};

/** One output for a transaction. This was extracted
  * from #good_test_transaction. */
static const uint8_t one_output[] = {
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // amount
0x19, // script length
0x76, // OP_DUP
0xA9, // OP_HASH160
0x14, // 20 bytes of data follows
// output address
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x88, // OP_EQUALVERIFY
0xAC, // OP_CHECKSIG
};

/** First output amount to use. */
static const uint8_t output_amount1[] = {
0x00, 0x46, 0xc3, 0x23, 0x00, 0x00, 0x00, 0x00 // 6 BTC
};

/** Second output amount to use. */
static const uint8_t output_amount2[] = {
0x87, 0xd6, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00 // 0.01234567 BTC
};

/** First output address to use. */
static const uint8_t output_address1[] = {
// 11MXTrefsj1ZS3Q5e9D6DxGzZKHWALyo9
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33
};

/** Second output address to use. */
static const uint8_t output_address2[] = {
// 16eCeyy63xi5yde9VrX4XCcRrCKZwtUZK
0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33
};

/** The known good test transaction, #good_test_transaction, with the input
  * script set to a blank (zero-length) script. */
static const uint8_t good_test_transaction_blank_script[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0x01, 0x00, 0x00, 0x00, // number in previous output
0x00, // script length
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

/** The known good test transaction, #good_test_transaction, with the outputs
  * removed. */
static const uint8_t outputs_removed_transaction[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
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
0x00, 0x00, 0x00, 0x00, // locktime
0x01, 0x00, 0x00, 0x00 // hashtype
};

/** The known good test transaction, #good_test_transaction, with an output
  * script set to a blank (zero-length) script. */
static const uint8_t good_test_transaction_blank_output_script[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
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
0x00, // script length
0x00, 0x00, 0x00, 0x00, // locktime
0x01, 0x00, 0x00, 0x00 // hashtype
};

/** The good test transaction, #good_test_transaction, with one output which
  * is non-standard. */
static const uint8_t non_standard1[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
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
0x01, // number of outputs
0x00, 0x46, 0xc3, 0x23, 0x00, 0x00, 0x00, 0x00, // 6 BTC
0x18, // script length
0x76, // OP_DUP
0xA9, // OP_HASH160
0x14, // 20 bytes of data follows
// 11MXTrefsj1ZS3Q5e9D6DxGzZKHWALyo9
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
0x88, // OP_EQUALVERIFY
0x00, 0x00, 0x00, 0x00, // locktime
0x01, 0x00, 0x00, 0x00 // hashtype
};

/** The good test transaction, #good_test_transaction, with one output which
  * is non-standard. */
static const uint8_t non_standard2[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
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
0x01, // number of outputs
0x00, 0x46, 0xc3, 0x23, 0x00, 0x00, 0x00, 0x00, // 6 BTC
0x18, // script length
0x76, // OP_DUP
0x14, // 20 bytes of data follows
// 11MXTrefsj1ZS3Q5e9D6DxGzZKHWALyo9
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
0x88, // OP_EQUALVERIFY
0xAC, // OP_CHECKSIG
0x00, 0x00, 0x00, 0x00, // locktime
0x01, 0x00, 0x00, 0x00 // hashtype
};

/** The good test transaction, #good_test_transaction, with one output which
  * is non-standard. */
static const uint8_t non_standard3[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
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
0x01, // number of outputs
0x00, 0x46, 0xc3, 0x23, 0x00, 0x00, 0x00, 0x00, // 6 BTC
0x18, // script length
0x76, // OP_DUP
0xA9, // OP_HASH160
0x13, // 19 bytes of data follows
0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
0x88, // OP_EQUALVERIFY
0xAC, // OP_CHECKSIG
0x00, 0x00, 0x00, 0x00, // locktime
0x01, 0x00, 0x00, 0x00 // hashtype
};

/** The good test transaction, #good_test_transaction, with one output which
  * is non-standard. */
static const uint8_t non_standard4[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
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
0x01, // number of outputs
0x00, 0x46, 0xc3, 0x23, 0x00, 0x00, 0x00, 0x00, // 6 BTC
0x1A, // script length
0x76, // OP_DUP
0xA9, // OP_HASH160
0x15, // 21 bytes of data follows
0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xff, 0xff,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
0x88, // OP_EQUALVERIFY
0xAC, // OP_CHECKSIG
0x00, 0x00, 0x00, 0x00, // locktime
0x01, 0x00, 0x00, 0x00 // hashtype
};

/** The good test transaction, #good_test_transaction, with one output which
  * is non-standard. */
static const uint8_t non_standard5[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
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
0x01, // number of outputs
0x00, 0x46, 0xc3, 0x23, 0x00, 0x00, 0x00, 0x00, // 6 BTC
0x19, // script length
0x76, // OP_DUP
0xAA, // OP_HASH256
0x14, // 20 bytes of data follows
// 11MXTrefsj1ZS3Q5e9D6DxGzZKHWALyo9
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
0x88, // OP_EQUALVERIFY
0xAC, // OP_CHECKSIG
0x00, 0x00, 0x00, 0x00, // locktime
0x01, 0x00, 0x00, 0x00 // hashtype
};

/** The good test transaction, #good_test_transaction, with one output which
  * is non-standard. */
static const uint8_t non_standard6[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
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
0x01, // number of outputs
0x00, 0x46, 0xc3, 0x23, 0x00, 0x00, 0x00, 0x00, // 6 BTC
0x19, // script length
0x76, // OP_DUP
0xA9, // OP_HASH160
0x14, // 20 bytes of data follows
// 11MXTrefsj1ZS3Q5e9D6DxGzZKHWALyo9
0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33,
0x87, // OP_EQUAL
0xAC, // OP_CHECKSIG
0x00, 0x00, 0x00, 0x00, // locktime
0x01, 0x00, 0x00, 0x00 // hashtype
};

/** The good test transaction, #good_test_transaction, with one output which
  * is non-standard. */
static const uint8_t non_standard7[] = {
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0x00, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee, // previous output
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
0x01, // number of outputs
0x00, 0x46, 0xc3, 0x23, 0x00, 0x00, 0x00, 0x00, // 6 BTC
0x19, // script length
// OP_CHECKSIG spam
0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC,
0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC,
0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC, 0xAC,
0x00, 0x00, 0x00, 0x00, // locktime
0x01, 0x00, 0x00, 0x00 // hashtype
};

/** Private key to sign test transaction with. */
static const uint8_t private_key[] = {
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee};

/** Stores one test case for encapsulateSignature(). */
struct EncapsulateSignatureTestStruct
{
	uint8_t r[32];
	uint8_t s[32];
	uint8_t expected_length;
	uint8_t expected_signature[MAX_SIGNATURE_LENGTH];
};

/** These test cases were constructed manually. */
const struct EncapsulateSignatureTestStruct encapsulate_tests[] = {
{ // All zeroes for r and s. This produces a minimum length signature.
{ // r
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
{ // s
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
9, // expected_length
// expected_signature
{0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01}},

{ // r and s < 128. This produces a minimum length signature.
{ // r
0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
{ // s
0x7f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
9, // expected_length
// expected_signature
{0x30, 0x06, 0x02, 0x01, 0x7f, 0x02, 0x01, 0x7f, 0x01}},

{ // r is 1, s is 0.
{ // r
0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
{ // s
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
9, // expected_length
// expected_signature
{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x01}},

{ // r is 0x80, s is 0. This tests zero-padding of r.
{ // r
0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
{ // s
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
10, // expected_length
// expected_signature
{0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x00, 0x01}},

{ // r is 0, s is 0xff. This tests zero-padding of s.
{ // r
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
{ // s
0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
10, // expected_length
// expected_signature
{0x30, 0x07, 0x02, 0x01, 0x00, 0x02, 0x02, 0x00, 0xff, 0x01}},

{ // r is 0, s is 2 ^ 256 - 1. This tests whether the leading zero is kept.
{ // r
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
{ // s
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
41, // expected_length
// expected_signature
{0x30, 0x26, 0x02, 0x01, 0x00, 0x02, 0x21, 0x00,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},

{ // Both r and s are 2 ^ 256 - 1. This results in a maximum length signature.
{ // r
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
{ // s
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
73, // expected_length
// expected_signature
{0x30, 0x46, 0x02, 0x21, 0x00,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0x02, 0x21, 0x00,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},

{ // r is 2 ^ 256 - 1, s is 2 ^ 255 - 1. s shouldn't have a leading zero.
{ // r
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
{ // s
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
72, // expected_length
// expected_signature
{0x30, 0x45, 0x02, 0x21, 0x00,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0x02, 0x20,
0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},

{ // r is 2 ^ 255 - 1, s is 2 ^ 256 - 1. r shouldn't have a leading zero.
{ // r
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
{ // s
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
72, // expected_length
// expected_signature
{0x30, 0x45, 0x02, 0x20,
0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0x02, 0x21, 0x00,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},

{ // Both r and s are 2 ^ 255 - 1. Both shouldn't have a leading zero.
{ // r
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
{ // s
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
71, // expected_length
// expected_signature
{0x30, 0x44, 0x02, 0x20,
0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0x02, 0x20,
0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},

{ // Both r and s are between 0 and 2 ^ 255 - 1. This tests zero removal.
{ // r
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0x12, 0x00, 0x00},
{ // s
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00},
66, // expected_length
// expected_signature
{0x30, 0x3f, 0x02, 0x1e,
0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0x02, 0x1d,
0x00, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}},

{ // r and s are swapped compared to previous test.
{ // r
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00},
{ // s
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0x12, 0x00, 0x00},
66, // expected_length
// expected_signature
{0x30, 0x3f, 0x02, 0x1d,
0x00, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0x02, 0x1e,
0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}}
};

/** Generate a test transaction with the specified number of inputs and
  * outputs.
  * The structure of transactions was obtained from
  * https://en.bitcoin.it/wiki/Protocol_specification on 11-June-2012.
  * \param out_length The length of the generated transaction will be written
  *                   here.
  * \param num_inputs The number of inputs to include in the transaction.
  * \param num_outputs The number of outputs to include in the transaction.
  * \return A pointer to a byte array containing the transaction data. This
  *         array must eventually be freed by the caller.
  */
static uint8_t *generateTestTransaction(uint32_t *out_length, uint32_t num_inputs, uint32_t num_outputs)
{
	uint8_t *buffer;
	uint32_t ptr;
	uint32_t i;
	size_t malloc_size;
	uint8_t temp[20];
	int j;

	malloc_size = num_inputs * sizeof(one_input);
	malloc_size += num_outputs * sizeof(one_output);
	malloc_size += sizeof(good_test_transaction);
	malloc_size += 100; // just to be sure
	buffer = malloc(malloc_size);
	ptr = 0;
	// Write version.
	writeU32LittleEndian(&(buffer[ptr]), 0x00000001);
	ptr += 4;
	// Write number of inputs.
	if (num_inputs < 0xfd)
	{
		buffer[ptr] = (uint8_t)num_inputs;
		ptr++;
	}
	else if (num_inputs <= 0xffff)
	{
		buffer[ptr] = 0xfd;
		ptr++;
		buffer[ptr] = (uint8_t)num_inputs;
		ptr++;
		buffer[ptr] = (uint8_t)(num_inputs >> 8);
		ptr++;
	}
	else
	{
		buffer[ptr] = 0xfe;
		ptr++;
		writeU32LittleEndian(&(buffer[ptr]), num_inputs);
		ptr += 4;
	}
	// Write inputs.
	for (i = 0; i < num_inputs; i++)
	{
		memcpy(&(buffer[ptr]), one_input, sizeof(one_input));
		ptr += sizeof(one_input);
	}
	// Write number of outputs.
	if (num_outputs < 0xfd)
	{
		buffer[ptr] = (uint8_t)num_outputs;
		ptr++;
	}
	else if (num_outputs <= 0xffff)
	{
		buffer[ptr] = 0xfd;
		ptr++;
		buffer[ptr] = (uint8_t)num_outputs;
		ptr++;
		buffer[ptr] = (uint8_t)(num_outputs >> 8);
		ptr++;
	}
	else
	{
		buffer[ptr] = 0xfe;
		ptr++;
		writeU32LittleEndian(&(buffer[ptr]), num_outputs);
		ptr += 4;
	}
	// Write outputs.
	for (i = 0; i < num_outputs; i++)
	{
		memcpy(&(buffer[ptr]), one_output, sizeof(one_output));
		if (i == 0)
		{
			memcpy(&(buffer[ptr]), output_amount1, sizeof(output_amount1));
			memcpy(&(buffer[ptr + 12]), output_address1, sizeof(output_address1));
		}
		else if (i == 1)
		{
			memcpy(&(buffer[ptr]), output_amount2, sizeof(output_amount2));
			memcpy(&(buffer[ptr + 12]), output_address2, sizeof(output_address2));
		}
		else
		{
			// Use random amount/address.
			for (j = 0; j < 6; j++)
			{
				temp[j] = (uint8_t)(rand() & 0xff);
			}
			temp[6] = 0; // make sure it's < 21000000 BTC
			temp[7] = 0;
			memcpy(&(buffer[ptr]), temp, 8);
			for (j = 0; j < 20; j++)
			{
				temp[j] = (uint8_t)(rand() & 0xff);
			}
			memcpy(&(buffer[ptr + 12]), temp, 20);
		}
		ptr += sizeof(one_output);
	}
	// Write locktime.
	writeU32LittleEndian(&(buffer[ptr]), 0x00000000);
	ptr += 4;
	// Write hashtype.
	writeU32LittleEndian(&(buffer[ptr]), 0x00000001);
	ptr += 4;
	*out_length = ptr;
	return buffer;
}

/** Check that the number of outputs seen is as expected.
  * \param target The expected number of outputs.
  */
static void checkOutputsSeen(int target)
{
	if (num_outputs_seen != target)
	{
		printf("Expected to see %d outputs, got %d\n", target, num_outputs_seen);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
}

/** Set the input stream to some transaction data and attempt to parse that
  * transaction.
  * \param buffer The test transaction data. If this is NULL, the input stream
  *               will be set to an infinite stream of zeroes.
  * \param length The length of the transaction, in number of bytes.
  * \param name The test name of the transaction. This is displayed on stdout
  *             if a test fails.
  * \param expected_return The expected return value of parseTransaction().
  */
static void testTransaction(const uint8_t *buffer, uint32_t length, const char *name, TransactionErrors expected_return)
{
	uint8_t sig_hash[32];
	uint8_t transaction_hash[32];
	TransactionErrors r;

	clearOutputsSeen();
	if (buffer == NULL)
	{
		setInfiniteZeroInputStream();
	}
	else
	{
		setTestInputStream(buffer, length);
	}
	r = parseTransaction(sig_hash, transaction_hash, length);
	// Check return value is what is expected.
	if (r != expected_return)
	{
		printf("parseTransaction() returned unexpected value for transaction \"%s\"\n", name);
		printf("Expected: %d, got: %d\n", (int)expected_return, (int)r);
		reportFailure();
	}
	else
	{
		// Then check if all bytes in the transaction were consumed.
		if (!isEndOfTransactionData())
		{
			printf("parseTransaction() didn't eat everything for transaction \"%s\"\n", name);
			reportFailure();
		}
		else
		{
			// Then check that there was no attempt to read past the end of
			// the transaction.
			if (transaction_data_index > transaction_length)
			{
				printf("parseTransaction() read past end for transaction \"%s\"\n", name);
				reportFailure();
			}
			else
			{
				reportSuccess();
			}
		}
	} // end if (r != expected_return)
}

int main(void)
{
	int i;
	int j;
	int abort;
	int abort_error;
	int abort_no_write;
	int num_tests;
	char name[1024];
	uint8_t bad_test_transaction[sizeof(good_test_transaction)];
	uint8_t *generated_transaction;
	uint32_t length;
	uint8_t sig_hash[32];
	uint8_t transaction_hash[32];
	uint8_t calculated_sig_hash[32];
	uint8_t calculated_transaction_hash[32];
	uint8_t sig_hash_input_changed[32];
	uint8_t transaction_hash_input_changed[32];
	uint8_t sig_hash_output_changed[32];
	uint8_t transaction_hash_output_changed[32];
	uint8_t signature[MAX_SIGNATURE_LENGTH];
	uint8_t signature_length;
	uint8_t *signatures_buffer;
	uint8_t *signatures_length;
	HashState test_hs;

	initTests(__FILE__);

	initWalletTest();
	initialiseDefaultEntropyPool();

	// Test the transaction parser on some transactions which have invalid
	// lengths.
	testTransaction(good_test_transaction, 0, "blank", TRANSACTION_INVALID_FORMAT);
	testTransaction(NULL, MAX_TRANSACTION_SIZE + 1, "toobig", TRANSACTION_TOO_LARGE);
	// length = 0xffffffff left to end.

	// Test the transaction parser on a known good transaction.
	testTransaction(good_test_transaction, sizeof(good_test_transaction), "good", TRANSACTION_NO_ERROR);

	// Truncate the good transaction and check that the transaction parser
	// doesn't choke.
	for (i = 1; i < sizeof(good_test_transaction); i++)
	{
		sprintf(name, "truncate%d", i);
		testTransaction(good_test_transaction, (uint32_t)i, name, TRANSACTION_INVALID_FORMAT);
	}

	// Corrupt the version field.
	memcpy(bad_test_transaction, good_test_transaction, sizeof(good_test_transaction));
	writeU32LittleEndian(bad_test_transaction, 0x00000000); // version
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "badversion", TRANSACTION_NON_STANDARD);
	writeU32LittleEndian(bad_test_transaction, 0xFFFFFFFF); // version
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "badversion2", TRANSACTION_NON_STANDARD);
	writeU32LittleEndian(bad_test_transaction, 0x00000002); // version
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "badversion3", TRANSACTION_NON_STANDARD);

	// Say that there are inputs, but don't actually include the inputs.
	testTransaction(inputs_removed_transaction, sizeof(inputs_removed_transaction), "noinputs", TRANSACTION_INVALID_FORMAT);
	memcpy(bad_test_transaction, inputs_removed_transaction, sizeof(inputs_removed_transaction));
	bad_test_transaction[4] = 0xfc; // number of inputs
	testTransaction(bad_test_transaction, sizeof(inputs_removed_transaction), "noinputs2", TRANSACTION_INVALID_FORMAT);

	// A sanity check: since generateTestTransaction() uses data derived
	// from good_test_transaction, using generateTestTransaction() with
	// num_inputs set to 1 should return a transaction identical to
	// good_test_transaction.
	generated_transaction = generateTestTransaction(&length, 1, 2);
	if (memcmp(generated_transaction, good_test_transaction, length))
	{
		printf("generateTestTransaction() sanity check failed\n");
		exit(1);
	}
	free(generated_transaction);

	// Include the wrong number of inputs.
	generated_transaction = generateTestTransaction(&length, 2, 2);
	generated_transaction[4] = 0x03; // number of inputs (too many)
	testTransaction(generated_transaction, length, "wronginputs", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 7, 2);
	generated_transaction[4] = 0x02; // number of inputs (too few)
	testTransaction(generated_transaction, length, "wronginputs2", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);

	// Include no inputs.
	generated_transaction = generateTestTransaction(&length, 0, 2);
	testTransaction(generated_transaction, length, "noinputs", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);

	// The transaction parser should successfully parse transactions with up
	// to MAX_INPUTS inputs.
	generated_transaction = generateTestTransaction(&length, 1, 2);
	testTransaction(generated_transaction, length, "1input", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 2, 2);
	testTransaction(generated_transaction, length, "2inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	// Try numbers close to varint boundaries...
	generated_transaction = generateTestTransaction(&length, 0xfb, 2);
	testTransaction(generated_transaction, length, "251inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 0xfc, 2);
	testTransaction(generated_transaction, length, "252inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 0xfd, 2);
	testTransaction(generated_transaction, length, "253inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 0xfe, 2);
	testTransaction(generated_transaction, length, "254inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 0xff, 2);
	testTransaction(generated_transaction, length, "255inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 0x100, 2);
	testTransaction(generated_transaction, length, "256inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 0x101, 2);
	testTransaction(generated_transaction, length, "257inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 0x102, 2);
	testTransaction(generated_transaction, length, "258inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, MAX_INPUTS - 2, 2);
	testTransaction(generated_transaction, length, "MAX-2inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, MAX_INPUTS - 1, 2);
	testTransaction(generated_transaction, length, "MAX-1inputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, MAX_INPUTS, 2);
	testTransaction(generated_transaction, length, "MAXinputs", TRANSACTION_NO_ERROR);
	free(generated_transaction);

	// The transaction parser should reject transactions with too many inputs.
	generated_transaction = generateTestTransaction(&length, MAX_INPUTS + 1, 2);
	testTransaction(generated_transaction, length, "MAX+2inputs", TRANSACTION_TOO_MANY_INPUTS);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, MAX_INPUTS + 2, 2);
	testTransaction(generated_transaction, length, "MAX+2inputs", TRANSACTION_TOO_MANY_INPUTS);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 10, 2);
	generated_transaction[4] = 0xfe;
	writeU32LittleEndian(&(generated_transaction[5]), 0xffffffff); // number of inputs
	testTransaction(generated_transaction, length, "stupidinputs", TRANSACTION_TOO_MANY_INPUTS);
	free(generated_transaction);

	// Technically, a blank script is a valid script. The transaction parser
	// doesn't care what the input script is, so it should accept blank
	// scripts.
	testTransaction(good_test_transaction_blank_script, sizeof(good_test_transaction_blank_script), "blankscript", TRANSACTION_NO_ERROR);

	// Corrupt the sequence field.
	memcpy(bad_test_transaction, good_test_transaction, sizeof(good_test_transaction));
	writeU32LittleEndian(&(bad_test_transaction[67]), 0x00000000); // sequence
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "badsequence", TRANSACTION_NON_STANDARD);
	writeU32LittleEndian(&(bad_test_transaction[67]), 0xFFFFFFFE); // sequence
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "badsequence2", TRANSACTION_NON_STANDARD);

	// Say that there are outputs, but don't actually include the outputs.
	testTransaction(outputs_removed_transaction, sizeof(outputs_removed_transaction), "nooutputs", TRANSACTION_INVALID_FORMAT);
	memcpy(bad_test_transaction, outputs_removed_transaction, sizeof(outputs_removed_transaction));
	bad_test_transaction[71] = 0xfc; // number of outputs
	testTransaction(bad_test_transaction, sizeof(outputs_removed_transaction), "nooutputs2", TRANSACTION_INVALID_FORMAT);

	// Include the wrong number of outputs.
	generated_transaction = generateTestTransaction(&length, 1, 2);
	generated_transaction[71] = 0x03; // number of outputs (too many)
	testTransaction(generated_transaction, length, "wrongoutputs", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 1, 9);
	generated_transaction[71] = 0x01; // number of outputs (too few)
	// The transaction parser will return TRANSACTION_NON_STANDARD because it
	// interprets the first 4 bytes of one of the outputs as locktime. Those
	// bytes won't be 0x00000000, so it will think the transaction is non
	// standard.
	testTransaction(generated_transaction, length, "wrongoutputs2", TRANSACTION_NON_STANDARD);
	free(generated_transaction);

	// Include no outputs.
	generated_transaction = generateTestTransaction(&length, 1, 0);
	testTransaction(generated_transaction, length, "nooutputs", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);

	// The transaction parser should successfully parse transactions with up
	// to MAX_OUTPUTS outputs.
	generated_transaction = generateTestTransaction(&length, 1, 1);
	testTransaction(generated_transaction, length, "1output", TRANSACTION_NO_ERROR);
	checkOutputsSeen(1);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 1, 2);
	testTransaction(generated_transaction, length, "2outputs", TRANSACTION_NO_ERROR);
	checkOutputsSeen(2);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 1, 3);
	testTransaction(generated_transaction, length, "3outputs", TRANSACTION_NO_ERROR);
	checkOutputsSeen(3);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS - 2);
	testTransaction(generated_transaction, length, "MAX-2outputs", TRANSACTION_NO_ERROR);
	checkOutputsSeen(MAX_OUTPUTS - 2);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS - 1);
	testTransaction(generated_transaction, length, "MAX-1outputs", TRANSACTION_NO_ERROR);
	checkOutputsSeen(MAX_OUTPUTS - 1);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS);
	testTransaction(generated_transaction, length, "MAXoutputs", TRANSACTION_NO_ERROR);
	checkOutputsSeen(MAX_OUTPUTS);
	free(generated_transaction);

	// The transaction parser should reject transactions with more than
	// MAX_OUTPUTS outputs.
	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS + 1);
	testTransaction(generated_transaction, length, "MAX+1output", TRANSACTION_TOO_MANY_OUTPUTS);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS + 2);
	testTransaction(generated_transaction, length, "MAX+2outputs", TRANSACTION_TOO_MANY_OUTPUTS);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 1, MAX_OUTPUTS + 3);
	testTransaction(generated_transaction, length, "MAX+3outputs", TRANSACTION_TOO_MANY_OUTPUTS);
	free(generated_transaction);
	generated_transaction = generateTestTransaction(&length, 1, 20);
	generated_transaction[71] = 0xfe;
	writeU32LittleEndian(&(generated_transaction[72]), 0xffffffff); // number of outputs
	testTransaction(generated_transaction, length, "stupidoutputs", TRANSACTION_TOO_MANY_OUTPUTS);
	free(generated_transaction);

	// Try number of outputs = 2 ^ 64 - 1, just to screw with the varint
	// reader.
	generated_transaction = generateTestTransaction(&length, 1, 20);
	generated_transaction[71] = 0xff;
	writeU32LittleEndian(&(generated_transaction[72]), 0xffffffff); // number of outputs
	writeU32LittleEndian(&(generated_transaction[76]), 0xffffffff); // number of outputs
	// The transaction parser returns TRANSACTION_INVALID_FORMAT because
	// the varint reader can't read uint64_t.
	testTransaction(generated_transaction, length, "stupideroutputs", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);

	// The transaction parser does care about output scripts, so it should
	// reject a blank output script as non-standard.
	testTransaction(good_test_transaction_blank_output_script, sizeof(good_test_transaction_blank_output_script), "blankoutput", TRANSACTION_NON_STANDARD);

	// Check that the transaction parser recognises (and rejects) non standard
	// transactions.
	testTransaction(non_standard1, sizeof(non_standard1), "non_standard1", TRANSACTION_NON_STANDARD);
	testTransaction(non_standard2, sizeof(non_standard2), "non_standard2", TRANSACTION_NON_STANDARD);
	testTransaction(non_standard3, sizeof(non_standard3), "non_standard3", TRANSACTION_NON_STANDARD);
	testTransaction(non_standard4, sizeof(non_standard4), "non_standard4", TRANSACTION_NON_STANDARD);
	testTransaction(non_standard5, sizeof(non_standard5), "non_standard5", TRANSACTION_NON_STANDARD);
	testTransaction(non_standard6, sizeof(non_standard6), "non_standard6", TRANSACTION_NON_STANDARD);
	testTransaction(non_standard7, sizeof(non_standard7), "non_standard7", TRANSACTION_NON_STANDARD);

	// Try some output amounts near and above max_money.
	memcpy(bad_test_transaction, good_test_transaction, sizeof(good_test_transaction));
	writeU32LittleEndian(&(bad_test_transaction[72]), 0x5A073FFF); // amount (least significant)
	writeU32LittleEndian(&(bad_test_transaction[76]), 0x000775F0); // amount (most significant)
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "maxmoney-1", TRANSACTION_NO_ERROR);
	writeU32LittleEndian(&(bad_test_transaction[72]), 0x5A074000); // amount (least significant)
	writeU32LittleEndian(&(bad_test_transaction[76]), 0x000775F0); // amount (most significant)
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "maxmoney", TRANSACTION_NO_ERROR);
	writeU32LittleEndian(&(bad_test_transaction[72]), 0x5A074001); // amount (least significant)
	writeU32LittleEndian(&(bad_test_transaction[76]), 0x000775F0); // amount (most significant)
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "maxmoney+1", TRANSACTION_INVALID_AMOUNT);
	writeU32LittleEndian(&(bad_test_transaction[72]), 0x5A074000); // amount (least significant)
	writeU32LittleEndian(&(bad_test_transaction[76]), 0x000775F1); // amount (most significant)
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "biggermoney", TRANSACTION_INVALID_AMOUNT);
	writeU32LittleEndian(&(bad_test_transaction[72]), 0xFFFFFFFF); // amount (least significant)
	writeU32LittleEndian(&(bad_test_transaction[76]), 0xFFFFFFFF); // amount (most significant)
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "biggestmoney", TRANSACTION_INVALID_AMOUNT);

	// Corrupt the locktime field.
	memcpy(bad_test_transaction, good_test_transaction, sizeof(good_test_transaction));
	writeU32LittleEndian(&(bad_test_transaction[140]), 0x00000001); // locktime
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "badlocktime", TRANSACTION_NON_STANDARD);
	writeU32LittleEndian(&(bad_test_transaction[140]), 0xFFFFFFFF); // locktime
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "badlocktime2", TRANSACTION_NON_STANDARD);

	// Corrupt the hashtype field.
	memcpy(bad_test_transaction, good_test_transaction, sizeof(good_test_transaction));
	writeU32LittleEndian(&(bad_test_transaction[144]), 0x00000000); // hashtype
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "badhashtype", TRANSACTION_NON_STANDARD);
	writeU32LittleEndian(&(bad_test_transaction[144]), 0xFFFFFFFF); // hashtype
	testTransaction(bad_test_transaction, sizeof(good_test_transaction), "badhashtype2", TRANSACTION_NON_STANDARD);

	// Add junk data to the end of a good transaction.
	length = sizeof(good_test_transaction) + 1;
	generated_transaction = malloc(length);
	memcpy(generated_transaction, good_test_transaction, sizeof(good_test_transaction));
	generated_transaction[sizeof(good_test_transaction)] = 0xca;
	testTransaction(generated_transaction, length, "junkatend", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);
	length = sizeof(good_test_transaction) + 65537;
	generated_transaction = malloc(length);
	memcpy(generated_transaction, good_test_transaction, sizeof(good_test_transaction));
	memset(&(generated_transaction[sizeof(good_test_transaction)]), 3, 65537);
	testTransaction(generated_transaction, length, "junkatend2", TRANSACTION_INVALID_FORMAT);
	free(generated_transaction);

	// Check that the signature hash is a double SHA-256 hash of the
	// transaction. This doesn't test if the signature hash is Bitcoin
	// compatible. The easiest way to check if the signature hash is Bitcoin
	// compatible is to sign a transaction and see if other nodes relay it.
	setTestInputStream(good_test_transaction, sizeof(good_test_transaction));
	parseTransaction(sig_hash, transaction_hash, sizeof(good_test_transaction));
	sha256Begin(&test_hs);
	for (i = 0; i < sizeof(good_test_transaction); i++)
	{
		sha256WriteByte(&test_hs, good_test_transaction[i]);
	}
	sha256FinishDouble(&test_hs);
	writeHashToByteArray(calculated_sig_hash, &test_hs, 0);
	if (memcmp(calculated_sig_hash, sig_hash, 32))
	{
		printf("parseTransaction() isn't calculating signature hash properly\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that the transaction hash is a single SHA-256 of the transaction,
	// ignoring input scripts.
	sha256Begin(&test_hs);
	for (i = 0; i < sizeof(good_test_transaction); i++)
	{
		if (i == 41)
		{
			i += 26; // skip input script
		}
		sha256WriteByte(&test_hs, good_test_transaction[i]);
	}
	sha256Finish(&test_hs);
	writeHashToByteArray(calculated_transaction_hash, &test_hs, 0);
	if (memcmp(calculated_transaction_hash, transaction_hash, 32))
	{
		printf("parseTransaction() isn't calculating transaction hash properly\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Now change one byte in the input script. The signature hash should
	// change, but the transaction hash should not.
	memcpy(bad_test_transaction, good_test_transaction, sizeof(good_test_transaction));
	bad_test_transaction[42] = 0x04; // first byte of input script
	setTestInputStream(bad_test_transaction, sizeof(good_test_transaction));
	parseTransaction(sig_hash_input_changed, transaction_hash_input_changed, sizeof(good_test_transaction));
	if (!memcmp(sig_hash_input_changed, sig_hash, 32))
	{
		printf("Signature hash doesn't change when input script changes\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	if (memcmp(transaction_hash_input_changed, transaction_hash, 32))
	{
		printf("Transaction hash changes when input script changes\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// As a sanity check, change one byte in an output script. Both the
	// signature and transaction hashes should change.
	memcpy(bad_test_transaction, good_test_transaction, sizeof(good_test_transaction));
	bad_test_transaction[103] = 0x00; // last byte of output address
	setTestInputStream(bad_test_transaction, sizeof(good_test_transaction));
	parseTransaction(sig_hash_output_changed, transaction_hash_output_changed, sizeof(good_test_transaction));
	if (!memcmp(sig_hash_output_changed, sig_hash, 32))
	{
		printf("Signature hash doesn't change when output script changes\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	if (!memcmp(transaction_hash_output_changed, transaction_hash, 32))
	{
		printf("Transaction hash doesn't change when output script changes\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that the transaction parser doesn't choke on a transaction
	// with the maximum possible size. This test takes a while.
	testTransaction(NULL, 0xffffffff, "max_size", TRANSACTION_TOO_LARGE);

	// Go through encapsulateSignature() tests.
	num_tests = sizeof(encapsulate_tests) / sizeof(struct EncapsulateSignatureTestStruct);
	for (i = 0; i < num_tests; i++)
	{
		signature_length = encapsulateSignature(signature, (uint8_t *)(encapsulate_tests[i].r), (uint8_t *)(encapsulate_tests[i].s));
		if (signature_length != encapsulate_tests[i].expected_length)
		{
			printf("Signature length mismatch on encapsulateSignature() test %d\n", i);
			reportFailure();
		}
		else
		{
			if (memcmp(signature, encapsulate_tests[i].expected_signature, signature_length))
			{
				printf("Signature contents mismatch on encapsulateSignature() test %d\n", i);
				reportFailure();
			}
			else
			{
				reportSuccess();
			}
		}
	}

	// Call signTransaction() a couple of times and make sure signatures don't
	// repeat. A repeating signature would indicate that signTransaction()
	// isn't using a different k for each signature.
	signatures_buffer = calloc(10, MAX_SIGNATURE_LENGTH);
	signatures_length = calloc(10, 1);
	abort = 0;
	abort_error = 0;
	abort_no_write = 0;
	for (i = 0; i < 10; i++)
	{
		memset(sig_hash, 42, 32);
		if (signTransaction(&(signatures_buffer[i * MAX_SIGNATURE_LENGTH]),
			&(signatures_length[i]),
			sig_hash,
			(BigNum256)private_key))
		{
			printf("signTransaction() failed unexpectedly\n");
			reportFailure();
			abort_error = 1;
			break;
		}
		// Check that signTransaction() wrote to the signature buffer and
		// signature length arrays.
		if ((signatures_buffer[i * MAX_SIGNATURE_LENGTH] != 0x30)
			|| (signatures_length[i] == 0))
		{
			printf("signTransaction() isn't writing to its outputs\n");
			reportFailure();
			abort_no_write = 1;
			break;
		}
		for (j = 0; j < i; j++)
		{
			if (signatures_length[i] == signatures_length[j])
			{
				if (!memcmp(&(signatures_buffer[i * MAX_SIGNATURE_LENGTH]),
					&(signatures_buffer[j * MAX_SIGNATURE_LENGTH]),
					signatures_length[i]))
				{
					printf("signTransaction() is producing repeating signatures\n");
					reportFailure();
					abort = 1;
					break;
				}
			}
		}
		if (abort)
		{
			break;
		}
	} // end for (i = 0; i < 10; i++)
	if (!abort)
	{
		reportSuccess();
	}
	if (!abort_error)
	{
		reportSuccess();
	}
	if (!abort_no_write)
	{
		reportSuccess();
	}
	free(signatures_buffer);
	free(signatures_length);

	// Disable the random number generator and make sure that
	// signTransaction() fails.
	corruptEntropyPool();
	if (!signTransaction(signature, &signature_length, sig_hash, (BigNum256)private_key))
	{
		printf("signTransaction() doesn't recognise when RNG is disabled\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	initialiseDefaultEntropyPool(); // restore RNG for further tests

	finishTests();
	exit(0);
}

#endif // #ifdef TEST_TRANSACTION

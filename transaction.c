// ***********************************************************************
// transaction.c
// ***********************************************************************
//
// Containes functions specific to BitCoin transactions.
//
// This file is licensed as described by the file LICENCE.

// Defining this will facilitate testing
//#define TEST
// Defining this will provide useless stubs for interface functions, to stop
// linker errors from occuring
//#define INTERFACE_STUBS

// The maximum size of a transaction (in bytes) which parse_transaction()
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

static u32 transaction_data_index;
static u32 transaction_length;
static u16 transaction_num_inputs;
static u8 read_error_occurred;
static u8 suppress_txhash;
static u8 suppress_bothhash;
static hash_state sighash_hs;
static hash_state txhash_hs;

// Returns the number of inputs from the most recent transaction parsed by
// parse_transaction. Returns 0 if there was an error obtaining the number
// of inputs.
u16 get_transaction_num_inputs(void)
{
	return transaction_num_inputs;
}

// Returns 0 on success and fills buffer with length bytes,
// otherwise returns 1 to indicate an unexpected end of transaction data.
static u8 get_tx_bytes(u8 *buffer, u8 length)
{
	u8 i;
	u8 onebyte;

	if (transaction_data_index + (u32)length > transaction_length)
	{
		return 1; // trying to read past end of transaction
	}
	else
	{
		for (i = 0; i < length; i++)
		{
			if (stream_get_one_byte(&onebyte) != 0)
			{
				read_error_occurred = 1;
				return 1; // error while trying to get byte from stream
			}
			buffer[i] = onebyte;
			if (suppress_bothhash == 0)
			{
				sha256_writebyte(&sighash_hs, onebyte);
				if (suppress_txhash == 0)
				{
					sha256_writebyte(&txhash_hs, onebyte);
				}
			}
			transaction_data_index++;
		}
		return 0;
	}
}

// Returns 0 if not at end of transaction data, otherwise returns 1.
static u8 is_end_of_transaction_data(void)
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
static u8 getvarint(u32 *out)
{
	u8 temp[4];

	if (get_tx_bytes(temp, 1) != 0)
	{
		return 1; // unexpected end of transaction data
	}
	if (temp[0] < 0xfd)
	{
		*out = temp[0];
	}
	else if (temp[0] == 0xfd)
	{
		if (get_tx_bytes(temp, 2) != 0)
		{
			return 1; // unexpected end of transaction data
		}
		*out = (u32)(temp[0]) | ((u32)(temp[1]) << 8);
	}
	else if (temp[0] == 0xfe)
	{
		if (get_tx_bytes(temp, 4) != 0)
		{
			return 1; // unexpected end of transaction data
		}
		*out = read_u32_littleendian(temp);
	}
	else
	{
		return 2; // varint is too large
	}
	return 0;
}

// See comments for parse_transaction() for description of what this does
// and return values.
static tx_errors parse_transaction_internal(u32 length, bignum256 sighash, bignum256 txhash)
{
	u8 temp[20];
	u32 numinputs;
	u8 numoutputs;
	u32 scriptlength;
	u16 i;
	u8 j;
	u32 i32;
	char textamount[22];
	char textaddress[36];

	transaction_num_inputs = 0;
	read_error_occurred = 0;
	transaction_data_index = 0;
	transaction_length = length;
	if (length > MAX_TRANSACTION_SIZE)
	{
		return TX_TOO_LARGE; // transaction too large
	}

	sha256_begin(&sighash_hs);
	suppress_bothhash = 0;
	sha256_begin(&txhash_hs);
	suppress_txhash = 0;

	// version
	if (get_tx_bytes(temp, 4) != 0)
	{
		return TX_INVALID_FORMAT; // transaction truncated
	}
	if ((temp[0] != 0x01) || (temp[1] != 0x00)
		|| (temp[2] != 0x00) || (temp[3] != 0x00))
	{
		return TX_INVALID_FORMAT; // unsupported transaction version
	}

	// number of inputs
	if (getvarint(&numinputs) != 0)
	{
		return TX_INVALID_FORMAT; // transaction truncated or varint too big
	}
	if (numinputs == 0)
	{
		return TX_INVALID_FORMAT; // invalid transaction
	}
	if (numinputs >= 0xffff)
	{
		return TX_TOO_MANY_INPUTS; // too many inputs
	}
	transaction_num_inputs = (u16)numinputs;

	// process each input
	for (i = 0; i < numinputs; i++)
	{
		suppress_txhash = 1;
		// skip transaction reference (hash and output number)
		for (j = 0; j < 9; j++)
		{
			if (get_tx_bytes(temp, 4) != 0)
			{
				return TX_INVALID_FORMAT; // transaction truncated
			}
		}
		// input script length
		if (getvarint(&scriptlength) != 0)
		{
			return TX_INVALID_FORMAT; // transaction truncated or varint too big
		}
		// skip the script
		for (i32 = 0; i32 < scriptlength; i32++)
		{
			if (get_tx_bytes(temp, 1) != 0)
			{
				return TX_INVALID_FORMAT; // transaction truncated
			}
		}
		suppress_txhash = 0;
		// skip sequence
		if (get_tx_bytes(temp, 4) != 0)
		{
			return TX_INVALID_FORMAT; // transaction truncated
		}
	}

	// number of outputs
	if (get_tx_bytes(&numoutputs, 1) != 0)
	{
		return TX_INVALID_FORMAT; // transaction truncated
	}
	if (numoutputs == 0)
	{
		return TX_INVALID_FORMAT; // invalid transaction
	}
	if (numoutputs >= 0xfd)
	{
		return TX_TOO_MANY_OUTPUTS; // too many outputs
	}

	// process each output
	for (i = 0; i < numoutputs; i++)
	{
		// amount
		if (get_tx_bytes(temp, 8) != 0)
		{
			return TX_INVALID_FORMAT; // transaction truncated
		}
		amount_to_text(textamount, temp);
		// output script length
		if (getvarint(&scriptlength) != 0)
		{
			return TX_INVALID_FORMAT; // transaction truncated or varint too big
		}
		if (scriptlength != 0x19)
		{
			return TX_NONSTANDARD; // nonstandard transaction
		}
		// look for: OP_DUP, OP_HASH160, (20 bytes of data)
		if (get_tx_bytes(temp, 3) != 0)
		{
			return TX_INVALID_FORMAT; // transaction truncated
		}
		if ((temp[0] != 0x76) || (temp[1] != 0xa9) || (temp[2] != 0x14))
		{
			return TX_NONSTANDARD; // nonstandard transaction
		}
		if (get_tx_bytes(temp, 20) != 0)
		{
			return TX_INVALID_FORMAT; // transaction truncated
		}
		hash_to_addr(textaddress, temp);
		// look for: OP_EQUALVERIFY OP_CHECKSIG
		if (get_tx_bytes(temp, 2) != 0)
		{
			return TX_INVALID_FORMAT; // transaction truncated
		}
		if ((temp[0] != 0x88) || (temp[1] != 0xac))
		{
			return TX_NONSTANDARD; // nonstandard transaction
		}
		if (new_output_seen(textamount, textaddress) != 0)
		{
			return TX_TOO_MANY_OUTPUTS; // too many outputs
		}
	}

	// locktime
	if (get_tx_bytes(temp, 4) != 0)
	{
		return TX_INVALID_FORMAT; // transaction truncated
	}
	if ((temp[0] != 0x00) || (temp[1] != 0x00)
		|| (temp[2] != 0x00) || (temp[3] != 0x00))
	{
		return TX_NONSTANDARD; // nonstandard transaction
	}

	// hashtype
	if (get_tx_bytes(temp, 4) != 0)
	{
		return TX_INVALID_FORMAT; // transaction truncated
	}
	if ((temp[0] != 0x01) || (temp[1] != 0x00)
		|| (temp[2] != 0x00) || (temp[3] != 0x00))
	{
		return TX_NONSTANDARD; // nonstandard transaction
	}

	if (is_end_of_transaction_data() == 0)
	{
		return TX_INVALID_FORMAT; // junk at end of transaction data
	}

	sha256_finishdouble(&sighash_hs);
	sha256_finish(&txhash_hs);
	convertHtobytearray(&sighash_hs, sighash, 0);
	convertHtobytearray(&txhash_hs, txhash, 0);

	return 0;
}

// Parse a BitCoin transaction, extracting the output amounts/addresses,
// validating the transaction (ensuring that it is "standard") and computing
// a double SHA-256 hash of the transaction. length should be the total length
// of the transaction data stream. If no read errors occur, then exactly
// length bytes should be read from the stream, even if the transaction is
// not parsed correctly. Upon success, the double SHA-256 hash will be written
// out to sighash (which should be a byte array which can hold 32 bytes) in
// little-endian format.
// In addition to sighash ("signature hash"), a transaction hash will be
// computed and written out to txhash in little-endian format. The transaction
// hash is just like the signature hash, except input references and scripts
// are not included. The transaction hash can be used to determine if (when
// signing a transaction with multiple inputs) a bunch of transactions are
// "the same".
// Returns one of the values in tx_errors.
// This will always read the number of bytes specified by length from the
// input stream, even in the case of an invalid transaction.
tx_errors parse_transaction(u32 length, bignum256 sighash, bignum256 txhash)
{
	tx_errors r;
	u8 junk;

	r = parse_transaction_internal(length, sighash, txhash);
	if (read_error_occurred == 0)
	{
		// Always try to consume the entire stream.
		suppress_bothhash = 1;
		while (is_end_of_transaction_data() == 0)
		{
			if (get_tx_bytes(&junk, 1) != 0)
			{
				break;
			}
		}
	}
	else
	{
		// Read errors are more fundamental (in terms of cause and effect)
		// than other errors.
		return TX_READ_ERROR;
	}
	return r;
}

// Swap endian representation of a 256-bit integer.
void swap_endian256(u8 *buffer)
{
	u8 i;
	u8 temp;

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

// Sign the transaction with the (signature) hash specified by sighash, using
// the private key specified by privatekey. Both sighash and privatekey are
// little-endian 256-bit numbers. The resulting signature will be written
// out to signature in DER format, with the hash type appended. signature must
// have space for at least 73 bytes.
// The return value is the length of the signature (including the
// hash type byte).
u8 sign_transaction(u8 *signature, bignum256 sighash, bignum256 privatekey)
{
	u8 k[32];
	u8 sequencelength;
	u8 i;

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
		get_random_256(k);
	} while (ecdsa_sign(
		(bignum256)(&(signature[R_OFFSET + 1])),
		(bignum256)(&(signature[S_OFFSET + 1])),
		sighash,
		privatekey,
		k) == 0);
	swap_endian256(&(signature[R_OFFSET + 1]));
	swap_endian256(&(signature[S_OFFSET + 1]));

	sequencelength = 0x46; // 2 + 33 + 2 + 33
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
		sequencelength--;
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
		sequencelength--;
		signature[R_OFFSET - 1]--;
		if (signature[R_OFFSET - 1] == 1)
		{
			break;
		}
	}

	signature[0] = 0x30; // SEQUENCE
	signature[1] = sequencelength; // length of SEQUENCE
	// 3 extra bytes: SEQUENCE/length and hashtype
	return (u8)(sequencelength + 3);
}

#if defined(TEST) || defined(INTERFACE_STUBS)

u8 new_output_seen(char *textamount, char *textaddress)
{
	printf("Amount: %s\n", textamount);
	printf("Address: %s\n", textaddress);
	return 0; // success
}

void clear_outputs_seen(void)
{
}

#endif // #if defined(TEST) || defined(INTERFACE_STUBS)

#ifdef TEST

static const u8 test_tx1[] = {
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

static const u8 privatekey[] = {
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee,
0xde, 0xad, 0xbe, 0xef, 0xc0, 0xff, 0xee, 0xee};

static u8 *transaction_data;

u8 stream_get_one_byte(u8 *onebyte)
{
	*onebyte = transaction_data[transaction_data_index];
	return 0; // success
}

int main(int argc, char **argv)
{
	size_t txsize;
	u8 sighash[32];
	u8 txhash[32];
	u8 signature[73];
	int i;

	// Reference argc and argv just to make certain compilers happy.
	if (argc == 2)
	{
		printf("%s\n", argv[1]);
	}

	srand(42);

	txsize = sizeof(test_tx1);
	transaction_data = malloc(txsize);
	memcpy(transaction_data, test_tx1, txsize);
	printf("parse_transaction() returned: %d\n", (int)parse_transaction(txsize, sighash, txhash));
	printf("Signature hash: ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", (int)sighash[i]);
	}
	printf("\n");
	printf("Transaction hash: ");
	for (i = 0; i < 32; i++)
	{
		printf("%02x", (int)txhash[i]);
	}
	printf("\n");
	printf("sign_transaction() returned: %d\n", (int)sign_transaction(signature, sighash, (bignum256)privatekey));
	for (i = 0; i < 73; i++)
	{
		printf("%02x", (int)signature[i]);
	}

	exit(0);
}

#endif // #ifdef TEST

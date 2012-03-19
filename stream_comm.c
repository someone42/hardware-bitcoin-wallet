// ***********************************************************************
// stream_comm.c
// ***********************************************************************
//
// Handles point-to-point communication over a stream device.
//
// This file is licensed as described by the file LICENCE.

// Defining this will facilitate testing
//#define TEST
// Defining this will provide useless stubs for interface functions, to stop
// linker errors from occuring
//#define INTERFACE_STUBS

#include "common.h"
#include "endian.h"
#include "hwinterface.h"
#include "wallet.h"
#include "bignum256.h"
#include "stream_comm.h"
#include "prandom.h"
#include "xex.h"
#include "ecdsa.h"

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#endif // #ifdef TEST

// Because stdlib.h might not be included, NULL might be undefined. NULL
// is only used as a placeholder pointer for translate_wallet_error() if
// there is no appropriate pointer.
#ifndef NULL
#define NULL ((void *)0) 
#endif // #ifndef NULL

// The transaction hash of the most recently approved transaction. This is
// stored so that if a transaction needs to be signed multiple times (eg.
// if it has more than one input), the user doesn't have to confirm every one.
static u8 prev_txhash[32];
// 0 means disregard prev_tx_hash, non-zero means that prev_tx_hash is valid
// for prev_tx_hash more transactions (eg. if prev_tx_hash is 2, then
// prev_txhash can be considered valid for the approval of 2 more
// transactions).
static u16 prev_txhash_valid;

// Length of current packet's payload.
static u32 payload_length;

// Write a number of bytes to the output stream. Returns 0 on success,
// non-zero on failure.
static u8 write_bytes(u8 *buffer, u16 length)
{
	u16 i;

	for (i = 0; i < length; i++)
	{
		if (stream_put_one_byte(buffer[i]))
		{
			return 1; // write error
		}
	}
	return 0;
}

// Sends a packet with a device string as payload. spec specifies the device
// string to send and command specifies the command of the packet.
// This returns 0 on success or non-zero if there was a write error.
static u8 put_string(string_set set, u8 spec, u8 command)
{
	u8 buffer[5];
	u16 length;
	u16 i;

	buffer[0] = command;
	length = get_string_length(set, spec);
	write_u32_littleendian(&(buffer[1]), length);
	if (write_bytes(buffer, 5))
	{
		return 1; // write error
	}
	for (i = 0; i < length; i++)
	{
		if (stream_put_one_byte((u8)get_string(set, spec, i)))
		{
			return 1; // write error
		}
	}
	return 0;
}

// Translates a return value from one of the wallet functions into a response
// packet to be sent to the output stream. If the return value indicates
// success, a payload (specified by length and data) can be included with the
// packet. Otherwise, if the return value indicates failure, the payload is
// a (text) error message.
// This returns 0 on success or non-zero if there was a write error.
static u8 translate_wallet_error(wallet_errors r, u8 length, u8 *data)
{
	u8 buffer[5];

	if (r == WALLET_NO_ERROR)
	{
		buffer[0] = 0x02;
		write_u32_littleendian(&(buffer[1]), length);
		if (write_bytes(buffer, 5))
		{
			return 1; // write error
		}
		if (write_bytes(data, length))
		{
			return 1; // write error
		}
	}
	else
	{
		return put_string(STRINGSET_WALLET, (u8)r, 0x03);
	}

	return 0;
}

// Read a number (specified by length) of bytes from the input stream
// and place those bytes into a buffer. Returns 0 on success, non-zero on
// failure.
static u8 read_bytes(u8 *buffer, u8 length)
{
	u8 i;

	for (i = 0; i < length; i++)
	{
		if (stream_get_one_byte(&(buffer[i])))
		{
			return 1; // read error
		}
	}
	payload_length -= length;
	return 0;
}

// Format non-volatile storage, erasing its contents and replacing it with
// random data.
// This returns 0 on success or non-zero if there was a write error.
u8 format_storage(void)
{
	if (translate_wallet_error(sanitise_nv_storage(0, 0xffffffff), 0, NULL))
	{
		return 1; // write error
	}

	init_wallet(); // force wallet to unload
	return 0;
}

// Sign the transaction with hash given by sighash with the private key
// associated with the address handle ah. If the signing process was
// successful, the signature is also sent as a success packet.
// This has the same return values as check_and_sign_by_address().
static NOINLINE u8 sign_transaction_by_ah(address_handle ah, u8 *sighash)
{
	u8 signature[73];
	u8 privkey[32];
	u8 signature_length;

	signature_length = 0;
	if (get_privkey(privkey, ah) == WALLET_NO_ERROR)
	{
		// Note: sign_transaction() cannot fail.
		signature_length = sign_transaction(signature, sighash, privkey);
	}
	if (translate_wallet_error (wallet_get_last_error(), signature_length, signature))
	{
		return 1; // write error
	}
	return 0;
}

// Read the transaction from the input stream, parse it and ask the user
// if they accept it. A non-zero value will be written to *out_confirmed if
// the user accepted it, otherwise a zero value will be written.
// This has the same return values as check_and_sign_by_address().
static NOINLINE u8 parse_and_ask_transaction(u8 *out_confirmed, u8 *sighash, u32 txlength)
{
	u8 confirmed;
	u8 i;
	tx_errors r;
	u8 txhash[32];

	// Validate transaction and calculate hashes of it.
	*out_confirmed = 0;
	clear_outputs_seen();
	r = parse_transaction(sighash, txhash, txlength);
	if (r == TX_READ_ERROR)
	{
		return 2; // read error
	}
	if (r != TX_NO_ERROR)
	{
		if (put_string(STRINGSET_TRANSACTION, (u8)r, 0x03))
		{
			return 1; // write error
		}
		else
		{
			return 0;
		}
	}

	// Get permission from user.
	confirmed = 0;
	// Does txhash match previous confirmed transaction?
	if (prev_txhash_valid)
	{
		if (bigcmp(txhash, prev_txhash) == BIGCMP_EQUAL)
		{
			confirmed = 1;
			prev_txhash_valid--;
		}
	}
	if (!confirmed)
	{
		// Need to explicitly get permission from user.
		// The call to parse_transaction should have logged all the outputs
		// to the user interface.
		if (ask_user(ASKUSER_SIGN_TRANSACTION))
		{
			if (put_string(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, 0x03))
			{
				return 1; // write error
			}
		}
		else
		{
			confirmed = 1;
			for (i = 0; i < 32; i++)
			{
				prev_txhash[i] = txhash[i];
			}
			// The transaction hash can only be reused another
			// (number of inputs) - 1 times. This is to prevent an exploit
			// where an attacker crafts a lot of copies (with differing inputs
			// but identical outputs) of a genuine transaction. With unlimited
			// reuse of the transaction hash, acceptance of the original
			// genuine transaction would also allow all the copies to be
			// automatically accepted, causing the user to spend more than
			// they intended.
			prev_txhash_valid = get_transaction_num_inputs();
			if (prev_txhash_valid)
			{
				prev_txhash_valid--;
			}
		}
	}

	*out_confirmed = confirmed;
	return 0;
}

// Validate and sign a transaction, given the address handle specified by
// ah and a transaction length specified by txlength. The signature or any
// error messages will be sent to the output stream.
// This will return 0 on success, 1 if a write error occurred or 2 if a read
// error occurred. "Success" here is defined as "no read or write errors
// occurred"; 0 will be returned even if the transaction was rejected.
// This function will always consume txlength bytes from the input stream,
// except when a read error occurs.
static NOINLINE u8 check_and_sign_by_ah(address_handle ah, u32 txlength)
{
	u8 confirmed;
	u8 r;
	u8 sighash[32];

	r = parse_and_ask_transaction(&confirmed, sighash, txlength);
	if (r)
	{
		return r;
	}

	if (confirmed)
	{
		// Okay to sign transaction.
		r = sign_transaction_by_ah(ah, sighash);
		if (r)
		{
			return r;
		}
	}

	return 0;
}

// Send a packet containing an address and its corresponding public key.
// If generate_new is non-zero, a new address will be generated. If
// generate_new is zero, the address handle will be read from the input
// stream.
// If generate_new is non-zero, the address handle of the generated
// address is also prepended to the output packet.
// Returns 1 if a read or write error occurred, otherwise returns 0.
static NOINLINE u8 get_and_send_address_and_pubkey(u8 generate_new)
{
	address_handle ah;
	point_affine pubkey;
	u8 address[20];
	u8 buffer[5];
	wallet_errors r;

	if (generate_new)
	{
		// Generate new address handle.
		r = WALLET_NO_ERROR;
		ah = make_new_address(address, &pubkey);
		if (ah == BAD_ADDRESS_HANDLE)
		{
			r = wallet_get_last_error();
		}
	}
	else
	{
		// Read address handle from input stream.
		if (read_bytes(buffer, 4))
		{
			return 1; // read error
		}
		ah = read_u32_littleendian(buffer);
		r = get_address_and_pubkey(address, &pubkey, ah);
	}

	if (r == WALLET_NO_ERROR)
	{
		buffer[0] = 0x02;
		if (generate_new)
		{
			// 4 (address handle) + 20 (address) + 65 (public key)
			write_u32_littleendian(&(buffer[1]), 89);
		}
		else
		{
			// 20 (address) + 65 (public key)
			write_u32_littleendian(&(buffer[1]), 85);
		}
		if (write_bytes(buffer, 5))
		{
			return 1; // write error
		}
		if (generate_new)
		{
			write_u32_littleendian(buffer, ah);
			if (write_bytes(buffer, 4))
			{
				return 1; // write error
			}
		}
		if (write_bytes(address, 20))
		{
			return 1; // write error
		}
		buffer[0] = 0x04;
		if (write_bytes(buffer, 1))
		{
			return 1; // write error
		}
		if (write_bytes(pubkey.x, 32))
		{
			return 1; // write error
		}
		if (write_bytes(pubkey.y, 32))
		{
			return 1; // write error
		}
	}
	else
	{
		if (translate_wallet_error (r, 0, NULL))
		{
			return 1; // write error
		}
	} // end if (r == WALLET_NO_ERROR)

	return 0;
}

// Read but ignore payload_length bytes from input stream.
// Returns 0 on success, non-zero if there was a read error.
static u8 read_and_ignore_input(void)
{
	u8 junk;

	if (payload_length)
	{
		for (; payload_length--; )
		{
			if (stream_get_one_byte(&junk))
			{
				return 1; // read error
			}
		}
	}
	return 0;
}

// All I/O errors returned by expect_length are >= EXPECT_LENGTH_IO_ERROR.
#define EXPECT_LENGTH_IO_ERROR		42

// Expect payload length to be equal to desired_length, and send an error
// message (and read but ignore payload_length bytes from input stream) if
// that is the case. Returns:
// 0 for success,
// 1 for length != desired_length.
// EXPECT_LENGTH_IO_ERROR for read error,
// EXPECT_LENGTH_IO_ERROR + 1 for write error,
static u8 expect_length(const u8 desired_length)
{
	if (payload_length != desired_length)
	{
		if (read_and_ignore_input())
		{
			return EXPECT_LENGTH_IO_ERROR; // read error
		}
		if (put_string(STRINGSET_MISC, MISCSTR_INVALID_PACKET, 0x03))
		{
			return EXPECT_LENGTH_IO_ERROR + 1; // write error
		}
		return 1; // mismatched length
	}
	else
	{
		return 0;
	}
}

// This must be called on device startup.
void init_stream_comm(void)
{
	prev_txhash_valid = 0;
}

// Get packet from stream and deal with it. Returns 0 if the packet was
// received successfully, non-zero if an error occurred. 0 will still
// be returned if a command failed; here, "an error" means a problem
// reading/writing from/to the stream.
u8 process_packet(void)
{
	u8 command;
	u8 buffer[40];
	u8 i;
	u8 r;
	address_handle ah;

	if (stream_get_one_byte(&command))
	{
		return 1; // read error
	}
	if (read_bytes(buffer, 4))
	{
		return 1; // read error
	}
	payload_length = read_u32_littleendian(buffer);

	// Checklist for each case:
	// 1. Have you checked or dealt with length?
	// 2. Have you fully read the input stream before writing (to avoid
	//    deadlocks)?
	// 3. Have you dealt with read and write errors?
	// 4. Have you asked permission from the user (for potentially dangerous
	//    operations)?
	// 5. Have you checked for errors from wallet functions?
	// 6. Have you used the right check for the wallet functions?

	switch (command)
	{

	case 0x00:
		// Ping request.
		// Just throw away the data and then send response.
		if (read_and_ignore_input())
		{
			return 1; // read error
		}
		if (put_string(STRINGSET_MISC, MISCSTR_VERSION, 0x01))
		{
			return 1; // write error
		}
		break;

	// Commands 0x01, 0x02 and 0x03 should never be received; they are only
	// sent.

	case 0x04:
		// Create new wallet.
		r = expect_length(72);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (read_bytes(buffer, 32))
			{
				return 1; // read error
			}
			set_encryption_key(buffer);
			set_tweak_key(&(buffer[16]));
			if (read_bytes(buffer, 40))
			{
				return 1; // read error
			}
			if (ask_user(ASKUSER_NUKE_WALLET))
			{
				if (put_string(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, 0x03))
				{
					return 1; // write error
				}
			}
			else
			{
				if (translate_wallet_error (new_wallet(buffer), 0, NULL))
				{
					return 1; // write error
				}
			}
		} // if (!r)
		break;

	case 0x05:
		// Create new address in wallet.
		r = expect_length(0);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (ask_user(ASKUSER_NEW_ADDRESS))
			{
				if (put_string(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, 0x03))
				{
					return 1; // write error
				}
			}
			else
			{
				if (get_and_send_address_and_pubkey(1))
				{
					return 1; // read or write error
				}
			}
		} // if (!r)
		break;

	case 0x06:
		// Get number of addresses in wallet.
		r = expect_length(0);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			write_u32_littleendian(buffer, get_num_addresses());
			if (translate_wallet_error(wallet_get_last_error(), 4, buffer))
			{
				return 1; // write error
			}
		} // if (!r)
		break;

	case 0x09:
		// Get public key corresponding to an address handle.
		r = expect_length(4);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (get_and_send_address_and_pubkey(0))
			{
				return 1; // read or write error
			}
		} // if (!r)
		break;

	case 0x0a:
		// Sign a transaction.
		if (payload_length <= 4)
		{
			if (read_and_ignore_input())
			{
				return 1; // read error
			}
			if (put_string(STRINGSET_MISC, MISCSTR_INVALID_PACKET, 0x03))
			{
				return 1; // write error
			}
		}
		else
		{
			if (read_bytes(buffer, 4))
			{
				return 1; // read error
			}
			ah = read_u32_littleendian(buffer);
			// Don't need to subtract 4 off payload_length because read_bytes
			// has already done so.
			if (check_and_sign_by_ah(ah, payload_length))
			{
				return 1; // read or write error
			}
			payload_length = 0;
		}
		break;

	case 0x0b:
		// Load wallet.
		r = expect_length(32);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (read_bytes(buffer, 32))
			{
				return 1; // read error
			}
			set_encryption_key(buffer);
			set_tweak_key(&(buffer[16]));
			if (translate_wallet_error (init_wallet(), 0, NULL))
			{
				return 1; // write error
			}
		} // if (!r)
		break;

	case 0x0c:
		// Unload wallet.
		r = expect_length(0);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			volatile u8 *buffer_alias;
			clear_keys();
			sanitise_ram();
			buffer_alias = buffer;
			for (i = 0; i < 32; i++)
			{
				buffer_alias[i] = 0xff;
			}
			for (i = 0; i < 32; i++)
			{
				buffer_alias[i] = 0x0;
			}
			if (translate_wallet_error (uninit_wallet(), 0, NULL))
			{
				return 1; // write error
			}
		} // if (!r)
		break;

	case 0x0d:
		// Format storage.
		r = expect_length(0);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (ask_user(ASKUSER_FORMAT))
			{
				if (put_string(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, 0x03))
				{
					return 1; // write error
				}
			}
			else
			{
				if (format_storage())
				{
					return 1; // write error
				}
			}
		} // if (!r)
		break;

	case 0x0e:
		// Change wallet encryption key.
		r = expect_length(32);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (read_bytes(buffer, 32))
			{
				return 1; // read error
			}
			if (translate_wallet_error (change_encryption_key(buffer), 0, NULL))
			{
				return 1; // write error
			}
		} // if (!r)
		break;

	default:
		// Unknown command.
		if (read_and_ignore_input())
		{
			return 1; // read error
		}
		if (put_string(STRINGSET_MISC, MISCSTR_INVALID_PACKET, 0x03))
		{
			return 1; // write error
		}
		break;

	}

#ifdef TEST
	assert(payload_length == 0);
#endif

	return 0;
}

#ifdef INTERFACE_STUBS

u8 stream_get_one_byte(u8 *onebyte)
{
	*onebyte = 0;
	return 0; // success
}

u8 stream_put_one_byte(u8 onebyte)
{
	// Reference onebyte to make certain compilers happy
	if (onebyte > 1000)
	{
		return 1;
	}
	return 0; // success
}

u16 get_string_length(string_set set, u8 spec)
{
	// Reference set and spec to make certain compilers happy
	if (set == spec)
	{
		return 1;
	}
	return 0;
}

char get_string(string_set set, u8 spec, u16 pos)
{
	// Reference set, spec and pos to make certain compilers happy
	if ((pos == set) && (set == spec))
	{
		return 32;
	}
	return 0;
}

u8 ask_user(askuser_command command)
{
	// Reference command to make certain compilers happy
	if (command == 99)
	{
		return 1;
	}
	return 0;
}

#endif // #ifdef INTERFACE_STUBS

#ifdef TEST

static u8 *stream;
static int stream_ptr;
static int stream_length;

// Sets input stream (what will be read by stream_get_one_byte()) to the
// contents of a buffer.
static void set_input_stream(const u8 *buffer, int length)
{
	if (stream != NULL)
	{
		free(stream);
	}
	stream = malloc(length);
	memcpy(stream, buffer, length);
	stream_length = length;
	stream_ptr = 0;
}

// Get one byte from the contents of the buffer set by set_input_stream().
u8 stream_get_one_byte(u8 *onebyte)
{
	if (stream_ptr >= stream_length)
	{
		return 1; // end of stream
	}
	*onebyte = stream[stream_ptr++];
	return 0; // success
}

u8 stream_put_one_byte(u8 onebyte)
{
	printf(" %02x", (int)onebyte);
	return 0; // success
}

static const char *get_string_internal(string_set set, u8 spec)
{
	if (set == STRINGSET_MISC)
	{
		switch (spec)
		{
		case MISCSTR_VERSION:
			return "Hello world v0.1";
			break;
		case MISCSTR_PERMISSION_DENIED:
			return "Permission denied by user";
			break;
		case MISCSTR_INVALID_PACKET:
			return "Unrecognised command";
			break;
		default:
			assert(0);
			return NULL;
		}
	}
	else if (set == STRINGSET_WALLET)
	{
		switch (spec)
		{
		case WALLET_FULL:
			return "Wallet has run out of space";
			break;
		case WALLET_EMPTY:
			return "Wallet has nothing in it";
			break;
		case WALLET_READ_ERROR:
			return "Read error";
			break;
		case WALLET_WRITE_ERROR:
			return "Write error";
			break;
		case WALLET_ADDRESS_NOT_FOUND:
			return "Address not in wallet";
			break;
		case WALLET_NOT_THERE:
			return "Wallet doesn't exist";
			break;
		case WALLET_END_OF_LIST:
			return "End of address list";
			break;
		case WALLET_INVALID_HANDLE:
			return "Invalid address handle";
			break;
		default:
			assert(0);
			return NULL;
		}
	}
	else if (set == STRINGSET_TRANSACTION)
	{
		switch (spec)
		{
		case TX_INVALID_FORMAT:
			return "Format of transaction is unknown or invalid";
			break;
		case TX_TOO_MANY_INPUTS:
			return "Too many inputs in transaction";
			break;
		case TX_TOO_MANY_OUTPUTS:
			return "Too many outputs in transaction";
			break;
		case TX_TOO_LARGE:
			return "Transaction's size is too large";
			break;
		case TX_NONSTANDARD:
			return "Transaction is non-standard";
			break;
		default:
			assert(0);
			return NULL;
		}
	}
	else
	{
		assert(0);
		return NULL;
	}
}

u16 get_string_length(string_set set, u8 spec)
{
	return (u16)strlen(get_string_internal(set, spec));
}

char get_string(string_set set, u8 spec, u16 pos)
{
	assert(pos < get_string_length(set, spec));
	return get_string_internal(set, spec)[pos];
}

u8 ask_user(askuser_command command)
{
	int c;

	switch (command)
	{
	case ASKUSER_NUKE_WALLET:
		printf("Nuke your wallet and start a new one? ");
		break;
	case ASKUSER_NEW_ADDRESS:
		printf("Create new address? ");
		break;
	case ASKUSER_SIGN_TRANSACTION:
		printf("Sign transaction? ");
		break;
	case ASKUSER_FORMAT:
		printf("Format storage area? ");
		break;
	default:
		assert(0);
		return 1;
	}
	printf("y/[n]: ");
	do
	{
		c = getchar();
	} while ((c == '\n') || (c == '\r'));
	if ((c == 'y') || (c == 'Y'))
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

// Create new wallet
static const u8 test_stream_new_wallet[] = {
0x04, 0x48, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x20,
0x66, 0x66, 0x20, 0x20, 0x20, 0x6F, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};

// Create new address
static const u8 test_stream_new_address[] = {
0x05, 0x00, 0x00, 0x00, 0x00};

// Get number of addresses
static const u8 test_stream_get_num_addresses[] = {
0x06, 0x00, 0x00, 0x00, 0x00};

// Get address 1
static const u8 test_stream_get_address1[] = {
0x09, 0x04, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00};

// Get address 0 (which is an invalid address handle)
static const u8 test_stream_get_address0[] = {
0x09, 0x04, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00};

// Sign something
static u8 test_stream_sign_tx[] = {
0x0a, 0x98, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00,
// transaction data is below
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

// Format storage
static const u8 test_stream_format[] = {
0x0d, 0x00, 0x00, 0x00, 0x00};

// Load wallet using correct key
static const u8 test_stream_load_correct[] = {
0x0b, 0x20, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Load wallet using incorrect key
static const u8 test_stream_load_incorrect[] = {
0x0b, 0x20, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Unload wallet
static const u8 test_stream_unload[] = {
0x0c, 0x00, 0x00, 0x00, 0x00};

// Change encryption key
static const u8 test_stream_change_key[] = {
0x0e, 0x20, 0x00, 0x00, 0x00,
0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Load with new encryption key
static const u8 test_stream_load_with_changed_key[] = {
0x0b, 0x20, 0x00, 0x00, 0x00,
0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static void send_one_test_stream(const u8 *test_stream, int size)
{
	int r;

	set_input_stream(test_stream, size);
	r = process_packet();
	printf("\n");
	printf("process_packet() returned: %d\n", r);
}

int main(int argc, char **argv)
{
	int i;

	// Reference argc and argv just to make certain compilers happy.
	if (argc == 2)
	{
		printf("%s\n", argv[1]);
	}

	wallet_test_init();
	init_wallet();

	printf("Creating new wallet...\n");
	send_one_test_stream(test_stream_new_wallet, sizeof(test_stream_new_wallet));
	for(i = 0; i < 4; i++)
	{
		printf("Creating new address...\n");
		send_one_test_stream(test_stream_new_address, sizeof(test_stream_new_address));
	}
	printf("Getting number of addresses...\n");
	send_one_test_stream(test_stream_get_num_addresses, sizeof(test_stream_get_num_addresses));
	printf("Getting address 1...\n");
	send_one_test_stream(test_stream_get_address1, sizeof(test_stream_get_address1));
	printf("Getting address 0...\n");
	send_one_test_stream(test_stream_get_address0, sizeof(test_stream_get_address0));
	printf("Signing transaction...\n");
	send_one_test_stream(test_stream_sign_tx, sizeof(test_stream_sign_tx));
	//printf("Formatting...\n");
	//send_one_test_stream(test_stream_format, sizeof(test_stream_format));
	printf("Loading wallet using incorrect key...\n");
	send_one_test_stream(test_stream_load_incorrect, sizeof(test_stream_load_incorrect));
	printf("Loading wallet using correct key...\n");
	send_one_test_stream(test_stream_load_correct, sizeof(test_stream_load_correct));
	printf("Changing wallet key...\n");
	send_one_test_stream(test_stream_change_key, sizeof(test_stream_change_key));
	printf("Unloading wallet...\n");
	send_one_test_stream(test_stream_unload, sizeof(test_stream_unload));
	printf("Loading wallet using changed key...\n");
	send_one_test_stream(test_stream_load_with_changed_key, sizeof(test_stream_load_with_changed_key));

	exit(0);
}

#endif // #ifdef TEST


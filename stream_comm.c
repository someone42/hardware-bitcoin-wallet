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
// is only used as a placeholder pointer for translateWalletError() if
// there is no appropriate pointer.
#ifndef NULL
#define NULL ((void *)0) 
#endif // #ifndef NULL

// The transaction hash of the most recently approved transaction. This is
// stored so that if a transaction needs to be signed multiple times (eg.
// if it has more than one input), the user doesn't have to confirm every one.
static u8 prev_transaction_hash[32];
// 0 means disregard prev_transaction_hash, non-zero means that
// prev_transaction_hash is valid for prev_transaction_hash_valid more
// transactions (eg. if prev_transaction_hash_valid is 2, then
// prev_transaction_hash can be considered valid for the approval of 2 more
// transactions).
static u16 prev_transaction_hash_valid;

// Length of current packet's payload.
static u32 payload_length;

// Write a number of bytes to the output stream. Returns 0 on success,
// non-zero on failure.
static u8 writeBytes(u8 *buffer, u16 length)
{
	u16 i;

	for (i = 0; i < length; i++)
	{
		if (streamPutOneByte(buffer[i]))
		{
			return 1; // write error
		}
	}
	return 0;
}

// Sends a packet with a device string as payload. spec specifies the device
// string to send and command specifies the command of the packet.
// This returns 0 on success or non-zero if there was a write error.
static u8 writeString(StringSet set, u8 spec, u8 command)
{
	u8 buffer[5];
	u16 length;
	u16 i;

	buffer[0] = command;
	length = getStringLength(set, spec);
	writeU32LittleEndian(&(buffer[1]), length);
	if (writeBytes(buffer, 5))
	{
		return 1; // write error
	}
	for (i = 0; i < length; i++)
	{
		if (streamPutOneByte((u8)getString(set, spec, i)))
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
static u8 translateWalletError(WalletErrors r, u8 length, u8 *data)
{
	u8 buffer[5];

	if (r == WALLET_NO_ERROR)
	{
		buffer[0] = 0x02;
		writeU32LittleEndian(&(buffer[1]), length);
		if (writeBytes(buffer, 5))
		{
			return 1; // write error
		}
		if (writeBytes(data, length))
		{
			return 1; // write error
		}
	}
	else
	{
		return writeString(STRINGSET_WALLET, (u8)r, 0x03);
	}

	return 0;
}

// Read a number (specified by length) of bytes from the input stream
// and place those bytes into a buffer. Returns 0 on success, non-zero on
// failure.
static u8 readBytes(u8 *buffer, u8 length)
{
	u8 i;

	for (i = 0; i < length; i++)
	{
		if (streamGetOneByte(&(buffer[i])))
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
u8 formatStorage(void)
{
	if (translateWalletError(sanitiseNonVolatileStorage(0, 0xffffffff), 0, NULL))
	{
		return 1; // write error
	}

	uninitWallet(); // force wallet to unload
	return 0;
}

// Sign the transaction with hash given by sig_hash with the private key
// associated with the address handle ah. If the signing process was
// successful, the signature is also sent as a success packet.
// This has the same return values as validateAndSignTransaction().
static NOINLINE u8 signTransactionByAddressHandle(AddressHandle ah, u8 *sig_hash)
{
	u8 signature[73];
	u8 private_key[32];
	u8 signature_length;

	signature_length = 0;
	if (getPrivateKey(private_key, ah) == WALLET_NO_ERROR)
	{
		// Note: signTransaction() cannot fail.
		signature_length = signTransaction(signature, sig_hash, private_key);
	}
	if (translateWalletError (walletGetLastError(), signature_length, signature))
	{
		return 1; // write error
	}
	return 0;
}

// Read the transaction from the input stream, parse it and ask the user
// if they accept it. A non-zero value will be written to *out_confirmed if
// the user accepted it, otherwise a zero value will be written.
// This has the same return values as validateAndSignTransaction().
static NOINLINE u8 parseTransactionAndAsk(u8 *out_confirmed, u8 *sig_hash, u32 transaction_length)
{
	u8 confirmed;
	u8 i;
	TransactionErrors r;
	u8 transaction_hash[32];

	// Validate transaction and calculate hashes of it.
	*out_confirmed = 0;
	clearOutputsSeen();
	r = parseTransaction(sig_hash, transaction_hash, transaction_length);
	if (r == TRANSACTION_READ_ERROR)
	{
		return 2; // read error
	}
	if (r != TRANSACTION_NO_ERROR)
	{
		if (writeString(STRINGSET_TRANSACTION, (u8)r, 0x03))
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
	// Does transaction_hash match previous confirmed transaction?
	if (prev_transaction_hash_valid)
	{
		if (bigCompare(transaction_hash, prev_transaction_hash) == BIGCMP_EQUAL)
		{
			confirmed = 1;
			prev_transaction_hash_valid--;
		}
	}
	if (!confirmed)
	{
		// Need to explicitly get permission from user.
		// The call to parseTransaction should have logged all the outputs
		// to the user interface.
		if (askUser(ASKUSER_SIGN_TRANSACTION))
		{
			if (writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, 0x03))
			{
				return 1; // write error
			}
		}
		else
		{
			confirmed = 1;
			for (i = 0; i < 32; i++)
			{
				prev_transaction_hash[i] = transaction_hash[i];
			}
			// The transaction hash can only be reused another
			// (number of inputs) - 1 times. This is to prevent an exploit
			// where an attacker crafts a lot of copies (with differing inputs
			// but identical outputs) of a genuine transaction. With unlimited
			// reuse of the transaction hash, acceptance of the original
			// genuine transaction would also allow all the copies to be
			// automatically accepted, causing the user to spend more than
			// they intended.
			prev_transaction_hash_valid = getTransactionNumInputs();
			if (prev_transaction_hash_valid)
			{
				prev_transaction_hash_valid--;
			}
		}
	}

	*out_confirmed = confirmed;
	return 0;
}

// Validate and sign a transaction, given the address handle specified by
// ah and a transaction length specified by transaction_length. The signature
// or any error messages will be sent to the output stream.
// This will return 0 on success, 1 if a write error occurred or 2 if a read
// error occurred. "Success" here is defined as "no read or write errors
// occurred"; 0 will be returned even if the transaction was rejected.
// This function will always consume transaction_length bytes from the input
// stream, except when a read error occurs.
static NOINLINE u8 validateAndSignTransaction(AddressHandle ah, u32 transaction_length)
{
	u8 confirmed;
	u8 r;
	u8 sig_hash[32];

	r = parseTransactionAndAsk(&confirmed, sig_hash, transaction_length);
	if (r)
	{
		return r;
	}

	if (confirmed)
	{
		// Okay to sign transaction.
		r = signTransactionByAddressHandle(ah, sig_hash);
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
static NOINLINE u8 getAndSendAddressAndPublicKey(u8 generate_new)
{
	AddressHandle ah;
	PointAffine public_key;
	u8 address[20];
	u8 buffer[5];
	WalletErrors r;

	if (generate_new)
	{
		// Generate new address handle.
		r = WALLET_NO_ERROR;
		ah = makeNewAddress(address, &public_key);
		if (ah == BAD_ADDRESS_HANDLE)
		{
			r = walletGetLastError();
		}
	}
	else
	{
		// Read address handle from input stream.
		if (readBytes(buffer, 4))
		{
			return 1; // read error
		}
		ah = readU32LittleEndian(buffer);
		r = getAddressAndPublicKey(address, &public_key, ah);
	}

	if (r == WALLET_NO_ERROR)
	{
		buffer[0] = 0x02;
		if (generate_new)
		{
			// 4 (address handle) + 20 (address) + 65 (public key)
			writeU32LittleEndian(&(buffer[1]), 89);
		}
		else
		{
			// 20 (address) + 65 (public key)
			writeU32LittleEndian(&(buffer[1]), 85);
		}
		if (writeBytes(buffer, 5))
		{
			return 1; // write error
		}
		if (generate_new)
		{
			writeU32LittleEndian(buffer, ah);
			if (writeBytes(buffer, 4))
			{
				return 1; // write error
			}
		}
		if (writeBytes(address, 20))
		{
			return 1; // write error
		}
		buffer[0] = 0x04;
		if (writeBytes(buffer, 1))
		{
			return 1; // write error
		}
		if (writeBytes(public_key.x, 32))
		{
			return 1; // write error
		}
		if (writeBytes(public_key.y, 32))
		{
			return 1; // write error
		}
	}
	else
	{
		if (translateWalletError (r, 0, NULL))
		{
			return 1; // write error
		}
	} // end if (r == WALLET_NO_ERROR)

	return 0;
}

// Send a packet containing a list of wallets.
// Returns 1 if a write error occurred, otherwise returns 0.
static NOINLINE u8 listWallets(void)
{
	u8 version[4];
	u8 name[40];
	u8 buffer[5];

	if (getWalletInfo(version, name) != WALLET_NO_ERROR)
	{
		if (translateWalletError(walletGetLastError(), 0, NULL))
		{
			return 1; // write error
		}
	}
	else
	{
		buffer[0] = 0x02;
		writeU32LittleEndian(&(buffer[1]), 44);
		if (writeBytes(buffer, 5))
		{
			return 1; // write error
		}
		if (writeBytes(version, 4))
		{
			return 1; // write error
		}
		if (writeBytes(name, 40))
		{
			return 1; // write error
		}
	}

	return 0;
}

// Read but ignore payload_length bytes from input stream.
// Returns 0 on success, non-zero if there was a read error.
static u8 readAndIgnoreInput(void)
{
	u8 junk;

	if (payload_length)
	{
		for (; payload_length--; )
		{
			if (streamGetOneByte(&junk))
			{
				return 1; // read error
			}
		}
	}
	return 0;
}

// All I/O errors returned by expectLength() are >= EXPECT_LENGTH_IO_ERROR.
#define EXPECT_LENGTH_IO_ERROR		42

// Expect payload length to be equal to desired_length, and send an error
// message (and read but ignore payload_length bytes from input stream) if
// that is the case. Returns:
// 0 for success,
// 1 for length != desired_length.
// EXPECT_LENGTH_IO_ERROR for read error,
// EXPECT_LENGTH_IO_ERROR + 1 for write error,
static u8 expectLength(const u8 desired_length)
{
	if (payload_length != desired_length)
	{
		if (readAndIgnoreInput())
		{
			return EXPECT_LENGTH_IO_ERROR; // read error
		}
		if (writeString(STRINGSET_MISC, MISCSTR_INVALID_PACKET, 0x03))
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
void initStreamComm(void)
{
	prev_transaction_hash_valid = 0;
}

// Get packet from stream and deal with it. Returns 0 if the packet was
// received successfully, non-zero if an error occurred. 0 will still
// be returned if a command failed; here, "an error" means a problem
// reading/writing from/to the stream.
u8 processPacket(void)
{
	u8 command;
	u8 buffer[40];
	u8 i;
	u8 r;
	AddressHandle ah;

	if (streamGetOneByte(&command))
	{
		return 1; // read error
	}
	if (readBytes(buffer, 4))
	{
		return 1; // read error
	}
	payload_length = readU32LittleEndian(buffer);

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
		if (readAndIgnoreInput())
		{
			return 1; // read error
		}
		if (writeString(STRINGSET_MISC, MISCSTR_VERSION, 0x01))
		{
			return 1; // write error
		}
		break;

	// Commands 0x01, 0x02 and 0x03 should never be received; they are only
	// sent.

	case 0x04:
		// Create new wallet.
		r = expectLength(72);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (readBytes(buffer, 32))
			{
				return 1; // read error
			}
			setEncryptionKey(buffer);
			setTweakKey(&(buffer[16]));
			if (readBytes(buffer, 40))
			{
				return 1; // read error
			}
			if (askUser(ASKUSER_NUKE_WALLET))
			{
				if (writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, 0x03))
				{
					return 1; // write error
				}
			}
			else
			{
				if (translateWalletError(newWallet(buffer), 0, NULL))
				{
					return 1; // write error
				}
			}
		} // if (!r)
		break;

	case 0x05:
		// Create new address in wallet.
		r = expectLength(0);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (askUser(ASKUSER_NEW_ADDRESS))
			{
				if (writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, 0x03))
				{
					return 1; // write error
				}
			}
			else
			{
				if (getAndSendAddressAndPublicKey(1))
				{
					return 1; // read or write error
				}
			}
		} // if (!r)
		break;

	case 0x06:
		// Get number of addresses in wallet.
		r = expectLength(0);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			writeU32LittleEndian(buffer, getNumAddresses());
			if (translateWalletError(walletGetLastError(), 4, buffer))
			{
				return 1; // write error
			}
		} // if (!r)
		break;

	case 0x09:
		// Get public key corresponding to an address handle.
		r = expectLength(4);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (getAndSendAddressAndPublicKey(0))
			{
				return 1; // read or write error
			}
		} // if (!r)
		break;

	case 0x0a:
		// Sign a transaction.
		if (payload_length <= 4)
		{
			if (readAndIgnoreInput())
			{
				return 1; // read error
			}
			if (writeString(STRINGSET_MISC, MISCSTR_INVALID_PACKET, 0x03))
			{
				return 1; // write error
			}
		}
		else
		{
			if (readBytes(buffer, 4))
			{
				return 1; // read error
			}
			ah = readU32LittleEndian(buffer);
			// Don't need to subtract 4 off payload_length because readBytes
			// has already done so.
			if (validateAndSignTransaction(ah, payload_length))
			{
				return 1; // read or write error
			}
			payload_length = 0;
		}
		break;

	case 0x0b:
		// Load wallet.
		r = expectLength(32);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (readBytes(buffer, 32))
			{
				return 1; // read error
			}
			setEncryptionKey(buffer);
			setTweakKey(&(buffer[16]));
			if (translateWalletError (initWallet(), 0, NULL))
			{
				return 1; // write error
			}
		} // if (!r)
		break;

	case 0x0c:
		// Unload wallet.
		r = expectLength(0);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			volatile u8 *buffer_alias;
			clearEncryptionKeys();
			sanitiseRam();
			buffer_alias = buffer;
			for (i = 0; i < 32; i++)
			{
				buffer_alias[i] = 0xff;
			}
			for (i = 0; i < 32; i++)
			{
				buffer_alias[i] = 0x0;
			}
			if (translateWalletError(uninitWallet(), 0, NULL))
			{
				return 1; // write error
			}
		} // if (!r)
		break;

	case 0x0d:
		// Format storage.
		r = expectLength(0);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (askUser(ASKUSER_FORMAT))
			{
				if (writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, 0x03))
				{
					return 1; // write error
				}
			}
			else
			{
				if (formatStorage())
				{
					return 1; // write error
				}
			}
		} // if (!r)
		break;

	case 0x0e:
		// Change wallet encryption key.
		r = expectLength(32);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (readBytes(buffer, 32))
			{
				return 1; // read error
			}
			if (translateWalletError(changeEncryptionKey(buffer), 0, NULL))
			{
				return 1; // write error
			}
		} // if (!r)
		break;

	case 0x0f:
		// Change wallet name.
		r = expectLength(40);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (readBytes(buffer, 40))
			{
				return 1; // read error
			}
			if (askUser(ASKUSER_CHANGE_NAME))
			{
				if (writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, 0x03))
				{
					return 1; // write error
				}
			}
			else
			{
				if (translateWalletError(changeWalletName(buffer), 0, NULL))
				{
					return 1; // write error
				}
			}
		} // if (!r)
		break;

	case 0x10:
		// List wallets.
		r = expectLength(0);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (listWallets())
			{
				return 1; // write error
			}
		} // if (!r)
		break;

	default:
		// Unknown command.
		if (readAndIgnoreInput())
		{
			return 1; // read error
		}
		if (writeString(STRINGSET_MISC, MISCSTR_INVALID_PACKET, 0x03))
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

u8 streamGetOneByte(u8 *one_byte)
{
	*one_byte = 0;
	return 0; // success
}

u8 streamPutOneByte(u8 one_byte)
{
	// Reference one_byte to make certain compilers happy
	if (one_byte > 1000)
	{
		return 1;
	}
	return 0; // success
}

u16 getStringLength(StringSet set, u8 spec)
{
	// Reference set and spec to make certain compilers happy
	if (set == spec)
	{
		return 1;
	}
	return 0;
}

char getString(StringSet set, u8 spec, u16 pos)
{
	// Reference set, spec and pos to make certain compilers happy
	if ((pos == set) && (set == spec))
	{
		return 32;
	}
	return 0;
}

u8 askUser(AskUserCommand command)
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

// Sets input stream (what will be read by streamGetOneByte()) to the
// contents of a buffer.
static void setInputStream(const u8 *buffer, int length)
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

// Get one byte from the contents of the buffer set by setInputStream().
u8 streamGetOneByte(u8 *one_byte)
{
	if (stream_ptr >= stream_length)
	{
		return 1; // end of stream
	}
	*one_byte = stream[stream_ptr++];
	return 0; // success
}

u8 streamPutOneByte(u8 one_byte)
{
	printf(" %02x", (int)one_byte);
	return 0; // success
}

static const char *getStringInternal(StringSet set, u8 spec)
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
		case TRANSACTION_INVALID_FORMAT:
			return "Format of transaction is unknown or invalid";
			break;
		case TRANSACTION_TOO_MANY_INPUTS:
			return "Too many inputs in transaction";
			break;
		case TRANSACTION_TOO_MANY_OUTPUTS:
			return "Too many outputs in transaction";
			break;
		case TRANSACTION_TOO_LARGE:
			return "Transaction's size is too large";
			break;
		case TRANSACTION_NON_STANDARD:
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

u16 getStringLength(StringSet set, u8 spec)
{
	return (u16)strlen(getStringInternal(set, spec));
}

char getString(StringSet set, u8 spec, u16 pos)
{
	assert(pos < getStringLength(set, spec));
	return getStringInternal(set, spec)[pos];
}

u8 askUser(AskUserCommand command)
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
	case ASKUSER_CHANGE_NAME:
		printf("Change wallet name? ");
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

// List wallets
static const u8 test_stream_list_wallets[] = {
0x10, 0x00, 0x00, 0x00, 0x00};

// Change wallet name
static const u8 test_stream_change_name[] = {
0x0f, 0x28, 0x00, 0x00, 0x00,
0x71, 0x71, 0x71, 0x72, 0x70, 0x74, 0x20, 0x20,
0x68, 0x68, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};

static void sendOneTestStream(const u8 *test_stream, int size)
{
	int r;

	setInputStream(test_stream, size);
	r = processPacket();
	printf("\n");
	printf("processPacket() returned: %d\n", r);
}

int main(void)
{
	int i;

	initWalletTest();
	initWallet();

	printf("Listing wallets...\n");
	sendOneTestStream(test_stream_list_wallets, sizeof(test_stream_list_wallets));
	printf("Creating new wallet...\n");
	sendOneTestStream(test_stream_new_wallet, sizeof(test_stream_new_wallet));
	printf("Listing wallets...\n");
	sendOneTestStream(test_stream_list_wallets, sizeof(test_stream_list_wallets));
	for(i = 0; i < 4; i++)
	{
		printf("Creating new address...\n");
		sendOneTestStream(test_stream_new_address, sizeof(test_stream_new_address));
	}
	printf("Getting number of addresses...\n");
	sendOneTestStream(test_stream_get_num_addresses, sizeof(test_stream_get_num_addresses));
	printf("Getting address 1...\n");
	sendOneTestStream(test_stream_get_address1, sizeof(test_stream_get_address1));
	printf("Getting address 0...\n");
	sendOneTestStream(test_stream_get_address0, sizeof(test_stream_get_address0));
	printf("Signing transaction...\n");
	sendOneTestStream(test_stream_sign_tx, sizeof(test_stream_sign_tx));
	//printf("Formatting...\n");
	//sendOneTestStream(test_stream_format, sizeof(test_stream_format));
	printf("Loading wallet using incorrect key...\n");
	sendOneTestStream(test_stream_load_incorrect, sizeof(test_stream_load_incorrect));
	printf("Loading wallet using correct key...\n");
	sendOneTestStream(test_stream_load_correct, sizeof(test_stream_load_correct));
	printf("Changing wallet key...\n");
	sendOneTestStream(test_stream_change_key, sizeof(test_stream_change_key));
	printf("Unloading wallet...\n");
	sendOneTestStream(test_stream_unload, sizeof(test_stream_unload));
	printf("Loading wallet using changed key...\n");
	sendOneTestStream(test_stream_load_with_changed_key, sizeof(test_stream_load_with_changed_key));
	printf("Changing name...\n");
	sendOneTestStream(test_stream_change_name, sizeof(test_stream_change_name));
	printf("Listing wallets...\n");
	sendOneTestStream(test_stream_list_wallets, sizeof(test_stream_list_wallets));

	exit(0);
}

#endif // #ifdef TEST


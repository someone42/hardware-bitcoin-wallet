/** \file stream_comm.c
  *
  * \brief Deals with packets sent over the stream device.
  *
  * The most important function in this file is processPacket(). It decodes
  * packets from the stream and calls the relevant functions from wallet.c or
  * transaction.c. Some validation of the received data is also handled in
  * this file. Here is a general rule for what validation is done: if the
  * validation can be done without knowing the internal details of how wallets
  * are stored or how transactions are parsed, then the validation is done
  * in this file. Finally, the functions in this file translate the return
  * values from wallet.c and transaction.c into response packets which are
  * sent over the stream device.
  *
  * This file is licensed as described by the file LICENCE.
  */

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

/** Because stdlib.h might not be included, NULL might be undefined. NULL
  * is only used as a placeholder pointer for translateWalletError() if
  * there is no appropriate pointer. */
#ifndef NULL
#define NULL ((void *)0) 
#endif // #ifndef NULL

/** The transaction hash of the most recently approved transaction. This is
  * stored so that if a transaction needs to be signed multiple times (eg.
  * if it has more than one input), the user doesn't have to approve every
  * one. */
static uint8_t prev_transaction_hash[32];
/** 0 means disregard #prev_transaction_hash, non-zero means
  * that #prev_transaction_hash is valid for prev_transaction_hash_valid more
  * transactions (eg. if prev_transaction_hash_valid is 2,
  * then #prev_transaction_hash can be considered valid for the approval of 2
  * more transactions). */
static uint16_t prev_transaction_hash_valid;

/** Length of current packet's payload. */
static uint32_t payload_length;

/** Write a number of bytes to the output stream.
  * \param buffer The array of bytes to be written.
  * \param length The number of bytes to write.
  * \return 0 on success, non-zero if a stream write error occurred.
  */
static uint8_t writeBytes(uint8_t *buffer, uint16_t length)
{
	uint16_t i;

	for (i = 0; i < length; i++)
	{
		if (streamPutOneByte(buffer[i]))
		{
			return 1; // write error
		}
	}
	return 0;
}

/** Sends a packet with a string as payload.
  * \param set See getString().
  * \param spec See getString().
  * \param command The type of the packet, as defined in the file PROTOCOL.
  * \return 0 on success, non-zero if there was a stream write error.
  */
static uint8_t writeString(StringSet set, uint8_t spec, uint8_t command)
{
	uint8_t buffer[5];
	uint8_t one_char;
	uint16_t length;
	uint16_t i;

	buffer[0] = command;
	length = getStringLength(set, spec);
	writeU32LittleEndian(&(buffer[1]), length);
	if (writeBytes(buffer, 5))
	{
		return 1; // write error
	}
	for (i = 0; i < length; i++)
	{
		one_char = (uint8_t)getString(set, spec, i);
		if (streamPutOneByte(one_char))
		{
			return 1; // write error
		}
	}
	return 0;
}

/** Translates a return value from one of the wallet functions into a response
  * packet to be written to the stream. If the wallet return value indicates
  * success, a payload can be included with the packet. Otherwise, if the
  * wallet return value indicates failure, the payload is a text error message
  * describing how the wallet function failed.
  * \param r The return value from the wallet function.
  * \param length The length of the success payload (use 0 for no payload) in
  *               number of bytes.
  * \param data A byte array holding the data of the success payload.
  *             Use #NULL for no payload.
  * \return 0 on success, non-zero if there was a stream write error.
  */
static uint8_t translateWalletError(WalletErrors r, uint8_t length, uint8_t *data)
{
	uint8_t buffer[5];

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
		return writeString(STRINGSET_WALLET, (uint8_t)r, 0x03);
	}

	return 0;
}

/** Read bytes from the stream.
  * \param buffer The byte array where the bytes will be placed. This must
  *               have enough space to store length bytes.
  * \param length The number of bytes to read.
  * \return 0 on success, non-zero if a stream read error occurred.
  */
static uint8_t readBytes(uint8_t *buffer, uint8_t length)
{
	uint8_t i;

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

/** Format non-volatile storage, erasing its contents in a way that makes
  * them irretrievable.
  * \return 0 on success or non-zero if there was a stream write error.
  */
uint8_t formatStorage(void)
{
	WalletErrors wallet_return;

	wallet_return = sanitiseNonVolatileStorage(0, 0xffffffff);
	if (translateWalletError(wallet_return, 0, NULL))
	{
		return 1; // write error
	}

	uninitWallet(); // force wallet to unload
	return 0;
}

/** Sign a transaction and (if everything goes well) send the signature in a
  * response packet.
  * \param ah The address handle whose corresponding private key will be used
  *           to sign the transaction.
  * \param sig_hash The signature hash of the transaction, as calculated by
  *                 parseTransaction(). This must be an array of 32 bytes.
  * \return Same values as validateAndSignTransaction().
  */
static NOINLINE uint8_t signTransactionByAddressHandle(AddressHandle ah, uint8_t *sig_hash)
{
	uint8_t signature[73];
	uint8_t private_key[32];
	uint8_t signature_length;
	WalletErrors wallet_return;

	signature_length = 0;
	if (getPrivateKey(private_key, ah) == WALLET_NO_ERROR)
	{
		// Note: signTransaction() cannot fail.
		signature_length = signTransaction(signature, sig_hash, private_key);
	}
	wallet_return = walletGetLastError();
	if (translateWalletError (wallet_return, signature_length, signature))
	{
		return 1; // write error
	}
	return 0;
}

/** Read a transaction from the stream, parse it and ask the user
  * if they approve it.
  * \param out_confirmed A non-zero value will be written to here if the
  *                      user approved the transaction, otherwise a zero value
  *                      will be written.
  * \param sig_hash The signature hash of the transaction will be written to
  *                 here by parseTransaction(). This must be an array of 32
  *                 bytes.
  * \param transaction_length The length of the transaction, in number of
  *                           bytes. This can be derived from the payload
  *                           length of a packet.
  * \return Same values as validateAndSignTransaction().
  */
static NOINLINE uint8_t parseTransactionAndAsk(uint8_t *out_confirmed, uint8_t *sig_hash, uint32_t transaction_length)
{
	TransactionErrors r;
	uint8_t transaction_hash[32];

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
		// Transaction parse error.
		if (writeString(STRINGSET_TRANSACTION, (uint8_t)r, 0x03))
		{
			return 1; // write error
		}
		else
		{
			return 0;
		}
	}

	// Get permission from user.
	*out_confirmed = 0;
	// Does transaction_hash match previous confirmed transaction?
	if (prev_transaction_hash_valid)
	{
		if (bigCompare(transaction_hash, prev_transaction_hash) == BIGCMP_EQUAL)
		{
			*out_confirmed = 1;
			prev_transaction_hash_valid--;
		}
	}
	if (!(*out_confirmed))
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
			*out_confirmed = 1;
			memcpy(prev_transaction_hash, transaction_hash, 32);
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

	return 0;
}

/** Validate and sign a transaction. This basically calls
  * parseTransactionAndAsk() and signTransactionByAddressHandle() in sequence.
  * Why do that? For the same reason generateDeterministic256() was split into
  * two parts - more efficient use of stack space.
  *
  * This function will always consume transaction_length bytes from the input
  * stream, except when a stream read error occurs.
  * \param ah The address handle whose corresponding private key will be used
  *           to sign the transaction.
  * \param transaction_length The length of the transaction, in number of
  *                           bytes. This can be derived from the payload
  *                           length of a packet.
  * \return 0 on success, 1 if a stream write error occurred or 2 if a stream
  *         read error occurred. "Success" here is defined as "no stream read
  *         or write errors occurred"; 0 will be returned even if the
  *         transaction was rejected by the user.
  */
static NOINLINE uint8_t validateAndSignTransaction(AddressHandle ah, uint32_t transaction_length)
{
	uint8_t confirmed;
	uint8_t r;
	uint8_t sig_hash[32];

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

/** Send a packet containing an address and its corresponding public key.
  * This can generate new addresses as well as obtain old addresses. Both
  * use cases were combined into one function because they involve similar
  * processes.
  * \param generate_new If this is non-zero, a new address will be generated
  *                     and the address handle of the generated address will
  *                     be prepended to the output packet.
  *                     If this is zero, the address handle will be read from
  *                     the input stream. No address handle will be prepended
  *                     to the output packet.
  * \return 1 if a stream read or write error occurred, 0 on success.
  */
static NOINLINE uint8_t getAndSendAddressAndPublicKey(uint8_t generate_new)
{
	AddressHandle ah;
	PointAffine public_key;
	uint8_t address[20];
	uint8_t buffer[5];
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

/** Send a packet containing a list of wallets.
  * \return 1 if a stream write error occurred, 0 on success.
  */
static NOINLINE uint8_t listWallets(void)
{
	uint8_t version[4];
	uint8_t name[NAME_LENGTH];
	uint8_t buffer[5];
	WalletErrors wallet_return;

	if (getWalletInfo(version, name) != WALLET_NO_ERROR)
	{
		wallet_return = walletGetLastError();
		if (translateWalletError(wallet_return, 0, NULL))
		{
			return 1; // write error
		}
	}
	else
	{
		buffer[0] = 0x02;
		writeU32LittleEndian(&(buffer[1]), 4 + NAME_LENGTH);
		if (writeBytes(buffer, 5))
		{
			return 1; // write error
		}
		if (writeBytes(version, 4))
		{
			return 1; // write error
		}
		if (writeBytes(name, NAME_LENGTH))
		{
			return 1; // write error
		}
	}

	return 0;
}

/** Read but ignore #payload_length bytes from input stream. This will also
  * set #payload_length to 0 (if everything goes well). This function is
  * useful for ensuring that the entire payload of a packet is read from the
  * stream device.
  * \return 0 on success, non-zero if there was a stream read error.
  */
static uint8_t readAndIgnoreInput(void)
{
	uint8_t junk;

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

/** All I/O errors returned by expectLength() are >= EXPECT_LENGTH_IO_ERROR. */
#define EXPECT_LENGTH_IO_ERROR		42

/** Expect the payload length of a packet to be equal to desired_length, and
  * send an error message (and read but ignore #payload_length bytes from the
  * stream) if that is not the case. This function is used to enforce the
  * payload length of packets to be compliant with the protocol described in
  * the file PROTOCOL.
  * \param desired_length The expected payload length (in bytes) of the packet
  *                       currently being received from the stream device.
  * \return 0 for success,
  * 1 for payload length != desired_length, #EXPECT_LENGTH_IO_ERROR for stream
  * read error and #EXPECT_LENGTH_IO_ERROR + 1 for stream write error.
  */
static uint8_t expectLength(const uint8_t desired_length)
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

/** Get packet from stream and deal with it. This basically implements the
  * protocol described in the file PROTOCOL.
  * 
  * This function will always completely
  * read a packet before sending a response packet. As long as the host
  * does the same thing, deadlocks cannot occur. Thus a productive
  * communication session between the hardware Bitcoin wallet and a host
  * should consist of the wallet and host alternating between sending a
  * packet and receiving a packet.
  * \return 0 if the packet was received successfully, non-zero if a stream
  *         read or write error occurred. 0 will still be returned if a
  *         command failed due to reasons other than stream I/O; here, "an
  *         error" means a problem reading/writing from/to the stream device.
  */
uint8_t processPacket(void)
{
	uint8_t command;
	// Technically, the length of buffer should also be >= 4, since it is used
	// in a couple of places to obtain 32 bit values. This is guaranteed by
	// the reference to WALLET_ENCRYPTION_KEY_LENGTH, since no-one in their
	// right mind would use encryption with smaller than 32 bit keys.
	uint8_t buffer[MAX(NAME_LENGTH, WALLET_ENCRYPTION_KEY_LENGTH)];
	uint8_t r;
	uint32_t num_addresses;
	AddressHandle ah;
	WalletErrors wallet_return;

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
			if (readBytes(buffer, WALLET_ENCRYPTION_KEY_LENGTH))
			{
				return 1; // read error
			}
			setEncryptionKey(buffer);
			if (readBytes(buffer, NAME_LENGTH))
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
				wallet_return = newWallet(buffer);
				if (translateWalletError(wallet_return, 0, NULL))
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
			num_addresses = getNumAddresses();
			writeU32LittleEndian(buffer, num_addresses);
			wallet_return = walletGetLastError();
			if (translateWalletError(wallet_return, 4, buffer))
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
		r = expectLength(WALLET_ENCRYPTION_KEY_LENGTH);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (readBytes(buffer, WALLET_ENCRYPTION_KEY_LENGTH))
			{
				return 1; // read error
			}
			setEncryptionKey(buffer);
			wallet_return = initWallet();
			if (translateWalletError (wallet_return, 0, NULL))
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
			clearEncryptionKey();
			sanitiseRam();
			memset(buffer, 0xff, sizeof(buffer));
			memset(buffer, 0, sizeof(buffer));
			wallet_return = uninitWallet();
			if (translateWalletError(wallet_return, 0, NULL))
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
		r = expectLength(WALLET_ENCRYPTION_KEY_LENGTH);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (readBytes(buffer, WALLET_ENCRYPTION_KEY_LENGTH))
			{
				return 1; // read error
			}
			wallet_return = changeEncryptionKey(buffer);
			if (translateWalletError(wallet_return, 0, NULL))
			{
				return 1; // write error
			}
		} // if (!r)
		break;

	case 0x0f:
		// Change wallet name.
		r = expectLength(NAME_LENGTH);
		if (r >= EXPECT_LENGTH_IO_ERROR)
		{
			return 1; // read or write error
		}
		if (!r)
		{
			if (readBytes(buffer, NAME_LENGTH))
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
				wallet_return = changeWalletName(buffer);
				if (translateWalletError(wallet_return, 0, NULL))
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

uint8_t streamGetOneByte(uint8_t *one_byte)
{
	*one_byte = 0;
	return 0; // success
}

uint8_t streamPutOneByte(uint8_t one_byte)
{
	// Reference one_byte to make certain compilers happy
	if (one_byte > 1000)
	{
		return 1;
	}
	return 0; // success
}

uint16_t getStringLength(StringSet set, uint8_t spec)
{
	// Reference set and spec to make certain compilers happy
	if (set == spec)
	{
		return 1;
	}
	return 0;
}

char getString(StringSet set, uint8_t spec, uint16_t pos)
{
	// Reference set, spec and pos to make certain compilers happy
	if ((pos == set) && (set == spec))
	{
		return 32;
	}
	return 0;
}

uint8_t askUser(AskUserCommand command)
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

static uint8_t *stream;
static int stream_ptr;
static int stream_length;

// Sets input stream (what will be read by streamGetOneByte()) to the
// contents of a buffer.
static void setInputStream(const uint8_t *buffer, int length)
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
uint8_t streamGetOneByte(uint8_t *one_byte)
{
	if (stream_ptr >= stream_length)
	{
		return 1; // end of stream
	}
	*one_byte = stream[stream_ptr++];
	return 0; // success
}

uint8_t streamPutOneByte(uint8_t one_byte)
{
	printf(" %02x", (int)one_byte);
	return 0; // success
}

static const char *getStringInternal(StringSet set, uint8_t spec)
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

uint16_t getStringLength(StringSet set, uint8_t spec)
{
	return (uint16_t)strlen(getStringInternal(set, spec));
}

char getString(StringSet set, uint8_t spec, uint16_t pos)
{
	assert(pos < getStringLength(set, spec));
	return getStringInternal(set, spec)[pos];
}

uint8_t askUser(AskUserCommand command)
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
static const uint8_t test_stream_new_wallet[] = {
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
static const uint8_t test_stream_new_address[] = {
0x05, 0x00, 0x00, 0x00, 0x00};

// Get number of addresses
static const uint8_t test_stream_get_num_addresses[] = {
0x06, 0x00, 0x00, 0x00, 0x00};

// Get address 1
static const uint8_t test_stream_get_address1[] = {
0x09, 0x04, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00};

// Get address 0 (which is an invalid address handle)
static const uint8_t test_stream_get_address0[] = {
0x09, 0x04, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00};

// Sign something
static uint8_t test_stream_sign_tx[] = {
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
static const uint8_t test_stream_format[] = {
0x0d, 0x00, 0x00, 0x00, 0x00};

// Load wallet using correct key
static const uint8_t test_stream_load_correct[] = {
0x0b, 0x20, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Load wallet using incorrect key
static const uint8_t test_stream_load_incorrect[] = {
0x0b, 0x20, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Unload wallet
static const uint8_t test_stream_unload[] = {
0x0c, 0x00, 0x00, 0x00, 0x00};

// Change encryption key
static const uint8_t test_stream_change_key[] = {
0x0e, 0x20, 0x00, 0x00, 0x00,
0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Load with new encryption key
static const uint8_t test_stream_load_with_changed_key[] = {
0x0b, 0x20, 0x00, 0x00, 0x00,
0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// List wallets
static const uint8_t test_stream_list_wallets[] = {
0x10, 0x00, 0x00, 0x00, 0x00};

// Change wallet name
static const uint8_t test_stream_change_name[] = {
0x0f, 0x28, 0x00, 0x00, 0x00,
0x71, 0x71, 0x71, 0x72, 0x70, 0x74, 0x20, 0x20,
0x68, 0x68, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};

static void sendOneTestStream(const uint8_t *test_stream, int size)
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


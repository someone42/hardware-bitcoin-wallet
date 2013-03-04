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

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#endif // #ifdef TEST

#ifdef TEST_STREAM_COMM
#include <string.h>
#include "test_helpers.h"
#endif // #ifdef TEST_STREAM_COMM

#include "common.h"
#include "endian.h"
#include "hwinterface.h"
#include "wallet.h"
#include "bignum256.h"
#include "stream_comm.h"
#include "prandom.h"
#include "xex.h"
#include "ecdsa.h"
#include "storage_common.h"

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
/** false means disregard #prev_transaction_hash, true means
  * that #prev_transaction_hash is valid. */
static bool prev_transaction_hash_valid;

/** Length of current packet's payload. */
static uint32_t payload_length;

/** Write a number of bytes to the output stream.
  * \param buffer The array of bytes to be written.
  * \param length The number of bytes to write.
  */
static void writeBytesToStream(uint8_t *buffer, uint16_t length)
{
	uint16_t i;

	for (i = 0; i < length; i++)
	{
		streamPutOneByte(buffer[i]);
	}
}

/** Sends a packet with a string as payload.
  * \param set See getString().
  * \param spec See getString().
  * \param command The type of the packet, as defined in the file PROTOCOL.
  */
static void writeString(StringSet set, uint8_t spec, uint8_t command)
{
	uint8_t buffer[4];
	uint8_t one_char;
	uint16_t length;
	uint16_t i;

	streamPutOneByte(command); // type
	length = getStringLength(set, spec);
	writeU32LittleEndian(buffer, length);
	writeBytesToStream(buffer, 4); // length
	for (i = 0; i < length; i++)
	{
		one_char = (uint8_t)getString(set, spec, i);
		streamPutOneByte(one_char); // value
	}
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
  */
static void translateWalletError(WalletErrors r, uint8_t length, uint8_t *data)
{
	uint8_t buffer[4];

	if (r == WALLET_NO_ERROR)
	{
		streamPutOneByte(PACKET_TYPE_SUCCESS); // type
		writeU32LittleEndian(buffer, length);
		writeBytesToStream(buffer, 4); // length
		writeBytesToStream(data, length); // value
	}
	else
	{
		writeString(STRINGSET_WALLET, (uint8_t)r, PACKET_TYPE_FAILURE);
	}
}

/** Read bytes from the stream.
  * \param buffer The byte array where the bytes will be placed. This must
  *               have enough space to store length bytes.
  * \param length The number of bytes to read.
  */
static void getBytesFromStream(uint8_t *buffer, uint8_t length)
{
	uint8_t i;

	for (i = 0; i < length; i++)
	{
		buffer[i] = streamGetOneByte();
	}
	payload_length -= length;
}

/** Sign a transaction and (if everything goes well) send the signature in a
  * response packet.
  * \param ah The address handle whose corresponding private key will be used
  *           to sign the transaction.
  * \param sig_hash The signature hash of the transaction, as calculated by
  *                 parseTransaction(). This must be an array of 32 bytes.
  */
static NOINLINE void signTransactionByAddressHandle(AddressHandle ah, uint8_t *sig_hash)
{
	uint8_t signature[MAX_SIGNATURE_LENGTH];
	uint8_t private_key[32];
	uint8_t signature_length;
	WalletErrors wallet_return;

	signature_length = 0;
	if (getPrivateKey(private_key, ah) == WALLET_NO_ERROR)
	{
		if (signTransaction(signature, &signature_length, sig_hash, private_key))
		{
			wallet_return = WALLET_RNG_FAILURE;
		}
		else
		{
			wallet_return = WALLET_NO_ERROR;
		}
	}
	else
	{
		wallet_return = walletGetLastError();
	}
	translateWalletError(wallet_return, signature_length, signature);
}

/** Read a transaction from the stream, parse it and ask the user
  * if they approve it.
  * \param out_approved Whether the user approved the transaction.
  * \param sig_hash The signature hash of the transaction will be written to
  *                 here by parseTransaction(). This must be an array of 32
  *                 bytes.
  * \param transaction_length The length of the transaction, in number of
  *                           bytes. This can be derived from the payload
  *                           length of a packet.
  */
static NOINLINE void parseTransactionAndAsk(bool *out_approved, uint8_t *sig_hash, uint32_t transaction_length)
{
	TransactionErrors r;
	uint8_t transaction_hash[32];

	// Validate transaction and calculate hashes of it.
	*out_approved = false;
	clearOutputsSeen();
	r = parseTransaction(sig_hash, transaction_hash, transaction_length);
	if (r != TRANSACTION_NO_ERROR)
	{
		// Transaction parse error.
		writeString(STRINGSET_TRANSACTION, (uint8_t)r, PACKET_TYPE_FAILURE);
		return;
	}

	// Get permission from user.
	*out_approved = false;
	// Does transaction_hash match previous approved transaction?
	if (prev_transaction_hash_valid)
	{
		if (bigCompare(transaction_hash, prev_transaction_hash) == BIGCMP_EQUAL)
		{
			*out_approved = true;
		}
	}
	if (!(*out_approved))
	{
		// Need to explicitly get permission from user.
		// The call to parseTransaction() should have logged all the outputs
		// to the user interface.
		if (userDenied(ASKUSER_SIGN_TRANSACTION))
		{
			writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, PACKET_TYPE_FAILURE);
		}
		else
		{
			// User approved transaction.
			*out_approved = true;
			memcpy(prev_transaction_hash, transaction_hash, 32);
			prev_transaction_hash_valid = true;
		}
	} // if (!(*out_approved))
}

/** Validate and sign a transaction. This basically calls
  * parseTransactionAndAsk() and signTransactionByAddressHandle() in sequence.
  * Why do that? For more efficient use of stack space.
  *
  * This function will always consume transaction_length bytes from the input
  * stream, except when a stream read error occurs.
  * \param ah The address handle whose corresponding private key will be used
  *           to sign the transaction.
  * \param transaction_length The length of the transaction, in number of
  *                           bytes. This can be derived from the payload
  *                           length of a packet.
  */
static NOINLINE void validateAndSignTransaction(AddressHandle ah, uint32_t transaction_length)
{
	bool approved;
	uint8_t sig_hash[32];

	approved = false;
	parseTransactionAndAsk(&approved, sig_hash, transaction_length);
	if (approved)
	{
		// Okay to sign transaction.
		signTransactionByAddressHandle(ah, sig_hash);
	}
}

/** Send a packet containing an address and its corresponding public key.
  * This can generate new addresses as well as obtain old addresses. Both
  * use cases were combined into one function because they involve similar
  * processes.
  * \param generate_new If this is true, a new address will be generated
  *                     and the address handle of the generated address will
  *                     be prepended to the output packet.
  *                     If this is false, the address handle will be read from
  *                     the input stream. No address handle will be prepended
  *                     to the output packet.
  */
static NOINLINE void getAndSendAddressAndPublicKey(bool generate_new)
{
	AddressHandle ah;
	PointAffine public_key;
	uint8_t address[20];
	uint8_t buffer[4];
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
		getBytesFromStream(buffer, 4);
		ah = readU32LittleEndian(buffer);
		r = getAddressAndPublicKey(address, &public_key, ah);
	}

	if (r == WALLET_NO_ERROR)
	{
		streamPutOneByte(PACKET_TYPE_SUCCESS); // type
		if (generate_new)
		{
			// 4 (address handle) + 20 (address) + 65 (public key)
			writeU32LittleEndian(buffer, 89);
		}
		else
		{
			// 20 (address) + 65 (public key)
			writeU32LittleEndian(buffer, 85);
		}
		writeBytesToStream(buffer, 4); // length
		if (generate_new)
		{
			writeU32LittleEndian(buffer, ah);
			writeBytesToStream(buffer, 4);
		}
		writeBytesToStream(address, 20);
		// The format of public keys sent is compatible with
		// "SEC 1: Elliptic Curve Cryptography" by Certicom research, obtained
		// 15-August-2011 from: http://www.secg.org/collateral/sec1_final.pdf
		// section 2.3 ("Data Types and Conversions"). The document basically
		// says that integers should be represented big-endian and that a 0x04
		// should be prepended to indicate that the public key is
		// uncompressed.
		streamPutOneByte(0x04);
		swapEndian256(public_key.x);
		swapEndian256(public_key.y);
		writeBytesToStream(public_key.x, 32);
		writeBytesToStream(public_key.y, 32);
	}
	else
	{
		translateWalletError(r, 0, NULL);
	} // end if (r == WALLET_NO_ERROR)
}

/** Send a packet containing a list of wallets.
  */
static NOINLINE void listWallets(void)
{
	uint8_t version[4];
	uint8_t name[NAME_LENGTH];
	uint8_t wallet_uuid[UUID_LENGTH];
	uint8_t buffer[4];
	uint32_t i;
	uint32_t num_wallets;
	WalletErrors wallet_return;

	num_wallets = getNumberOfWallets();
	if (num_wallets == 0)
	{
		wallet_return = walletGetLastError();
		translateWalletError(wallet_return, 0, NULL);
	}
	else
	{
		streamPutOneByte(PACKET_TYPE_SUCCESS); // type
		writeU32LittleEndian(buffer, (4 + NAME_LENGTH + UUID_LENGTH) * num_wallets); // length
		writeBytesToStream(buffer, 4);
		for (i = 0; i < num_wallets; i++)
		{
			if (getWalletInfo(version, name, wallet_uuid, i) != WALLET_NO_ERROR)
			{
				// It's too late to return an error message, since the host
				// now expects a full payload, so just send all 00s.
				memset(version, 0, 4);
				memset(name, 0, NAME_LENGTH);
				memset(wallet_uuid, 0, UUID_LENGTH);
			}
			writeBytesToStream(version, 4);
			writeBytesToStream(name, NAME_LENGTH);
			writeBytesToStream(wallet_uuid, UUID_LENGTH);
		} // end for (i = 0; i < num_wallets; i++)
	} // end if (num_wallets == 0)
}

/** Read name and seed from input stream and restore a wallet using those
  * values. This also prompts the user for approval of the action.
  * \param wallet_spec The wallet number of the wallet to restore.
  * \param make_hidden Whether to make the restored wallet a hidden wallet.
  */
static NOINLINE void restoreWallet(uint32_t wallet_spec, bool make_hidden)
{
	WalletErrors wallet_return;
	uint8_t name[NAME_LENGTH];
	uint8_t seed[SEED_LENGTH];

	getBytesFromStream(name, NAME_LENGTH);
	getBytesFromStream(seed, SEED_LENGTH);
	// userDenied() has to be called here (and not processPacket()) because
	// name and seed must be read from the stream before we're allowed to send
	// anything.
	if (userDenied(ASKUSER_RESTORE_WALLET))
	{
		writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, PACKET_TYPE_FAILURE);
	}
	else
	{
		wallet_return = newWallet(wallet_spec, name, true, seed, make_hidden);
		translateWalletError(wallet_return, 0, NULL);
	}
}

/** Return bytes of entropy from the random number generation system.
  * \param num_bytes Number of bytes of entropy to send to stream.
  */
static NOINLINE void getBytesOfEntropy(uint32_t num_bytes)
{
	uint8_t validness_byte;
	uint32_t random_bytes_index;
	uint8_t random_buffer[32];
	uint8_t buffer[4];

	if (num_bytes > 0x7FFFFFFF)
	{
		// Huge num_bytes. Probably a transmission error.
		writeString(STRINGSET_MISC, MISCSTR_INVALID_PACKET, PACKET_TYPE_FAILURE);
	}
	else
	{
		validness_byte = 1;
		random_bytes_index = 0;
		streamPutOneByte(PACKET_TYPE_SUCCESS); // type
		writeU32LittleEndian(buffer, (uint32_t)(num_bytes + 1)); // length
		writeBytesToStream(buffer, 4);
		while (num_bytes--)
		{
			if (random_bytes_index == 0)
			{
				if (getRandom256(random_buffer))
				{
					validness_byte = 0;
					// Set the buffer to all 00s so:
					// 1. The contents of RAM aren't leaked.
					// 2. It's obvious that the RNG is broken.
					memset(random_buffer, 0, sizeof(random_buffer));
				}
			}
			streamPutOneByte(random_buffer[random_bytes_index]);
			random_bytes_index = (uint32_t)((random_bytes_index + 1) & 31);
		}
		streamPutOneByte(validness_byte);
	}
}

/** Obtain master public key and chain code, then send it over the stream. */
static NOINLINE void getAndSendMasterPublicKey(void)
{
	WalletErrors wallet_return;
	PointAffine master_public_key;
	uint8_t chain_code[32];
	uint8_t buffer[97]; // 0x04 (1 byte) + x (32 bytes) + y (32 bytes) + chain code (32 bytes)

	wallet_return = getMasterPublicKey(&master_public_key, chain_code);
	buffer[0] = 0x04;
	memcpy(&(buffer[1]), master_public_key.x, 32);
	swapEndian256(&(buffer[1]));
	memcpy(&(buffer[33]), master_public_key.y, 32);
	swapEndian256(&(buffer[33]));
	memcpy(&(buffer[65]), chain_code, 32);
	translateWalletError(wallet_return, sizeof(buffer), buffer);
}

/** Read but ignore #payload_length bytes from input stream. This will also
  * set #payload_length to 0 (if everything goes well). This function is
  * useful for ensuring that the entire payload of a packet is read from the
  * stream device.
  */
static void readAndIgnoreInput(void)
{
	if (payload_length)
	{
		for (; payload_length > 0; payload_length--)
		{
			streamGetOneByte();
		}
	}
}

/** Expect the payload length of a packet to be equal to desired_length, and
  * send an error message (and read but ignore #payload_length bytes from the
  * stream) if that is not the case. This function is used to enforce the
  * payload length of packets to be compliant with the protocol described in
  * the file PROTOCOL.
  * \param desired_length The expected payload length (in bytes) of the packet
  *                       currently being received from the stream device.
  * \return false for success, true for payload length != desired_length.
  */
static bool expectLength(const uint8_t desired_length)
{
	if (payload_length != desired_length)
	{
		readAndIgnoreInput();
		writeString(STRINGSET_MISC, MISCSTR_INVALID_PACKET, PACKET_TYPE_FAILURE);
		return true; // mismatched length
	}
	else
	{
		return false; // success
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
  */
void processPacket(void)
{
	uint8_t command;
	// Technically, the length of buffer should also be >= 4, since it is used
	// in a couple of places to obtain 32 bit values. This is guaranteed by
	// the reference to WALLET_ENCRYPTION_KEY_LENGTH, since no-one in their
	// right mind would use encryption with smaller than 32 bit keys.
	uint8_t buffer[MAX(NAME_LENGTH, MAX(WALLET_ENCRYPTION_KEY_LENGTH, MAX(ENTROPY_POOL_LENGTH, UUID_LENGTH)))];
	uint8_t make_hidden_byte;
	bool make_hidden;
	bool do_encrypt;
	uint32_t wallet_spec;
	uint32_t num_addresses;
	uint32_t num_bytes;
	AddressHandle ah;
	WalletErrors wallet_return;

	command = streamGetOneByte();
	getBytesFromStream(buffer, 4);
	payload_length = readU32LittleEndian(buffer);

	// Checklist for each case:
	// 1. Have you checked or dealt with length?
	// 2. Have you fully read the input stream before writing (to avoid
	//    deadlocks)?
	// 3. Have you asked permission from the user (for potentially dangerous
	//    operations)?
	// 4. Have you checked for errors from wallet functions?
	// 5. Have you used the right check for the wallet functions?

	switch (command)
	{

	case PACKET_TYPE_PING:
		// Ping request.
		// Just throw away the data and then send response.
		readAndIgnoreInput();
		writeString(STRINGSET_MISC, MISCSTR_VERSION, PACKET_TYPE_SUCCESS);
		break;

	// Commands PACKET_TYPE_SUCCESS and PACKET_TYPE_FAILURE should never be
	// received; they are only sent.

	case PACKET_TYPE_NEW_WALLET:
		// Create new wallet.
		if (!expectLength(4 + 1 + WALLET_ENCRYPTION_KEY_LENGTH + NAME_LENGTH))
		{
			getBytesFromStream(buffer, 4);
			wallet_spec = readU32LittleEndian(buffer);
			getBytesFromStream(&make_hidden_byte, 1);
			getBytesFromStream(buffer, WALLET_ENCRYPTION_KEY_LENGTH);
			setEncryptionKey(buffer);
			getBytesFromStream(buffer, NAME_LENGTH);
			if (userDenied(ASKUSER_NUKE_WALLET))
			{
				writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, PACKET_TYPE_FAILURE);
			}
			else
			{
				if (make_hidden_byte != 0)
				{
					make_hidden = true;
				}
				else
				{
					make_hidden = false;
				}
				wallet_return = newWallet(wallet_spec, buffer, false, NULL, make_hidden);
				translateWalletError(wallet_return, 0, NULL);
			}
		}
		break;

	case PACKET_TYPE_NEW_ADDRESS:
		// Create new address in wallet.
		if (!expectLength(0))
		{
			if (userDenied(ASKUSER_NEW_ADDRESS))
			{
				writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, PACKET_TYPE_FAILURE);
			}
			else
			{
				getAndSendAddressAndPublicKey(true);
			}
		}
		break;

	case PACKET_TYPE_GET_NUM_ADDRESSES:
		// Get number of addresses in wallet.
		if (!expectLength(0))
		{
			num_addresses = getNumAddresses();
			writeU32LittleEndian(buffer, num_addresses);
			wallet_return = walletGetLastError();
			translateWalletError(wallet_return, 4, buffer);
		}
		break;

	case PACKET_TYPE_GET_ADDRESS_PUBKEY:
		// Get address and public key corresponding to an address handle.
		if (!expectLength(4))
		{
			getAndSendAddressAndPublicKey(false);
		}
		break;

	case PACKET_TYPE_SIGN_TRANSACTION:
		// Sign a transaction.
		if (payload_length <= 4)
		{
			readAndIgnoreInput();
			writeString(STRINGSET_MISC, MISCSTR_INVALID_PACKET, PACKET_TYPE_FAILURE);
		}
		else
		{
			getBytesFromStream(buffer, 4);
			ah = readU32LittleEndian(buffer);
			// Don't need to subtract 4 off payload_length because
			// getBytesFromStream() has already done so.
			validateAndSignTransaction(ah, payload_length);
			payload_length = 0;
		}
		break;

	case PACKET_TYPE_LOAD_WALLET:
		// Load wallet.
		if (!expectLength(4 + WALLET_ENCRYPTION_KEY_LENGTH))
		{
			getBytesFromStream(buffer, 4);
			wallet_spec = readU32LittleEndian(buffer);
			getBytesFromStream(buffer, WALLET_ENCRYPTION_KEY_LENGTH);
			setEncryptionKey(buffer);
			wallet_return = initWallet(wallet_spec);
			translateWalletError(wallet_return, 0, NULL);
		}
		break;

	case PACKET_TYPE_UNLOAD_WALLET:
		// Unload wallet.
		if (!expectLength(0))
		{
			prev_transaction_hash_valid = false;
			clearEncryptionKey();
			sanitiseRam();
			memset(buffer, 0xff, sizeof(buffer));
			memset(buffer, 0, sizeof(buffer));
			wallet_return = uninitWallet();
			translateWalletError(wallet_return, 0, NULL);
		}
		break;

	case PACKET_TYPE_FORMAT:
		// Format storage.
		if (!expectLength(ENTROPY_POOL_LENGTH))
		{
			getBytesFromStream(buffer, ENTROPY_POOL_LENGTH);
			if (userDenied(ASKUSER_FORMAT))
			{
				writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, PACKET_TYPE_FAILURE);
			}
			else
			{
				if (initialiseEntropyPool(buffer))
				{
					translateWalletError(WALLET_RNG_FAILURE, 0, NULL);
				}
				else
				{
					wallet_return = sanitiseNonVolatileStorage(0, 0xffffffff);
					translateWalletError(wallet_return, 0, NULL);
					uninitWallet(); // force wallet to unload
				}
			}
		}
		break;

	case PACKET_TYPE_CHANGE_KEY:
		// Change wallet encryption key.
		if (!expectLength(WALLET_ENCRYPTION_KEY_LENGTH))
		{
			getBytesFromStream(buffer, WALLET_ENCRYPTION_KEY_LENGTH);
			if (userDenied(ASKUSER_CHANGE_KEY))
			{
				writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, PACKET_TYPE_FAILURE);
			}
			else
			{
				wallet_return = changeEncryptionKey(buffer);
				translateWalletError(wallet_return, 0, NULL);
			}
		}
		break;

	case PACKET_TYPE_CHANGE_NAME:
		// Change wallet name.
		if (!expectLength(NAME_LENGTH))
		{
			getBytesFromStream(buffer, NAME_LENGTH);
			if (userDenied(ASKUSER_CHANGE_NAME))
			{
				writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, PACKET_TYPE_FAILURE);
			}
			else
			{
				wallet_return = changeWalletName(buffer);
				translateWalletError(wallet_return, 0, NULL);
			}
		}
		break;

	case PACKET_TYPE_LIST_WALLETS:
		// List wallets.
		if (!expectLength(0))
		{
			listWallets();
		}
		break;

	case PACKET_TYPE_BACKUP_WALLET:
		// Backup wallet.
		if (!expectLength(2))
		{
			getBytesFromStream(buffer, 2);
			if (userDenied(ASKUSER_BACKUP_WALLET))
			{
				writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, PACKET_TYPE_FAILURE);
			}
			else
			{
				if(buffer[0] != 0)
				{
					do_encrypt = true;
				}
				else
				{
					do_encrypt = false;
				}
				wallet_return = backupWallet(do_encrypt, buffer[1]);
				translateWalletError(wallet_return, 0, NULL);
			}
		}
		break;

	case PACKET_TYPE_RESTORE_WALLET:
		// Restore wallet.
		if (!expectLength(4 + 1 + WALLET_ENCRYPTION_KEY_LENGTH + NAME_LENGTH + SEED_LENGTH))
		{
			getBytesFromStream(buffer, 4);
			wallet_spec = readU32LittleEndian(buffer);
			getBytesFromStream(&make_hidden_byte, 1);
			getBytesFromStream(buffer, WALLET_ENCRYPTION_KEY_LENGTH);
			setEncryptionKey(buffer);
			if (make_hidden_byte != 0)
			{
				make_hidden = true;
			}
			else
			{
				make_hidden = false;
			}
			restoreWallet(wallet_spec, make_hidden);
		}
		break;

	case PACKET_TYPE_GET_DEVICE_UUID:
		// Get device UUID.
		if (!expectLength(0))
		{
			if (nonVolatileRead(buffer, ADDRESS_DEVICE_UUID, UUID_LENGTH) == NV_NO_ERROR)
			{
				wallet_return = WALLET_NO_ERROR;
			}
			else
			{
				wallet_return = WALLET_READ_ERROR;
			}
			translateWalletError(wallet_return, UUID_LENGTH, buffer);
		}
		break;

	case PACKET_TYPE_GET_ENTROPY:
		// Get an arbitrary number of bytes of entropy.
		if (!expectLength(4))
		{
			getBytesFromStream(buffer, 4);
			num_bytes = readU32LittleEndian(buffer);
			getBytesOfEntropy(num_bytes);
		}
		break;

	case PACKET_TYPE_GET_MASTER_KEY:
		// Get master public key and chain code.
		if (!expectLength(0))
		{
			if (userDenied(ASKUSER_GET_MASTER_KEY))
			{
				writeString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED, PACKET_TYPE_FAILURE);
			}
			else
			{
				getAndSendMasterPublicKey();
			}
		}
		break;

	default:
		// Unknown command.
		readAndIgnoreInput();
		writeString(STRINGSET_MISC, MISCSTR_INVALID_PACKET, PACKET_TYPE_FAILURE);
		break;

	}

#ifdef TEST_STREAM_COMM
	assert(payload_length == 0);
#endif

}

#ifdef TEST

/** Contents of a test stream (to read from). */
static uint8_t *stream;
/** 0-based index into #stream specifying which byte will be read next. */
static uint32_t stream_ptr;
/** Length of the test stream, in number of bytes. */
static uint32_t stream_length;
/** Whether to use a test stream consisting of an infinite stream of zeroes. */
static bool is_infinite_zero_stream;

/** Sets input stream (what will be read by streamGetOneByte()) to the
  * contents of a buffer.
  * \param buffer The test stream data. Each call to streamGetOneByte() will
  *               return successive bytes from this buffer.
  * \param length The length of the buffer, in number of bytes.
  */
void setTestInputStream(const uint8_t *buffer, uint32_t length)
{
	if (stream != NULL)
	{
		free(stream);
	}
	stream = malloc(length);
	memcpy(stream, buffer, length);
	stream_length = length;
	stream_ptr = 0;
	is_infinite_zero_stream = false;
}

/** Sets the input stream (what will be read by streamGetOneByte()) to an
  * infinite stream of zeroes. */
void setInfiniteZeroInputStream(void)
{
	is_infinite_zero_stream = true;
}

/** Get one byte from the contents of the buffer set by setTestInputStream().
  * \return The next byte from the test stream buffer.
  */
uint8_t streamGetOneByte(void)
{
	if (is_infinite_zero_stream)
	{
		return 0;
	}
	else
	{
		if (stream == NULL)
		{
			printf("ERROR: Tried to read a stream whose contents weren't set.\n");
			exit(1);
		}
		if (stream_ptr >= stream_length)
		{
			printf("ERROR: Tried to read past end of stream\n");
			exit(1);
		}
		return stream[stream_ptr++];
	}
}

/** Simulate the sending of a byte by displaying its value.
  * \param one_byte The byte to send.
  */
void streamPutOneByte(uint8_t one_byte)
{
	printf(" %02x", (int)one_byte);
}

/** Helper for getString().
  * \param set See getString().
  * \param spec See getString().
  * \return A pointer to the actual string.
  */
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
		case WALLET_NOT_LOADED:
			return "Wallet not loaded";
			break;
		case WALLET_INVALID_HANDLE:
			return "Invalid address handle";
			break;
		case WALLET_BACKUP_ERROR:
			return "Seed could not be written to specified device";
			break;
		case WALLET_RNG_FAILURE:
			return "Failure in random number generation system";
			break;
		case WALLET_INVALID_WALLET_NUM:
			return "Invalid wallet number specified";
			break;
		case WALLET_INVALID_OPERATION:
			return "Operation not allowed on this wallet";
			break;
		default:
			assert(0);
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
		case TRANSACTION_INVALID_AMOUNT:
			return "Invalid output amount in transaction";
			break;
		case TRANSACTION_INVALID_REFERENCE:
			return "Invalid transaction reference";
			break;
		default:
			assert(0);
		}
	}
	else
	{
		assert(0);
	}

	// GCC is smart enough to realise that the following line will never
	// be executed.
#ifndef __GNUC__
	return NULL;
#endif // #ifndef __GNUC__
}

/** Get the length of one of the device's strings.
  * \param set Specifies which set of strings to use; should be
  *            one of #StringSetEnum.
  * \param spec Specifies which string to get the character from. The
  *             interpretation of this depends on the value of set;
  *             see #StringSetEnum for clarification.
  * \return The length of the string, in number of characters.
  */
uint16_t getStringLength(StringSet set, uint8_t spec)
{
	return (uint16_t)strlen(getStringInternal(set, spec));
}

/** Obtain one character from one of the device's strings.
  * \param set Specifies which set of strings to use; should be
  *            one of #StringSetEnum.
  * \param spec Specifies which string to get the character from. The
  *             interpretation of this depends on the value of set;
  *             see #StringSetEnum for clarification.
  * \param pos The position of the character within the string; 0 means first,
  *            1 means second etc.
  * \return The character from the specified string.
  */
char getString(StringSet set, uint8_t spec, uint16_t pos)
{
	assert(pos < getStringLength(set, spec));
	return getStringInternal(set, spec)[pos];
}

/** Ask user if they want to allow some action.
  * \param command The action to ask the user about. See #AskUserCommandEnum.
  * \return false if the user accepted, true if the user denied.
  */
bool userDenied(AskUserCommand command)
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
	case ASKUSER_BACKUP_WALLET:
		printf("Do a wallet backup? ");
		break;
	case ASKUSER_RESTORE_WALLET:
		printf("Restore wallet from backup? ");
		break;
	case ASKUSER_CHANGE_KEY:
		printf("Change wallet encryption key? ");
		break;
	case ASKUSER_GET_MASTER_KEY:
		printf("Reveal master public key? ");
		break;
	default:
		assert(0);
		// GCC is smart enough to realise that the following line will never
		// be executed.
#ifndef __GNUC__
		return true;
#endif // #ifndef __GNUC__
	}
	printf("y/[n]: ");
	do
	{
		c = getchar();
	} while ((c == '\n') || (c == '\r'));
	if ((c == 'y') || (c == 'Y'))
	{
		return false;
	}
	else
	{
		return true;
	}
}

#endif // #ifdef TEST

#ifdef TEST_STREAM_COMM

/** Test stream data for: create new wallet. */
static const uint8_t test_stream_new_wallet[] = {
0x04, 0x4d, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, // wallet number
0x00, // make hidden?
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // encryption key
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x20, // name
0x66, 0x66, 0x20, 0x20, 0x20, 0x6F, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};

/** Test stream data for: create new address. */
static const uint8_t test_stream_new_address[] = {
0x05, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: get number of addresses. */
static const uint8_t test_stream_get_num_addresses[] = {
0x06, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: get address 1. */
static const uint8_t test_stream_get_address1[] = {
0x09, 0x04, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: get address 0 (which is an invalid address
  * handle). */
static const uint8_t test_stream_get_address0[] = {
0x09, 0x04, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: sign something. */
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

/** Test stream data for: format storage. */
static const uint8_t test_stream_format[] = {
0x0d, 0x20, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: load wallet using correct key. */
static const uint8_t test_stream_load_correct[] = {
0x0b, 0x24, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: load wallet using incorrect key. */
static const uint8_t test_stream_load_incorrect[] = {
0x0b, 0x24, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: unload wallet. */
static const uint8_t test_stream_unload[] = {
0x0c, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: change encryption key. */
static const uint8_t test_stream_change_key[] = {
0x0e, 0x20, 0x00, 0x00, 0x00,
0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: load with new encryption key. */
static const uint8_t test_stream_load_with_changed_key[] = {
0x0b, 0x24, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00,
0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: list wallets. */
static const uint8_t test_stream_list_wallets[] = {
0x10, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: change wallet name. */
static const uint8_t test_stream_change_name[] = {
0x0f, 0x28, 0x00, 0x00, 0x00,
0x71, 0x71, 0x71, 0x72, 0x70, 0x74, 0x20, 0x20,
0x68, 0x68, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};

/** Test stream data for: backup wallet. */
static const uint8_t test_stream_backup_wallet[] = {
0x11, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: restore wallet. */
static const uint8_t test_stream_restore_wallet[] = {
0x12, 0x8d, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, // wallet number
0x00, // make hidden?
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // encryption key
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x20, // name
0x66, 0x66, 0x20, 0x20, 0x20, 0x6F, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, // seed
0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
0x12, 0x34, 0x56, 0x00, 0x9a, 0xbc, 0xde, 0xf0,
0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
0xea, 0x11, 0x44, 0xf0, 0x0f, 0xb0, 0x0b, 0x50,
0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
0x12, 0x34, 0xde, 0xad, 0xfe, 0xed, 0xde, 0xf0};

/** Test stream data for: get device UUID. */
static const uint8_t test_stream_get_device_uuid[] = {
0x13, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: get 0 bytes of entropy. */
static const uint8_t test_stream_get_entropy0[] = {
0x14, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: get 1 byte of entropy. */
static const uint8_t test_stream_get_entropy1[] = {
0x14, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

/** Test stream data for: get 32 bytes of entropy. */
static const uint8_t test_stream_get_entropy32[] = {
0x14, 0x04, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00};

/** Test stream data for: get 100 bytes of entropy. */
static const uint8_t test_stream_get_entropy100[] = {
0x14, 0x04, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00};

/** Ping (get version). */
static const uint8_t test_stream_ping[] = {
0x00, 0x00, 0x00, 0x00, 0x00};

/** Get master public key. */
static const uint8_t test_get_master_public_key[] = {
0x15, 0x00, 0x00, 0x00, 0x00};

/** Test response of processPacket() for a given test stream.
  * \param test_stream The test stream data to use.
  * \param size The length of the test stream, in bytes.
  */
static void sendOneTestStream(const uint8_t *test_stream, uint32_t size)
{
	setTestInputStream(test_stream, size);
	processPacket();
	printf("\n");
}

/** Wrapper around sendOneTestStream() that covers its most common use
  * case (use of a constant byte array). */
#define SEND_ONE_TEST_STREAM(x)	sendOneTestStream(x, (uint32_t)sizeof(x));

int main(void)
{
	int i;

	initTests(__FILE__);

	initWalletTest();

	printf("Formatting...\n");
	SEND_ONE_TEST_STREAM(test_stream_format);
	printf("Listing wallets...\n");
	SEND_ONE_TEST_STREAM(test_stream_list_wallets);
	printf("Creating new wallet...\n");
	SEND_ONE_TEST_STREAM(test_stream_new_wallet);
	printf("Listing wallets...\n");
	SEND_ONE_TEST_STREAM(test_stream_list_wallets);
	for(i = 0; i < 4; i++)
	{
		printf("Creating new address...\n");
		SEND_ONE_TEST_STREAM(test_stream_new_address);
	}
	printf("Getting number of addresses...\n");
	SEND_ONE_TEST_STREAM(test_stream_get_num_addresses);
	printf("Getting address 1...\n");
	SEND_ONE_TEST_STREAM(test_stream_get_address1);
	printf("Getting address 0...\n");
	SEND_ONE_TEST_STREAM(test_stream_get_address0);
	printf("Signing transaction...\n");
	SEND_ONE_TEST_STREAM(test_stream_sign_tx);
	printf("Signing transaction again...\n");
	SEND_ONE_TEST_STREAM(test_stream_sign_tx);
	printf("Loading wallet using incorrect key...\n");
	SEND_ONE_TEST_STREAM(test_stream_load_incorrect);
	printf("Loading wallet using correct key...\n");
	SEND_ONE_TEST_STREAM(test_stream_load_correct);
	printf("Changing wallet key...\n");
	SEND_ONE_TEST_STREAM(test_stream_change_key);
	printf("Unloading wallet...\n");
	SEND_ONE_TEST_STREAM(test_stream_unload);
	printf("Loading wallet using changed key...\n");
	SEND_ONE_TEST_STREAM(test_stream_load_with_changed_key);
	printf("Changing name...\n");
	SEND_ONE_TEST_STREAM(test_stream_change_name);
	printf("Listing wallets...\n");
	SEND_ONE_TEST_STREAM(test_stream_list_wallets);
	printf("Backing up a wallet...\n");
	SEND_ONE_TEST_STREAM(test_stream_backup_wallet);
	printf("Restoring a wallet...\n");
	SEND_ONE_TEST_STREAM(test_stream_restore_wallet);
	printf("Getting device UUID...\n");
	SEND_ONE_TEST_STREAM(test_stream_get_device_uuid);
	printf("Getting 0 bytes of entropy...\n");
	SEND_ONE_TEST_STREAM(test_stream_get_entropy0);
	printf("Getting 1 byte of entropy...\n");
	SEND_ONE_TEST_STREAM(test_stream_get_entropy1);
	printf("Getting 32 bytes of entropy...\n");
	SEND_ONE_TEST_STREAM(test_stream_get_entropy32);
	printf("Getting 100 bytes of entropy...\n");
	SEND_ONE_TEST_STREAM(test_stream_get_entropy100);
	printf("Pinging...\n");
	SEND_ONE_TEST_STREAM(test_stream_ping);
	printf("Getting master public key...\n");
	SEND_ONE_TEST_STREAM(test_get_master_public_key);

	finishTests();
	exit(0);
}

#endif // #ifdef TEST_STREAM_COMM


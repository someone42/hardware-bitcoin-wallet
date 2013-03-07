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
#include "pb.h"
#include "pb_decode.h"
#include "pb_encode.h"
#include "messages.pb.h"

// Prototypes for forward-referenced functions.
bool mainInputStreamCallback(pb_istream_t *stream, uint8_t *buf, size_t count);
bool mainOutputStreamCallback(pb_ostream_t *stream, const uint8_t *buf, size_t count);
static void writeFailureString(StringSet set, uint8_t spec);

/** Maximum size (in bytes) of any protocol buffer message send by functions
  * in this file. */
#define MAX_SEND_SIZE			255

/** Because stdlib.h might not be included, NULL might be undefined. NULL
  * is only used as a placeholder pointer for translateWalletError() if
  * there is no appropriate pointer. */
#ifndef NULL
#define NULL ((void *)0) 
#endif // #ifndef NULL

/** Union of field buffers for all protocol buffer messages. They're placed
  * in a union to make memory access more efficient, since the functions in
  * this file only need to deal with one message at any one time. */
union MessageBufferUnion
{
	Ping ping;
	PingResponse ping_response;
};

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

/** String set (see getString()) of next string to be outputted by
  * writeStringCallback(). */
static StringSet next_set;
/** String specifier (see getString()) of next string to be outputted by
  * writeStringCallback(). */
static uint8_t next_spec;

/** nanopb input stream which uses mainInputStreamCallback() as a stream
  * callback. */
pb_istream_t main_input_stream = {&mainInputStreamCallback, NULL, 0, NULL};
/** nanopb output stream which uses mainOutputStreamCallback() as a stream
  * callback. */
pb_ostream_t main_output_stream = {&mainOutputStreamCallback, NULL, 0, 0};

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

/** Write a number of bytes to the output stream.
  * \param buffer The array of bytes to be written.
  * \param length The number of bytes to write.
  */
static void writeBytesToStream(const uint8_t *buffer, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++)
	{
		streamPutOneByte(buffer[i]);
	}
}

/** nanopb input stream callback which uses streamGetOneByte() to get the
  * requested bytes.
  * \param stream Input stream object that issued the callback.
  * \param buf Buffer to fill with requested bytes.
  * \param count Requested number of bytes.
  * \return true on success, false on failure (nanopb convention).
  */
bool mainInputStreamCallback(pb_istream_t *stream, uint8_t *buf, size_t count)
{
	size_t i;

	if (buf == NULL)
	{
		fatalError(); // this should never happen
	}
	for (i = 0; i < count; i++)
	{
		if (payload_length == 0)
		{
			// Attempting to read past end of payload.
			stream->bytes_left = 0;
			return false;
		}
		buf[i] = streamGetOneByte();
		payload_length--;
	}
	return true;
}

/** nanopb output stream callback which uses streamPutOneByte() to send a byte
  * buffer.
  * \param stream Output stream object that issued the callback.
  * \param buf Buffer with bytes to send.
  * \param count Number of bytes to send.
  * \return true on success, false on failure (nanopb convention).
  */
bool mainOutputStreamCallback(pb_ostream_t *stream, const uint8_t *buf, size_t count)
{
	writeBytesToStream(buf, count);
	return true;
}

/** Read but ignore #payload_length bytes from input stream. This will also
  * set #payload_length to 0 (if everything goes well). This function is
  * useful for ensuring that the entire payload of a packet is read from the
  * stream device.
  */
static void readAndIgnoreInput(void)
{
	if (payload_length > 0)
	{
		for (; payload_length > 0; payload_length--)
		{
			streamGetOneByte();
		}
	}
}

/** Receive a message from the stream #main_input_stream.
  * \param fields Field description array.
  * \param dest_struct Where field data will be stored.
  * \return false on success, true if a parse error occurred.
  */
static bool receiveMessage(const pb_field_t fields[], void *dest_struct)
{
	bool r;

	r = pb_decode(&main_input_stream, fields, dest_struct);
	// In order for the message to be considered valid, it must also occupy
	// the entire payload of the packet.
	if ((payload_length > 0) || !r)
	{
		readAndIgnoreInput();
		writeFailureString(STRINGSET_MISC, MISCSTR_INVALID_PACKET);
		return true;
	}
	else
	{
		return false;
	}
}

/** Send a packet.
  * \param command The message ID of the packet.
  * \param fields Field description array.
  * \param src_struct Field data which will be serialised and sent.
  */
static void sendPacket(uint16_t command, const pb_field_t fields[], const void *src_struct)
{
	uint8_t buffer[4];
	pb_ostream_t substream;

	// Use a non-writing substream to get the length of the message without
	// storing it anywhere.
	substream.callback = NULL;
	substream.state = NULL;
	substream.max_size = MAX_SEND_SIZE;
	substream.bytes_written = 0;
	if (!pb_encode(&substream, fields, src_struct))
	{
		fatalError();
	}

	// Send packet header.
	streamPutOneByte('#');
	streamPutOneByte('#');
	streamPutOneByte((uint8_t)(command >> 8));
	streamPutOneByte((uint8_t)command);
	writeU32BigEndian(buffer, substream.bytes_written);
	writeBytesToStream(buffer, 4);
	// Send actual message.
	main_output_stream.bytes_written = 0;
	main_output_stream.max_size = substream.bytes_written;
	if (!pb_encode(&main_output_stream, fields, src_struct))
	{
		fatalError();
	}
}

/** nanopb field callback which will write the string specified
  * by #next_set and #next_spec.
  * \param stream Output stream to write to.
  * \param field Field which contains the string.
  * \param arg Unused.
  * \return true on success, false on failure (nanopb convention).
  */
bool writeStringCallback(pb_ostream_t *stream, const pb_field_t *field, const void *arg)
{
	uint16_t i;
	uint16_t length;
	char c;

	length = getStringLength(next_set, next_spec);
	if (!pb_encode_tag_for_field(stream, field))
	{
		return false;
	}
	// Cannot use pb_encode_string() because it expects a pointer to the
	// contents of an entire string; getString() does not return such a
	// pointer.
	if (!pb_encode_varint(stream, (uint64_t)length))
	{
		return false;
	}
	for (i = 0; i < length; i++)
	{
		c = getString(next_set, next_spec, i);
		if (!pb_write(stream, (uint8_t *)&c, 1))
		{
			return false;
		}
	}
	return true;
}

/** Sends a Failure message with the specified error message.
  * \param set See getString().
  * \param spec See getString().
  */
static void writeFailureString(StringSet set, uint8_t spec)
{
	Failure message_buffer;

	next_set = set;
	next_spec = spec;
	message_buffer.error_message.funcs.encode = &writeStringCallback;
	sendPacket(PACKET_TYPE_FAILURE, Failure_fields, &message_buffer);
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
		writeFailureString(STRINGSET_WALLET, (uint8_t)r);
	}
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
		writeFailureString(STRINGSET_TRANSACTION, (uint8_t)r);
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
			writeFailureString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED);
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
		writeFailureString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED);
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
		writeFailureString(STRINGSET_MISC, MISCSTR_INVALID_PACKET);
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
	uint16_t command;
	uint8_t buffer[4];
	union MessageBufferUnion message_buffer;
	bool receive_failure;

	// Receive packet header.
	getBytesFromStream(buffer, 2);
	if ((buffer[0] != '#') || (buffer[1] != '#'))
	{
		fatalError(); // invalid header
	}
	getBytesFromStream(buffer, 2);
	command = (uint16_t)(((uint16_t)buffer[0] << 8) | ((uint16_t)buffer[1]));
	getBytesFromStream(buffer, 4);
	payload_length = readU32BigEndian(buffer);
	// TODO: size_t not generally uint32_t
	main_input_stream.bytes_left = payload_length;

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
		message_buffer.ping.greeting.funcs.decode = NULL; // throw away greeting
		receive_failure = receiveMessage(Ping_fields, &(message_buffer.ping));
		if (!receive_failure)
		{
			next_set = STRINGSET_MISC;
			next_spec = MISCSTR_VERSION;
			message_buffer.ping_response.version.funcs.encode = &writeStringCallback;
			sendPacket(PACKET_TYPE_PING_RESPONSE, PingResponse_fields, &(message_buffer.ping_response));
		}
		break;

	default:
		// Unknown command.
		readAndIgnoreInput();
		writeFailureString(STRINGSET_MISC, MISCSTR_INVALID_PACKET);
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

/** This will be called whenever something very unexpected occurs. This
  * function must not return. */
void fatalError(void)
{
	printf("************\n");
	printf("FATAL ERROR!\n");
	printf("************\n");
	exit(1);
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
0x23, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0a, 0x03, 0x4d, 0x6f, 0x6f};

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
	initTests(__FILE__);

	initWalletTest();

	printf("Pinging...\n");
	SEND_ONE_TEST_STREAM(test_stream_ping);

	finishTests();
	exit(0);
}

#endif // #ifdef TEST_STREAM_COMM


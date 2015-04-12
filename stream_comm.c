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
#include <stdio.h>
#include <assert.h>
#endif // #ifdef TEST

#ifdef TEST_STREAM_COMM
#include <string.h>
#endif // #ifdef TEST_STREAM_COMM

#include <stdlib.h> // for definition of NULL
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
#include "sha256.h"
#include "transaction.h"

#ifdef TEST_STREAM_COMM
#include "test_helpers.h"
#endif // #ifdef TEST_STREAM_COMM

// Prototypes for forward-referenced functions.
bool mainInputStreamCallback(pb_istream_t *stream, uint8_t *buf, size_t count);
bool mainOutputStreamCallback(pb_ostream_t *stream, const uint8_t *buf, size_t count);
static void writeFailureString(StringSet set, uint8_t spec);
bool hashFieldCallback(pb_istream_t *stream, const pb_field_t *field, void **arg);

/** Maximum size (in bytes) of any protocol buffer message sent by functions
  * in this file. */
#define MAX_SEND_SIZE			255

/** Union of field buffers for all protocol buffer messages. They're placed
  * in a union to make memory access more efficient, since the functions in
  * this file only need to deal with one message at any one time. */
union MessageBufferUnion
{
	Initialize initialize;
	Features features;
	Ping ping;
	PingResponse ping_response;
	DeleteWallet delete_wallet;
	NewWallet new_wallet;
	NewAddress new_address;
	GetNumberOfAddresses get_number_of_addresses;
	NumberOfAddresses number_of_addresses;
	GetAddressAndPublicKey get_address_and_public_key;
	LoadWallet load_wallet;
	FormatWalletArea format_wallet_area;
	ChangeEncryptionKey change_encryption_key;
	ChangeWalletName change_wallet_name;
	ListWallets list_wallets;
	Wallets wallets;
	BackupWallet backup_wallet;
	RestoreWallet restore_wallet;
	GetDeviceUUID get_device_uuid;
	DeviceUUID device_uuid;
	GetEntropy get_entropy;
	GetMasterPublicKey get_master_public_key;
	MasterPublicKey master_public_key;
};

/** Determines the string that writeStringCallback() will write. */
struct StringSetAndSpec
{
	/** String set (see getString()) of string to be outputted. */
	StringSet next_set;
	/** String specifier (see getString()) of string to be outputted. */
	uint8_t next_spec;
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

/** Argument for writeStringCallback() which determines what string it will
  * write. Don't put this on the stack, otherwise the consequences of a
  * dangling pointer are less secure. */
static struct StringSetAndSpec string_arg;
/** Alternate copy of #string_arg, for when more than one string needs to be
  * written. */
static struct StringSetAndSpec string_arg_alt;
/** Current number of wallets; used for the listWalletsCallback() callback
  * function. */
static uint32_t number_of_wallets;
/** Pointer to bytes of entropy to send to the host; used for
  * the getEntropyCallback() callback function. */
static uint8_t *entropy_buffer;
/** Number of bytes of entropy to send to the host; used for
  * the getEntropyCallback() callback function. */
static size_t num_entropy_bytes;
/** Storage for fields of SignTransaction message. Needed for the
  * signTransactionCallback() callback function. */
static SignTransaction sign_transaction;
/** Double SHA-256 of a field parsed by hashFieldCallback(). */
static uint8_t field_hash[32];
/** Whether #field_hash has been set. */
static bool field_hash_set;

/** Number of valid bytes in #session_id. */
static size_t session_id_length;
/** Arbitrary host-supplied bytes which are sent to the host to assure it that
  * a reset hasn't occurred. */
static uint8_t session_id[64];

/** nanopb input stream which uses mainInputStreamCallback() as a stream
  * callback. */
pb_istream_t main_input_stream = {&mainInputStreamCallback, NULL, 0, NULL};
/** nanopb output stream which uses mainOutputStreamCallback() as a stream
  * callback. */
pb_ostream_t main_output_stream = {&mainOutputStreamCallback, NULL, 0, 0, NULL};

#ifdef TEST_STREAM_COMM
/** When sending test packets, the OTP stored here will be used instead of
  * a generated OTP. This allows the test cases to be static. */
static char test_otp[OTP_LENGTH] = {'1', '2', '3', '4', '\0'};
#endif // #ifdef TEST_STREAM_COMM

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
  * \param message_id The message ID of the packet.
  * \param fields Field description array.
  * \param src_struct Field data which will be serialised and sent.
  */
static void sendPacket(uint16_t message_id, const pb_field_t fields[], const void *src_struct)
{
	uint8_t buffer[4];
	pb_ostream_t substream;

#ifdef TEST_STREAM_COMM
	// From PROTOCOL, the current received packet must be fully consumed
	// before any response can be sent.
	assert(payload_length == 0);
#endif
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
	streamPutOneByte((uint8_t)(message_id >> 8));
	streamPutOneByte((uint8_t)message_id);
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

/** nanopb field callback which will write the string specified by arg.
  * \param stream Output stream to write to.
  * \param field Field which contains the string.
  * \param arg Pointer to #StringSetAndSpec structure specifying the string
  *            to write.
  * \return true on success, false on failure (nanopb convention).
  */
bool writeStringCallback(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	uint16_t i;
	uint16_t length;
	char c;
	struct StringSetAndSpec **ptr_arg_s;
	struct StringSetAndSpec *arg_s;

	ptr_arg_s = (struct StringSetAndSpec **)arg;
	if (ptr_arg_s == NULL)
	{
		fatalError(); // this should never happen
	}
	arg_s = *ptr_arg_s;
	if (arg_s == NULL)
	{
		fatalError(); // this should never happen
	}
	length = getStringLength(arg_s->next_set, arg_s->next_spec);
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
		c = getString(arg_s->next_set, arg_s->next_spec, i);
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
	uint32_t code;

	string_arg.next_set = set;
	string_arg.next_spec = spec;
	code = (uint32_t)spec & 0xffff;
	code |= ((uint32_t)set & 0xffff) << 16;
	message_buffer.error_code = code;
	message_buffer.error_message.funcs.encode = &writeStringCallback;
	message_buffer.error_message.arg = &string_arg;
	sendPacket(PACKET_TYPE_FAILURE, Failure_fields, &message_buffer);
}

/** Translates a return value from one of the wallet functions into a Success
  * or Failure response packet which is written to the stream.
  * \param r The return value from the wallet function.
  */
static void translateWalletError(WalletErrors r)
{
	Success message_buffer;

	if (r == WALLET_NO_ERROR)
	{
		sendPacket(PACKET_TYPE_SUCCESS, Success_fields, &message_buffer);
	}
	else
	{
		writeFailureString(STRINGSET_WALLET, (uint8_t)r);
	}
}

/** Receive packet header.
  * \return Message ID (i.e. command type) of packet.
  */
static uint16_t receivePacketHeader(void)
{
	uint8_t buffer[4];
	uint16_t message_id;

	getBytesFromStream(buffer, 2);
	if ((buffer[0] != '#') || (buffer[1] != '#'))
	{
		fatalError(); // invalid header
	}
	getBytesFromStream(buffer, 2);
	message_id = (uint16_t)(((uint16_t)buffer[0] << 8) | ((uint16_t)buffer[1]));
	getBytesFromStream(buffer, 4);
	payload_length = readU32BigEndian(buffer);
	// TODO: size_t not generally uint32_t
	main_input_stream.bytes_left = payload_length;
	return message_id;
}

/** Begin ButtonRequest interjection. This asks the host whether it is okay
  * to prompt the user and wait for a button press.
  * \param command The action to ask the user about. See #AskUserCommandEnum.
  * \return false if the user accepted, true if the user or host denied.
  */
static bool buttonInterjection(AskUserCommand command)
{
	uint16_t message_id;
	ButtonRequest button_request;
	ButtonAck button_ack;
	ButtonCancel button_cancel;
	bool receive_failure;

	memset(&button_request, 0, sizeof(button_request));
	sendPacket(PACKET_TYPE_BUTTON_REQUEST, ButtonRequest_fields, &button_request);
	message_id = receivePacketHeader();
	if (message_id == PACKET_TYPE_BUTTON_ACK)
	{
		// Host will allow button press.
		receive_failure = receiveMessage(ButtonAck_fields, &button_ack);
		if (receive_failure)
		{
			return true;
		}
		else
		{
			if (userDenied(command))
			{
				writeFailureString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED_USER);
				return true;
			}
			else
			{
				return false;
			}
		}
	}
	else if (message_id == PACKET_TYPE_BUTTON_CANCEL)
	{
		// Host will not allow button press. The only way to safely deal
		// with this is to unconditionally deny permission for the
		// requested action.
		receive_failure = receiveMessage(ButtonCancel_fields, &button_cancel);
		if (!receive_failure)
		{
			writeFailureString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED_HOST);
		}
		return true;
	}
	else
	{
		// Unexpected message.
		readAndIgnoreInput();
		writeFailureString(STRINGSET_MISC, MISCSTR_UNEXPECTED_PACKET);
		return true;
	}
}

/** Begin PinRequest interjection. This asks the host to submit a password
  * to the device. If the host does submit a password, then #field_hash_set
  * will be set and #field_hash updated.
  * \return false if the host submitted a password, true on error.
  */
static bool pinInterjection(void)
{
	uint16_t message_id;
	PinRequest pin_request;
	PinAck pin_ack;
	PinCancel pin_cancel;
	bool receive_failure;

	memset(&pin_request, 0, sizeof(pin_request));
	sendPacket(PACKET_TYPE_PIN_REQUEST, PinRequest_fields, &pin_request);
	message_id = receivePacketHeader();
	if (message_id == PACKET_TYPE_PIN_ACK)
	{
		// Host has just sent password.
		field_hash_set = false;
		memset(field_hash, 0, sizeof(field_hash));
		pin_ack.password.funcs.decode = &hashFieldCallback;
		pin_ack.password.arg = NULL;
		receive_failure = receiveMessage(PinAck_fields, &pin_ack);
		if (receive_failure)
		{
			return true;
		}
		else
		{
			if (!field_hash_set)
			{
				fatalError(); // should never happen since password is a required field
			}
			return false;
		}
	}
	else if (message_id == PACKET_TYPE_PIN_CANCEL)
	{
		// Host does not want to send password.
		receive_failure = receiveMessage(PinCancel_fields, &pin_cancel);
		if (!receive_failure)
		{
			writeFailureString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED_HOST);
		}
		return true;
	}
	else
	{
		// Unexpected message.
		readAndIgnoreInput();
		writeFailureString(STRINGSET_MISC, MISCSTR_UNEXPECTED_PACKET);
		return true;
	}
}

/** Begin OtpRequest interjection. This asks the host to submit a one-time
  * password that is displayed on the device.
  * \return false if the host submitted a matching password, true on error.
  */
static bool otpInterjection(AskUserCommand command)
{
	uint16_t message_id;
	OtpRequest otp_request;
	OtpAck otp_ack;
	OtpCancel otp_cancel;
	bool receive_failure;
	char otp[OTP_LENGTH];

	generateInsecureOTP(otp);
#ifdef TEST_STREAM_COMM
	memcpy(otp, test_otp, OTP_LENGTH);
#endif // #ifdef TEST_STREAM_COMM
	displayOTP(command, otp);
	memset(&otp_request, 0, sizeof(otp_request));
	sendPacket(PACKET_TYPE_OTP_REQUEST, OtpRequest_fields, &otp_request);
	message_id = receivePacketHeader();
	clearOTP();
	if (message_id == PACKET_TYPE_OTP_ACK)
	{
		// Host has just sent OTP.
		memset(&otp_ack, 0, sizeof(otp_ack));
		receive_failure = receiveMessage(OtpAck_fields, &otp_ack);
		if (receive_failure)
		{
			return true;
		}
		else
		{
			if (memcmp(otp, otp_ack.otp, MIN(OTP_LENGTH, sizeof(otp_ack.otp))))
			{
				writeFailureString(STRINGSET_MISC, MISCSTR_OTP_MISMATCH);
				return true;
			}
			else
			{
				return false;
			}
		}
	}
	else if (message_id == PACKET_TYPE_OTP_CANCEL)
	{
		// Host does not want to send OTP.
		receive_failure = receiveMessage(OtpCancel_fields, &otp_cancel);
		if (!receive_failure)
		{
			writeFailureString(STRINGSET_MISC, MISCSTR_PERMISSION_DENIED_HOST);
		}
		return true;
	}
	else
	{
		// Unexpected message.
		readAndIgnoreInput();
		writeFailureString(STRINGSET_MISC, MISCSTR_UNEXPECTED_PACKET);
		return true;
	}
}

/** nanopb field callback for signature data of SignTransaction message. This
  * does (or more accurately, delegates) all the "work" of transaction
  * signing: parsing the transaction, asking the user for approval, generating
  * the signature and sending the signature.
  * \param stream Input stream to read from.
  * \param field Field which contains the signature data.
  * \param arg Unused.
  * \return true on success, false on failure (nanopb convention).
  */
bool signTransactionCallback(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
	AddressHandle ah;
	bool approved;
	bool permission_denied;
	TransactionErrors r;
	WalletErrors wallet_return;
	uint8_t transaction_hash[32];
	uint8_t sig_hash[32];
	uint8_t private_key[32];
	uint8_t signature_length;
	Signature message_buffer;

	// Validate transaction and calculate hashes of it.
	clearOutputsSeen();
	r = parseTransaction(sig_hash, transaction_hash, stream->bytes_left);
	// parseTransaction() always reads transaction_length bytes, even if parse
	// errors occurs. These next two lines are a bit of a hack to account for
	// differences between streamGetOneByte() and pb_read(stream, buf, 1).
	// The intention is that transaction.c doesn't have to know anything about
	// protocol buffers.
	payload_length -= stream->bytes_left;
	stream->bytes_left = 0;
	if (r != TRANSACTION_NO_ERROR)
	{
		// Transaction parse error.
		writeFailureString(STRINGSET_TRANSACTION, (uint8_t)r);
		return true;
	}

	// Get permission from user.
	approved = false;
	// Does transaction_hash match previous approved transaction?
	if (prev_transaction_hash_valid)
	{
		if (bigCompare(transaction_hash, prev_transaction_hash) == BIGCMP_EQUAL)
		{
			approved = true;
		}
	}
	if (!approved)
	{
		// Need to explicitly get permission from user.
		// The call to parseTransaction() should have logged all the outputs
		// to the user interface.
		permission_denied = buttonInterjection(ASKUSER_SIGN_TRANSACTION);
		if (!permission_denied)
		{
			// User approved transaction.
			approved = true;
			memcpy(prev_transaction_hash, transaction_hash, 32);
			prev_transaction_hash_valid = true;
		}
	} // if (!approved)
	if (approved)
	{
		// Okay to sign transaction.
		signature_length = 0;
		ah = sign_transaction.address_handle;
		if (getPrivateKey(private_key, ah) == WALLET_NO_ERROR)
		{
			if (sizeof(message_buffer.signature_data.bytes) < MAX_SIGNATURE_LENGTH)
			{
				// This should never happen.
				fatalError();
			}
			signTransaction(message_buffer.signature_data.bytes, &signature_length, sig_hash, private_key);
			message_buffer.signature_data.size = signature_length;
			sendPacket(PACKET_TYPE_SIGNATURE, Signature_fields, &message_buffer);
		}
		else
		{
			wallet_return = walletGetLastError();
			translateWalletError(wallet_return);
		}
	}
	return true;
}

/** Send a packet containing an address and its corresponding public key.
  * This can generate new addresses as well as obtain old addresses. Both
  * use cases were combined into one function because they involve similar
  * processes.
  * \param generate_new If this is true, a new address will be generated
  *                     and the address handle of the generated address will
  *                     be prepended to the output packet.
  *                     If this is false, the address handle specified by ah
  *                     will be used.
  * \param ah Address handle to use (if generate_new is false).
  */
static NOINLINE void getAndSendAddressAndPublicKey(bool generate_new, AddressHandle ah)
{
	Address message_buffer;
	PointAffine public_key;
	WalletErrors r;

	message_buffer.address.size = 20;
	if (generate_new)
	{
		r = WALLET_NO_ERROR;
		ah = makeNewAddress(message_buffer.address.bytes, &public_key);
		if (ah == BAD_ADDRESS_HANDLE)
		{
			r = walletGetLastError();
		}
	}
	else
	{
		r = getAddressAndPublicKey(message_buffer.address.bytes, &public_key, ah);
	}

	if (r == WALLET_NO_ERROR)
	{
		message_buffer.address_handle = ah;
		if (sizeof(message_buffer.public_key.bytes) < ECDSA_MAX_SERIALISE_SIZE) // sanity check
		{
			fatalError();
			return;
		}
		message_buffer.public_key.size = ecdsaSerialise(message_buffer.public_key.bytes, &public_key, true);
		sendPacket(PACKET_TYPE_ADDRESS_PUBKEY, Address_fields, &message_buffer);
	}
	else
	{
		translateWalletError(r);
	} // end if (r == WALLET_NO_ERROR)
}

/** nanopb field callback which will write repeated WalletInfo messages; one
  * for each wallet on the device.
  * \param stream Output stream to write to.
  * \param field Field which contains the WalletInfo submessage.
  * \param arg Unused.
  * \return true on success, false on failure (nanopb convention).
  */
bool listWalletsCallback(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	uint32_t version;
	uint32_t i;
	WalletInfo message_buffer;

	for (i = 0; i < number_of_wallets; i++)
	{
		message_buffer.wallet_number = i;
		message_buffer.wallet_name.size = NAME_LENGTH;
		message_buffer.wallet_uuid.size = UUID_LENGTH;
		if (getWalletInfo(
			&version,
			message_buffer.wallet_name.bytes,
			message_buffer.wallet_uuid.bytes,
			i) != WALLET_NO_ERROR)
		{
			// It's too late to return an error message, so cut off the
			// array now.
			return true;
		}
		if (version != VERSION_NOTHING_THERE)
		{
			if (!pb_encode_tag_for_field(stream, field))
			{
				return false;
			}
			if (!pb_encode_submessage(stream, WalletInfo_fields, &message_buffer))
			{
				return false;
			}
		}
	}
	return true;
}

/** nanopb field callback which will write out the contents
  * of #entropy_buffer.
  * \param stream Output stream to write to.
  * \param field Field which contains the the entropy bytes.
  * \param arg Unused.
  * \return true on success, false on failure (nanopb convention).
  */
bool getEntropyCallback(pb_ostream_t *stream, const pb_field_t *field, void * const *arg)
{
	if (entropy_buffer == NULL)
	{
		return false;
	}
	if (!pb_encode_tag_for_field(stream, field))
	{
		return false;
	}
	if (!pb_encode_string(stream, entropy_buffer, num_entropy_bytes))
	{
		return false;
	}
	return true;
}

/** Return bytes of entropy from the random number generation system.
  * \param num_bytes Number of bytes of entropy to send to stream.
  */
static NOINLINE void getBytesOfEntropy(uint32_t num_bytes)
{
	Entropy message_buffer;
	unsigned int random_bytes_index;
	uint8_t random_bytes[1024]; // must be multiple of 32 bytes large

	if (num_bytes > sizeof(random_bytes))
	{
		writeFailureString(STRINGSET_MISC, MISCSTR_PARAM_TOO_LARGE);
		return;
	}

	// All bytes of entropy must be collected before anything can be sent.
	// This is because it is only safe to send those bytes if every call
	// to getRandom256() succeeded.
	random_bytes_index = 0;
	num_entropy_bytes = 0;
	while (num_bytes--)
	{
		if (random_bytes_index == 0)
		{
			if (getRandom256(&(random_bytes[num_entropy_bytes])))
			{
				translateWalletError(WALLET_RNG_FAILURE);
				return;
			}
		}
		num_entropy_bytes++;
		random_bytes_index++;
		random_bytes_index &= 31;
	}
	message_buffer.entropy.funcs.encode = &getEntropyCallback;
	entropy_buffer = random_bytes;
	sendPacket(PACKET_TYPE_ENTROPY, Entropy_fields, &message_buffer);
	num_entropy_bytes = 0;
	entropy_buffer = NULL;
}

/** nanopb field callback which calculates the double SHA-256 of an arbitrary
  * number of bytes. This is useful if we don't care about the contents of a
  * field but want to compress an arbitrarily-sized field into a fixed-length
  * variable.
  * \param stream Input stream to read from.
  * \param field Field which contains an arbitrary number of bytes.
  * \param arg Unused.
  * \return true on success, false on failure (nanopb convention).
  */
bool hashFieldCallback(pb_istream_t *stream, const pb_field_t *field, void **arg)
{
	uint8_t one_byte;
	HashState hs;

	sha256Begin(&hs);
	while (stream->bytes_left > 0)
    {
		if (!pb_read(stream, &one_byte, 1))
		{
			return false;
		}
        sha256WriteByte(&hs, one_byte);
    }
	sha256FinishDouble(&hs);
	writeHashToByteArray(field_hash, &hs, true);
	field_hash_set = true;
    return true;
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
	uint16_t message_id;
	union MessageBufferUnion message_buffer;
	PointAffine master_public_key;
	bool receive_failure;
	bool permission_denied;
	bool invalid_otp;
	unsigned int password_length;
	WalletErrors wallet_return;
	char ping_greeting[sizeof(message_buffer.ping.greeting)];
	bool has_ping_greeting;

	message_id = receivePacketHeader();

	// Checklist for each case:
	// 1. Have you checked or dealt with length?
	// 2. Have you fully read the input stream before writing (to avoid
	//    deadlocks)?
	// 3. Have you asked permission from the user (for potentially dangerous
	//    operations)?
	// 4. Have you checked for errors from wallet functions?
	// 5. Have you used the right check for the wallet functions?

	memset(&message_buffer, 0, sizeof(message_buffer));

	switch (message_id)
	{

	case PACKET_TYPE_INITIALIZE:
		// Reset state and report features.
		session_id_length = 0; // just in case receiveMessage() fails
		receive_failure = receiveMessage(Initialize_fields, &(message_buffer.initialize));
		if (!receive_failure)
		{
			session_id_length = message_buffer.initialize.session_id.size;
			if (session_id_length >= sizeof(session_id))
			{
				fatalError(); // sanity check failed
			}
			memcpy(session_id, message_buffer.initialize.session_id.bytes, session_id_length);
			prev_transaction_hash_valid = false;
			sanitiseRam();
			wallet_return = uninitWallet();
			if (wallet_return == WALLET_NO_ERROR)
			{
				memset(&message_buffer, 0, sizeof(message_buffer));
				message_buffer.features.echoed_session_id.size = session_id_length;
				if (session_id_length >= sizeof(message_buffer.features.echoed_session_id.bytes))
				{
					fatalError(); // sanity check failed
				}
				memcpy(message_buffer.features.echoed_session_id.bytes, session_id, session_id_length);
				string_arg.next_set = STRINGSET_MISC;
				string_arg.next_spec = MISCSTR_VENDOR;
				message_buffer.features.vendor.funcs.encode = &writeStringCallback;
				message_buffer.features.vendor.arg = &string_arg;
				message_buffer.features.has_major_version = true;
				message_buffer.features.major_version = VERSION_MAJOR;
				message_buffer.features.has_minor_version = true;
				message_buffer.features.minor_version = VERSION_MINOR;
				string_arg_alt.next_set = STRINGSET_MISC;
				string_arg_alt.next_spec = MISCSTR_CONFIG;
				message_buffer.features.config.funcs.encode = &writeStringCallback;
				message_buffer.features.config.arg = &string_arg_alt;
				message_buffer.features.has_otp = true;
				message_buffer.features.otp = true;
				message_buffer.features.has_pin = true;
				message_buffer.features.pin = true;
				message_buffer.features.has_spv = true;
				message_buffer.features.spv = true;
				message_buffer.features.algo_count = 1;
				message_buffer.features.algo[0] = Algorithm_BIP32;
				message_buffer.features.has_debug_link = true;
				message_buffer.features.debug_link = false;
				sendPacket(PACKET_TYPE_FEATURES, Features_fields, &(message_buffer.features));
			}
			else
			{
				translateWalletError(wallet_return);
			}
		}
		break;

	case PACKET_TYPE_PING:
		// Ping request.
		receive_failure = receiveMessage(Ping_fields, &(message_buffer.ping));
		if (!receive_failure)
		{
			has_ping_greeting = message_buffer.ping.has_greeting;
			if (sizeof(message_buffer.ping.greeting) != sizeof(ping_greeting))
			{
				fatalError(); // sanity check failed
			}
			if (has_ping_greeting)
			{
				memcpy(ping_greeting, message_buffer.ping.greeting, sizeof(ping_greeting));
			}
			ping_greeting[sizeof(ping_greeting) - 1] = '\0'; // ensure that string is terminated
			// Generate ping response message.
			memset(&message_buffer, 0, sizeof(message_buffer));
			message_buffer.ping_response.has_echoed_greeting = has_ping_greeting;
			if (sizeof(ping_greeting) != sizeof(message_buffer.ping_response.echoed_greeting))
			{
				fatalError(); // sanity check failed
			}
			if (has_ping_greeting)
			{
				memcpy(message_buffer.ping_response.echoed_greeting, ping_greeting, sizeof(message_buffer.ping_response.echoed_greeting));
			}
			message_buffer.ping_response.echoed_session_id.size = session_id_length;
			if (session_id_length >= sizeof(message_buffer.ping_response.echoed_session_id.bytes))
			{
				fatalError(); // sanity check failed
			}
			memcpy(message_buffer.ping_response.echoed_session_id.bytes, session_id, session_id_length);
			sendPacket(PACKET_TYPE_PING_RESPONSE, PingResponse_fields, &(message_buffer.ping_response));
		}
		break;

	case PACKET_TYPE_DELETE_WALLET:
		// Delete existing wallet.
		receive_failure = receiveMessage(DeleteWallet_fields, &(message_buffer.delete_wallet));
		if (!receive_failure)
		{
			permission_denied = buttonInterjection(ASKUSER_DELETE_WALLET);
			if (!permission_denied)
			{
				invalid_otp = otpInterjection(ASKUSER_DELETE_WALLET);
				if (!invalid_otp)
				{
					wallet_return = deleteWallet(message_buffer.delete_wallet.wallet_handle);
					translateWalletError(wallet_return);
				}
			}
		}
		break;

	case PACKET_TYPE_NEW_WALLET:
		// Create new wallet.
		field_hash_set = false;
		memset(field_hash, 0, sizeof(field_hash));
		message_buffer.new_wallet.password.funcs.decode = &hashFieldCallback;
		message_buffer.new_wallet.password.arg = NULL;
		receive_failure = receiveMessage(NewWallet_fields, &(message_buffer.new_wallet));
		if (!receive_failure)
		{
			permission_denied = buttonInterjection(ASKUSER_NEW_WALLET);
			if (!permission_denied)
			{
				if (field_hash_set)
				{
					password_length = sizeof(field_hash);
				}
				else
				{
					password_length = 0; // no password
				}
				wallet_return = newWallet(
					message_buffer.new_wallet.wallet_number,
					message_buffer.new_wallet.wallet_name.bytes,
					false,
					NULL,
					message_buffer.new_wallet.is_hidden,
					field_hash,
					password_length);
				translateWalletError(wallet_return);
			}
		}
		break;

	case PACKET_TYPE_NEW_ADDRESS:
		// Create new address in wallet.
		receive_failure = receiveMessage(NewAddress_fields, &(message_buffer.new_address));
		if (!receive_failure)
		{
			permission_denied = buttonInterjection(ASKUSER_NEW_ADDRESS);
			if (!permission_denied)
			{
				getAndSendAddressAndPublicKey(true, BAD_ADDRESS_HANDLE);
			}
		}
		break;

	case PACKET_TYPE_GET_NUM_ADDRESSES:
		// Get number of addresses in wallet.
		receive_failure = receiveMessage(GetNumberOfAddresses_fields, &(message_buffer.get_number_of_addresses));
		if (!receive_failure)
		{
			message_buffer.number_of_addresses.number_of_addresses = getNumAddresses();
			wallet_return = walletGetLastError();
			if (wallet_return == WALLET_NO_ERROR)
			{
				sendPacket(PACKET_TYPE_NUM_ADDRESSES, NumberOfAddresses_fields, &(message_buffer.number_of_addresses));
			}
			else
			{
				translateWalletError(wallet_return);
			}
		}
		break;

	case PACKET_TYPE_GET_ADDRESS_PUBKEY:
		// Get address and public key corresponding to an address handle.
		receive_failure = receiveMessage(GetAddressAndPublicKey_fields, &(message_buffer.get_address_and_public_key));
		if (!receive_failure)
		{
			getAndSendAddressAndPublicKey(false, message_buffer.get_address_and_public_key.address_handle);
		}
		break;

	case PACKET_TYPE_SIGN_TRANSACTION:
		// Sign a transaction.
		sign_transaction.transaction_data.funcs.decode = &signTransactionCallback;
		// Everything else is handled in signTransactionCallback().
		receiveMessage(SignTransaction_fields, &sign_transaction);
		break;

	case PACKET_TYPE_LOAD_WALLET:
		// Load wallet.
		receive_failure = receiveMessage(LoadWallet_fields, &(message_buffer.load_wallet));
		if (!receive_failure)
		{
			// Attempt load with no password.
			wallet_return = initWallet(message_buffer.load_wallet.wallet_number, field_hash, 0);
			if (wallet_return == WALLET_NOT_THERE)
			{
				// Attempt load with password.
				permission_denied = pinInterjection();
				if (!permission_denied)
				{
					if (!field_hash_set)
					{
						fatalError(); // this should never happen
					}
					wallet_return = initWallet(message_buffer.load_wallet.wallet_number, field_hash, sizeof(field_hash));
					translateWalletError(wallet_return);
				}
			}
			else
			{
				translateWalletError(wallet_return);
			}
		}
		break;

	case PACKET_TYPE_FORMAT:
		// Format storage.
		receive_failure = receiveMessage(FormatWalletArea_fields, &(message_buffer.format_wallet_area));
		if (!receive_failure)
		{
			permission_denied = buttonInterjection(ASKUSER_FORMAT);
			if (!permission_denied)
			{
				invalid_otp = otpInterjection(ASKUSER_FORMAT);
				if (!invalid_otp)
				{
					if (initialiseEntropyPool(message_buffer.format_wallet_area.initial_entropy_pool.bytes))
					{
						translateWalletError(WALLET_RNG_FAILURE);
					}
					else
					{
						wallet_return = sanitiseEverything();
						translateWalletError(wallet_return);
						uninitWallet(); // force wallet to unload
					}
				}
			}
		}
		break;

	case PACKET_TYPE_CHANGE_KEY:
		// Change wallet encryption key.
		field_hash_set = false;
		memset(field_hash, 0, sizeof(field_hash));
		message_buffer.change_encryption_key.password.funcs.decode = &hashFieldCallback;
		message_buffer.change_encryption_key.password.arg = NULL;
		receive_failure = receiveMessage(ChangeEncryptionKey_fields, &(message_buffer.change_encryption_key));
		if (!receive_failure)
		{
			permission_denied = buttonInterjection(ASKUSER_CHANGE_KEY);
			if (!permission_denied)
			{
				invalid_otp = otpInterjection(ASKUSER_CHANGE_KEY);
				if (!invalid_otp)
				{
					if (field_hash_set)
					{
						password_length = sizeof(field_hash);
					}
					else
					{
						password_length = 0; // no password
					}
					wallet_return = changeEncryptionKey(field_hash, password_length);
					translateWalletError(wallet_return);
				}
			}
		}
		break;

	case PACKET_TYPE_CHANGE_NAME:
		// Change wallet name.
		receive_failure = receiveMessage(ChangeWalletName_fields, &(message_buffer.change_wallet_name));
		if (!receive_failure)
		{
			permission_denied = buttonInterjection(ASKUSER_CHANGE_NAME);
			if (!permission_denied)
			{
				wallet_return = changeWalletName(message_buffer.change_wallet_name.wallet_name.bytes);
				translateWalletError(wallet_return);
			}
		}
		break;

	case PACKET_TYPE_LIST_WALLETS:
		// List wallets.
		receive_failure = receiveMessage(ListWallets_fields, &(message_buffer.list_wallets));
		if (!receive_failure)
		{
			number_of_wallets = getNumberOfWallets();
			if (number_of_wallets == 0)
			{
				wallet_return = walletGetLastError();
				translateWalletError(wallet_return);
			}
			else
			{
				message_buffer.wallets.wallet_info.funcs.encode = &listWalletsCallback;
				sendPacket(PACKET_TYPE_WALLETS, Wallets_fields, &(message_buffer.wallets));
			}
		}
		break;

	case PACKET_TYPE_BACKUP_WALLET:
		// Backup wallet.
		receive_failure = receiveMessage(BackupWallet_fields, &(message_buffer.backup_wallet));
		if (!receive_failure)
		{
			permission_denied = buttonInterjection(ASKUSER_BACKUP_WALLET);
			if (!permission_denied)
			{
				wallet_return = backupWallet(message_buffer.backup_wallet.is_encrypted, message_buffer.backup_wallet.device);
				translateWalletError(wallet_return);
			}
		}
		break;

	case PACKET_TYPE_RESTORE_WALLET:
		// Restore wallet.
		field_hash_set = false;
		memset(field_hash, 0, sizeof(field_hash));
		message_buffer.restore_wallet.new_wallet.password.funcs.decode = &hashFieldCallback;
		message_buffer.restore_wallet.new_wallet.password.arg = NULL;
		receive_failure = receiveMessage(RestoreWallet_fields, &(message_buffer.restore_wallet));
		if (!receive_failure)
		{
			if (message_buffer.restore_wallet.seed.size != SEED_LENGTH)
			{
				writeFailureString(STRINGSET_MISC, MISCSTR_INVALID_PACKET);
			}
			else
			{
				permission_denied = buttonInterjection(ASKUSER_RESTORE_WALLET);
				if (!permission_denied)
				{
					if (field_hash_set)
					{
						password_length = sizeof(field_hash);
					}
					else
					{
						password_length = 0; // no password
					}
					wallet_return = newWallet(
						message_buffer.restore_wallet.new_wallet.wallet_number,
						message_buffer.restore_wallet.new_wallet.wallet_name.bytes,
						true,
						message_buffer.restore_wallet.seed.bytes,
						message_buffer.restore_wallet.new_wallet.is_hidden,
						field_hash,
						password_length);
					translateWalletError(wallet_return);
				}
			}
		}
		break;

	case PACKET_TYPE_GET_DEVICE_UUID:
		// Get device UUID.
		receive_failure = receiveMessage(GetDeviceUUID_fields, &(message_buffer.get_device_uuid));
		if (!receive_failure)
		{
			message_buffer.device_uuid.device_uuid.size = UUID_LENGTH;
			if (nonVolatileRead(message_buffer.device_uuid.device_uuid.bytes, PARTITION_GLOBAL, ADDRESS_DEVICE_UUID, UUID_LENGTH) == NV_NO_ERROR)
			{
				sendPacket(PACKET_TYPE_DEVICE_UUID, DeviceUUID_fields, &(message_buffer.device_uuid));
			}
			else
			{
				translateWalletError(WALLET_READ_ERROR);
			}
		}
		break;

	case PACKET_TYPE_GET_ENTROPY:
		// Get an arbitrary number of bytes of entropy.
		receive_failure = receiveMessage(GetEntropy_fields, &(message_buffer.get_entropy));
		if (!receive_failure)
		{
			getBytesOfEntropy(message_buffer.get_entropy.number_of_bytes);
		}
		break;

	case PACKET_TYPE_GET_MASTER_KEY:
		// Get master public key and chain code.
		receive_failure = receiveMessage(GetMasterPublicKey_fields, &(message_buffer.get_master_public_key));
		if (!receive_failure)
		{
			permission_denied = buttonInterjection(ASKUSER_GET_MASTER_KEY);
			if (!permission_denied)
			{
				invalid_otp = otpInterjection(ASKUSER_GET_MASTER_KEY);
				if (!invalid_otp)
				{
					wallet_return = getMasterPublicKey(&master_public_key, message_buffer.master_public_key.chain_code.bytes);
					if (wallet_return == WALLET_NO_ERROR)
					{
						message_buffer.master_public_key.chain_code.size = 32;
						if (sizeof(message_buffer.master_public_key.public_key.bytes) < ECDSA_MAX_SERIALISE_SIZE) // sanity check
						{
							fatalError();
							return;
						}
						message_buffer.master_public_key.public_key.size = ecdsaSerialise(message_buffer.master_public_key.public_key.bytes, &master_public_key, true);
						sendPacket(PACKET_TYPE_MASTER_KEY, MasterPublicKey_fields, &(message_buffer.master_public_key));
					}
					else
					{
						translateWalletError(wallet_return);
					}
				}
			}
		}
		break;

	default:
		// Unknown message ID.
		readAndIgnoreInput();
		writeFailureString(STRINGSET_MISC, MISCSTR_UNEXPECTED_PACKET);
		break;

	}
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
		case MISCSTR_VENDOR:
			return "Vendor";
			break;
		case MISCSTR_PERMISSION_DENIED_USER:
			return "Permission denied by user";
			break;
		case MISCSTR_INVALID_PACKET:
			return "Invalid packet";
			break;
		case MISCSTR_PARAM_TOO_LARGE:
			return "Parameter too large";
			break;
		case MISCSTR_PERMISSION_DENIED_HOST:
			return "Action cancelled by host";
			break;
		case MISCSTR_UNEXPECTED_PACKET:
			return "Unexpected message received";
			break;
		case MISCSTR_OTP_MISMATCH:
			return "OTP mismatch";
			break;
		case MISCSTR_CONFIG:
			return "Config string";
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
		case WALLET_ALREADY_EXISTS:
			return "Wallet already exists";
			break;
		case WALLET_BAD_ADDRESS:
			return "Bad non-volatile address or partition number";
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

/** Display human-readable description of an action on stdout.
  * \param command The action to display. See #AskUserCommandEnum.
  */
static void printAction(AskUserCommand command)
{
	printf("\n");
	switch (command)
	{
	case ASKUSER_NEW_WALLET:
		printf("Create new wallet? ");
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
	case ASKUSER_DELETE_WALLET:
		printf("Delete existing wallet? ");
		break;
	default:
		fatalError();
	}
}

/** Ask user if they want to allow some action.
  * \param command The action to ask the user about. See #AskUserCommandEnum.
  * \return false if the user accepted, true if the user denied.
  */
bool userDenied(AskUserCommand command)
{
	int c;

	printAction(command);
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

/** Display a short (maximum 8 characters) one-time password for the user to
  * see. This one-time password is used to reduce the chance of a user
  * accidentally doing something stupid.
  * \param command The action to ask the user about. See #AskUserCommandEnum.
  * \param otp The one-time password to display.
  */
void displayOTP(AskUserCommand command, char *otp)
{
	printAction(command);
	printf("OTP: %s\n", otp);
}

/** Clear the OTP (one-time password) shown by displayOTP() from the
  * display. */
void clearOTP(void)
{
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

/** Test stream data for: create new wallet and allow button press. */
static const uint8_t test_stream_new_wallet[] = {
0x23, 0x23, 0x00, 0x04, 0x00, 0x00, 0x00, 0x52,
0x12, 0x40,
0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00,
0x00, 0x00, 0x42, 0x00, 0x00, 0xfd, 0x00, 0x00,
0x00, 0x00, 0x00, 0x42, 0xfc, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0xee, 0x43, 0x00, 0x00, 0x00,
0x00, 0x00, 0x10, 0x00, 0x00, 0x44, 0x00, 0x00,
0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00,
0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
0x1a, 0x0e, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65,
0x65, 0x20, 0x66, 0x66, 0x20, 0x20, 0x20, 0x6f,

0x23, 0x23, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: create new address and allow button press. */
static const uint8_t test_stream_new_address[] = {
0x23, 0x23, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,

0x23, 0x23, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: get number of addresses. */
static const uint8_t test_stream_get_num_addresses[] = {
0x23, 0x23, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: get address 1. */
static const uint8_t test_stream_get_address1[] = {
0x23, 0x23, 0x00, 0x09, 0x00, 0x00, 0x00, 0x02,
0x08, 0x01};

/** Test stream data for: get address 0 (which is an invalid address
  * handle). */
static const uint8_t test_stream_get_address0[] = {
0x23, 0x23, 0x00, 0x09, 0x00, 0x00, 0x00, 0x02,
0x08, 0x00};

/** Test stream data for: sign something and allow button press. */
static uint8_t test_stream_sign_tx[] = {
0x23, 0x23, 0x00, 0x0a, 0x00, 0x00, 0x01, 0xa0,
0x08, 0x01, 0x12, 0x9b, 0x03,
// transaction data is below
0x01, // is_ref = 1 (input)
0x01, 0x00, 0x00, 0x00, // output number to examine
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0xdf, 0x08, 0xf9, 0xa3, 0x7c, 0x6d, 0x71, 0x3c, // previous output
0x6a, 0x99, 0x2e, 0x88, 0x29, 0x8e, 0x0b, 0x4c,
0x8f, 0xb5, 0xf9, 0x0e, 0x11, 0xf0, 0x2c, 0xa7,
0x36, 0x72, 0xeb, 0x58, 0xb3, 0x04, 0xef, 0xc0,
0x01, 0x00, 0x00, 0x00, // number in previous output
0x8a, // script length
0x47, // 71 bytes of data follows
0x30, 0x44, 0x02, 0x20, 0x1b, 0xf4, 0xef, 0x3c, 0x34, 0x96, 0x02, 0x9b, 0x1a,
0xb1, 0xc8, 0x49, 0xbf, 0x18, 0x55, 0xcc, 0x16, 0xbc, 0x52, 0x6d, 0xcc, 0x20,
0xfb, 0x7c, 0x0a, 0x1d, 0x48, 0xd6, 0xe9, 0xbd, 0xd7, 0xb1, 0x02, 0x20, 0x53,
0xb1, 0xa3, 0xaa, 0xbf, 0xd3, 0x87, 0x84, 0xdc, 0xf3, 0x10, 0xe5, 0xd2, 0x09,
0xa4, 0xba, 0xb0, 0x01, 0x62, 0xe5, 0xbc, 0x09, 0x75, 0x9d, 0x4f, 0x74, 0x2c,
0xb4, 0x6b, 0x32, 0x37, 0x2c, 0x01,
0x41, // 65 bytes of data follows
0x04, 0x05, 0x4d, 0xb5, 0xe0, 0x8e, 0x2a, 0x33, 0x89, 0x2c, 0xf3, 0x4b, 0x7e,
0xbc, 0x18, 0x3b, 0xa5, 0xf5, 0x54, 0xc6, 0x9d, 0x6d, 0x21, 0x65, 0x60, 0x89,
0xf5, 0x5e, 0x2d, 0x0f, 0x3a, 0x68, 0x08, 0x23, 0x83, 0x19, 0xcd, 0x89, 0xba,
0xda, 0x09, 0x9b, 0xc6, 0xef, 0x3f, 0xdc, 0x80, 0xd8, 0x7a, 0xb2, 0xbf, 0x2b,
0x37, 0x18, 0xdd, 0x4a, 0x4e, 0x36, 0x09, 0x60, 0x28, 0x6e, 0x2e, 0x77, 0x57,
0xFF, 0xFF, 0xFF, 0xFF, // sequence
0x02, // number of outputs
0xc0, 0xa4, 0x70, 0x57, 0x00, 0x00, 0x00, 0x00, // 14.67 BTC
0x19, // script length
0x76, // OP_DUP
0xA9, // OP_HASH160
0x14, // 20 bytes of data follows
// 1Q6W8HTPdwccCkLRMLJpYkGvweKhpsKKjE
0xfd, 0x55, 0x49, 0x20, 0x22, 0xa0, 0x3f, 0xf7, 0x7a, 0x9d,
0xe0, 0x0d, 0xa2, 0x18, 0x08, 0x0c, 0xa9, 0x51, 0xde, 0xef,
0x88, // OP_EQUALVERIFY
0xAC, // OP_CHECKSIG
0x40, 0x54, 0x92, 0x3d, 0x00, 0x00, 0x00, 0x00, // 10.33 BTC
0x19, // script length
0x76, // OP_DUP
0xA9, // OP_HASH160
0x14, // 20 bytes of data follows
// 16E7VhudyU3iXNddNazG8sChjQwfWcrHNw
0x39, 0x53, 0x75, 0x46, 0x88, 0x84, 0x3d, 0xe5, 0x50, 0x0b,
0x79, 0x91, 0x33, 0x7f, 0x96, 0xf5, 0x41, 0x71, 0x48, 0xa1,
0x88, // OP_EQUALVERIFY
0xAC, // OP_CHECKSIG
0x00, 0x00, 0x00, 0x00, // locktime
// The main (spending) transaction.
0x00, // is_ref = 0 (main)
0x01, 0x00, 0x00, 0x00, // version
0x01, // number of inputs
0xee, 0xce, 0xae, 0x86, 0xf5, 0x70, 0x4d, 0x76, // previous output
0xb8, 0x54, 0x5e, 0x6d, 0xcf, 0x21, 0xf1, 0x75,
0x35, 0x7f, 0x83, 0xbd, 0xa4, 0x96, 0x43, 0x83,
0xd6, 0xdd, 0x7e, 0x41, 0x68, 0x1b, 0x5e, 0x1a,
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
0x01, 0x00, 0x00, 0x00, // hashtype

0x23, 0x23, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00
};

/** Test stream data for: format storage and allow button press. */
static const uint8_t test_stream_format[] = {
0x23, 0x23, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x22,
0x0a, 0x20,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x23, 0x23, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00,

0x23, 0x23, 0x00, 0x57, 0x00, 0x00, 0x00, 0x06,
0x0a, 0x04, 0x31, 0x32, 0x33, 0x34};

/** Test stream data for: load wallet using correct key. */
static const uint8_t test_stream_load_correct[] = {
0x23, 0x23, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x02,
0x08, 0x00,

0x23, 0x23, 0x00, 0x54, 0x00, 0x00, 0x00, 0x42,
0x0a, 0x40,
0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
0x00, 0x42, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00,
0x00, 0x00, 0x42, 0x00, 0x00, 0xfd, 0x00, 0x00,
0x00, 0x00, 0x00, 0x42, 0xfc, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0xee, 0x43, 0x00, 0x00, 0x00,
0x00, 0x00, 0x10, 0x00, 0x00, 0x44, 0x00, 0x00,
0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00,
0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};

/** Test stream data for: load wallet using incorrect key. */
static const uint8_t test_stream_load_incorrect[] = {
0x23, 0x23, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x02,
0x08, 0x00,

0x23, 0x23, 0x00, 0x54, 0x00, 0x00, 0x00, 0x22,
0x0a, 0x20,
0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: initialize. */
static const uint8_t test_stream_init[] = {
0x23, 0x23, 0x00, 0x17, 0x00, 0x00, 0x00, 0x04, 0x0a, 0x02, 0x61, 0x62};

/** Test stream data for: change encryption key and allow button press. */
static const uint8_t test_stream_change_key[] = {
0x23, 0x23, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x22,
0x0a, 0x20,
0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

0x23, 0x23, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00,

0x23, 0x23, 0x00, 0x57, 0x00, 0x00, 0x00, 0x06,
0x0a, 0x04, 0x31, 0x32, 0x33, 0x34};

/** Test stream data for: load with new encryption key. */
static const uint8_t test_stream_load_with_changed_key[] = {
0x23, 0x23, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x02,
0x08, 0x00,

0x23, 0x23, 0x00, 0x54, 0x00, 0x00, 0x00, 0x22,
0x0a, 0x20,
0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: list wallets. */
static const uint8_t test_stream_list_wallets[] = {
0x23, 0x23, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: change wallet name and allow button press. */
static const uint8_t test_stream_change_name[] = {
0x23, 0x23, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0c,
0x0a, 0x0a,
0x71, 0x71, 0x71, 0x72, 0x70, 0x74, 0x20, 0x20,
0x68, 0x68,

0x23, 0x23, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: backup wallet and allow button press. */
static const uint8_t test_stream_backup_wallet[] = {
0x23, 0x23, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00,

0x23, 0x23, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: delete wallet and allow button press. */
static const uint8_t test_stream_delete[] = {
0x23, 0x23, 0x00, 0x16, 0x00, 0x00, 0x00, 0x02,
0x08, 0x00,

0x23, 0x23, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00,

0x23, 0x23, 0x00, 0x57, 0x00, 0x00, 0x00, 0x06,
0x0a, 0x04, 0x31, 0x32, 0x33, 0x34};

/** Test stream data for: restore wallet and allow button press. */
static const uint8_t test_stream_restore_wallet[] = {
0x23, 0x23, 0x00, 0x12, 0x00, 0x00, 0x00, 0x7a,
0x0a, 0x36,
0x08, 0x00, // wallet number
0x12, 0x20,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // encryption key
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x1a, 0x0e,
0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x65, 0x20, // name
0x66, 0x66, 0x20, 0x20, 0x20, 0x6F,
0x20, 0x00, // make hidden?
0x12, 0x40,
0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, // seed
0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
0x12, 0x34, 0x56, 0x00, 0x9a, 0xbc, 0xde, 0xf0,
0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
0xea, 0x11, 0x44, 0xf0, 0x0f, 0xb0, 0x0b, 0x50,
0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
0x12, 0x34, 0xde, 0xad, 0xfe, 0xed, 0xde, 0xf0,

0x23, 0x23, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: get device UUID. */
static const uint8_t test_stream_get_device_uuid[] = {
0x23, 0x23, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: get 0 bytes of entropy. */
static const uint8_t test_stream_get_entropy0[] = {
0x23, 0x23, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00};

/** Test stream data for: get 1 byte of entropy. */
static const uint8_t test_stream_get_entropy1[] = {
0x23, 0x23, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x08, 0x01};

/** Test stream data for: get 32 bytes of entropy. */
static const uint8_t test_stream_get_entropy32[] = {
0x23, 0x23, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x08, 0x20};

/** Test stream data for: get 100 bytes of entropy. */
static const uint8_t test_stream_get_entropy100[] = {
0x23, 0x23, 0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x08, 0x64};

/** Ping (get version). */
static const uint8_t test_stream_ping[] = {
0x23, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0a, 0x03, 0x4d, 0x6f, 0x6f};

/** Get master public key and allow button press. */
static const uint8_t test_get_master_public_key[] = {
0x23, 0x23, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00,

0x23, 0x23, 0x00, 0x51, 0x00, 0x00, 0x00, 0x00,

0x23, 0x23, 0x00, 0x57, 0x00, 0x00, 0x00, 0x06,
0x0a, 0x04, 0x31, 0x32, 0x33, 0x34};

/** Get master public key but don't allow button press. */
static const uint8_t test_get_master_public_key_no_press[] = {
0x23, 0x23, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00,

0x23, 0x23, 0x00, 0x52, 0x00, 0x00, 0x00, 0x00};

/** Test stream data for: load but don't allow password to be sent. */
static const uint8_t test_stream_load_no_key[] = {
0x23, 0x23, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x02,
0x08, 0x00,

0x23, 0x23, 0x00, 0x55, 0x00, 0x00, 0x00, 0x00};

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
	initialiseDefaultEntropyPool();

	printf("Initialising...\n");
	SEND_ONE_TEST_STREAM(test_stream_init);
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
	printf("Initialising again...\n");
	SEND_ONE_TEST_STREAM(test_stream_init);
	printf("Loading wallet using changed key...\n");
	SEND_ONE_TEST_STREAM(test_stream_load_with_changed_key);
	printf("Changing name...\n");
	SEND_ONE_TEST_STREAM(test_stream_change_name);
	printf("Listing wallets...\n");
	SEND_ONE_TEST_STREAM(test_stream_list_wallets);
	printf("Backing up a wallet...\n");
	SEND_ONE_TEST_STREAM(test_stream_backup_wallet);
	printf("Deleting a wallet...\n");
	SEND_ONE_TEST_STREAM(test_stream_delete);
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
	printf("Getting master public key but not allowing button press...\n");
	SEND_ONE_TEST_STREAM(test_get_master_public_key_no_press);
	printf("Loading wallet but not allowing password to be sent...\n");
	SEND_ONE_TEST_STREAM(test_stream_load_no_key);

	finishTests();
	exit(0);
}

#endif // #ifdef TEST_STREAM_COMM


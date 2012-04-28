/** \file wallet.c
  *
  * \brief Manages the storage and generation of Bitcoin addresses.
  *
  * Addresses are stored in wallets, which can be
  * "loaded" or "unloaded". A loaded wallet can have operations (eg. new
  * address) performed on it, whereas an unloaded wallet can only sit dormant.
  * Addresses aren't actually physically stored in non-volatile storage;
  * rather a seed for a deterministic private key generation algorithm is
  * stored and private keys are generated when they are needed. This means
  * that obtaining an address is a slow operation (requiring a point
  * multiply), so the host should try to remember all public keys and
  * addresses. The advantage of not storing addresses is that very little
  * non-volatile storage space is needed per
  * wallet - only #WALLET_RECORD_LENGTH bytes per wallet.
  *
  * Wallets can be encrypted or unencrypted. Actually, technically, all
  * wallets are encrypted. However, wallets marked as "unencrypted" are
  * encrypted using an encryption key consisting of all zeroes. This purely
  * semantic definition was done to avoid having to insert special cases
  * everytime encrypted storage needed to be accessed.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifdef TEST
#include <stdlib.h>
#include <stdio.h>
#endif // #ifdef TEST

#ifdef TEST_WALLET
#include "test_helpers.h"
#endif // #ifdef TEST_WALLET

#include "common.h"
#include "endian.h"
#include "wallet.h"
#include "prandom.h"
#include "sha256.h"
#include "ripemd160.h"
#include "ecdsa.h"
#include "hwinterface.h"
#include "xex.h"
#include "bignum256.h"

/** The most recent error to occur in a function in this file,
  * or #WALLET_NO_ERROR if no error occurred in the most recent function
  * call. See #WalletErrorsEnum for possible values. */
static WalletErrors last_error;
/** This will be 0 if a wallet is not currently loaded. This will be non-zero
  * if a wallet is currently loaded. */
static uint8_t wallet_loaded;
/** This will only be valid if a wallet is loaded. It contains a cache of the
  * number of addresses in the currently loaded wallet. */
static uint32_t num_addresses;

#ifdef TEST
/** The file to perform test non-volatile I/O on. */
FILE *wallet_test_file;
#endif // #ifdef TEST

/** Find out what the most recent error which occurred in any wallet function
  * was. If no error occurred in the most recent wallet function that was
  * called, this will return #WALLET_NO_ERROR.
  * \return See #WalletErrorsEnum for possible values.
  */
WalletErrors walletGetLastError(void)
{
	return last_error;
}

#ifdef TEST

void initWalletTest(void)
{
	wallet_test_file = fopen("wallet_test.bin", "w+b");
	if (wallet_test_file == NULL)
	{
		printf("Could not open \"wallet_test.bin\" for writing\n");
		exit(1);
	}
}

#endif // #ifdef TEST

#ifdef TEST_WALLET
/** Maximum of addresses which can be stored in storage area - for testing
  * only. This should actually be the capacity of the wallet, since one
  * of the tests is to see what happens when the wallet is full. */
#define MAX_TESTING_ADDRESSES	7
#endif // #ifdef TEST_WALLET

/**
 * \defgroup WalletStorageFormat Wallet storage format
 *
 * Wallets are stored as sequential records in non-volatile
 * storage. Each record is 160 bytes. If the wallet is encrypted, the
 * first 48 bytes are unencrypted and the last 112 bytes are encrypted.
 * The contents of each record:
 * - 4 bytes: little endian version
 *  - 0x00000000: nothing here
 *  - 0x00000001: v0.1 wallet format (not supported)
 *  - 0x00000002: unencrypted wallet
 *  - 0x00000003: encrypted wallet, host provides key
 * - 4 bytes: reserved
 * - 40 bytes: name of wallet (padded with spaces)
 * - 4 bytes: little endian number of addresses
 * - 8 bytes: random data
 * - 4 bytes: reserved
 * - 64 bytes: seed for deterministic private key generator
 * - 32 bytes: SHA-256 of everything except number of addresses and this
 * @{
 */
/** Length of a record.
  * \warning This must be a multiple of 32 in order for newWallet() to
  *          work properly.
  * \warning This must also be a multiple of 16, since the block size of
  *          AES is 128 bits.
  */
#define WALLET_RECORD_LENGTH	160
/** The offset where encryption starts. The contents of a record before this
  * offset are not encrypted, while the contents of a record at and after this
  * offset are encrypted.
  * \warning This must also be a multiple of 16, since the block size of
  *          AES is 128 bits.
  */
#define ENCRYPT_START			48
/** Offset within a record where version is. */
#define OFFSET_VERSION			0
/** Offset within a record where first reserved area is. */
#define OFFSET_RESERVED1		4
/** Offset within a record where name is. */
#define OFFSET_NAME				8
/** Offset within a record where number of addresses is. */
#define OFFSET_NUM_ADDRESSES	48
/** Offset within a record where some random data is. */
#define OFFSET_NONCE1			52
/** Offset within a record where second reserved area is. */
#define OFFSET_RESERVED2		60
/** Offset within a record where deterministic private key generator seed
  * is. */
#define OFFSET_SEED				64
/** Offset within a record where some wallet checksum is. */
#define OFFSET_CHECKSUM			128
/** Version number which means "nothing here". */
#define VERSION_NOTHING_THERE	0x00000000
/** Version number which means "wallet is not encrypted".
  * \warning A wallet which uses an encryption key consisting of
  *          all zeroes (see isEncryptionKeyNonZero()) is considered to be
  *          unencrypted.
  */
#define VERSION_UNENCRYPTED		0x00000002
/** Version number which means "wallet is encrypted". */
#define VERSION_IS_ENCRYPTED	0x00000003
/**@}*/

/** Calculate the checksum (SHA-256 hash) of the wallet's contents. The
  * wallet checksum is invariant to the number of addresses in the wallet.
  * This invariance is necessary to avoid having to rewrite the wallet
  * checksum every time a new address is generated.
  * \param hash The resulting SHA-256 hash will be written here. This must
  *             be a byte array with space for 32 bytes.
  * \return See #NonVolatileReturnEnum.
  */
static NonVolatileReturn calculateWalletChecksum(uint8_t *hash)
{
	uint16_t i;
	uint8_t buffer[4];
	HashState hs;
	NonVolatileReturn r;

	sha256Begin(&hs);
	for (i = 0; i < WALLET_RECORD_LENGTH; i = (uint16_t)(i + 4))
	{
		// Skip number of addresses and checksum.
		if (i == OFFSET_NUM_ADDRESSES)
		{
			i = (uint16_t)(i + 4);
		}
		if (i == OFFSET_CHECKSUM)
		{
			i = (uint16_t)(i + 32);
		}
		if (i < WALLET_RECORD_LENGTH)
		{
			// "The first 48 bytes are unencrypted, the last 112 bytes are
			// encrypted."
			if (i < ENCRYPT_START)
			{
				r = nonVolatileRead(buffer, i, 4);
			}
			else
			{
				r = encryptedNonVolatileRead(buffer, i, 4);
			}
			if (r != NV_NO_ERROR)
			{
				return r;
			}
			sha256WriteByte(&hs, buffer[0]);
			sha256WriteByte(&hs, buffer[1]);
			sha256WriteByte(&hs, buffer[2]);
			sha256WriteByte(&hs, buffer[3]);
		}
	}
	sha256Finish(&hs);
	writeHashToByteArray(hash, &hs, 1);
	return NV_NO_ERROR;
}

/** Initialise wallet (load it if it's there).
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors initWallet(void)
{
	uint8_t buffer[32];
	uint8_t hash[32];
	uint32_t version;

	wallet_loaded = 0;

	// Read version.
	if (nonVolatileRead(buffer, OFFSET_VERSION, 4) != NV_NO_ERROR)
	{
		last_error = WALLET_READ_ERROR;
		return last_error;
	}
	version = readU32LittleEndian(buffer);
	if ((version != VERSION_UNENCRYPTED) && (version != VERSION_IS_ENCRYPTED))
	{
		last_error = WALLET_NOT_THERE;
		return last_error;
	}

	// Calculate checksum and check that it matches.
	if (calculateWalletChecksum(hash) != NV_NO_ERROR)
	{
		last_error = WALLET_READ_ERROR;
		return last_error;
	}
	if (encryptedNonVolatileRead(buffer, OFFSET_CHECKSUM, 32) != NV_NO_ERROR)
	{
		last_error = WALLET_READ_ERROR;
		return last_error;
	}
	if (bigCompare(buffer, hash) != BIGCMP_EQUAL)
	{
		last_error = WALLET_NOT_THERE;
		return last_error;
	}

	// Read number of addresses.
	if (encryptedNonVolatileRead(buffer, OFFSET_NUM_ADDRESSES, 4) != NV_NO_ERROR)
	{
		last_error = WALLET_READ_ERROR;
		return last_error;
	}
	num_addresses = readU32LittleEndian(buffer);

	wallet_loaded = 1;
	last_error = WALLET_NO_ERROR;
	return last_error;
}

/** Unload wallet, so that it cannot be used until initWallet() is called.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors uninitWallet(void)
{
	wallet_loaded = 0;
	num_addresses = 0;
	last_error = WALLET_NO_ERROR;
	return last_error;
}

/** Sanitise (clear) a selected area of non-volatile storage. This will clear
  * the area between start (inclusive) and end (exclusive).
  * \param start The first address which will be cleared.
  * \param end One byte past the last address which will be cleared.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred. This will still return #WALLET_NO_ERROR even if
  *         end is an address beyond the end of the non-volatile storage area.
  *         This is done so that using start = 0 and end = 0xffffffff will
  *         clear the entire non-volatile storage area.
  * \warning start and end must be a multiple of 32 (unless start is 0 and
  *          end is 0xffffffff).
  */
WalletErrors sanitiseNonVolatileStorage(uint32_t start, uint32_t end)
{
	uint8_t buffer[32];
	uint32_t address;
	NonVolatileReturn r;
	uint8_t pass;

	r = NV_NO_ERROR;
	for (pass = 0; pass < 4; pass++)
	{
		address = start;
		r = NV_NO_ERROR;
		while ((r == NV_NO_ERROR) && (address < end))
		{
			if (pass == 0)
			{
				memset(buffer, 0, sizeof(buffer));
			}
			else if (pass == 1)
			{
				memset(buffer, 0xff, sizeof(buffer));
			}
			else
			{
				getRandom256(buffer);
			}
			r = nonVolatileWrite(buffer, address, 32);
			nonVolatileFlush();
			address += 32;
		}

		if ((r != NV_INVALID_ADDRESS) && (r != NV_NO_ERROR))
		{
			// Uh oh, probably an I/O error.
			break;
		}
	} // end for (pass = 0; pass < 4; pass++)

	if ((r == NV_INVALID_ADDRESS) || (r == NV_NO_ERROR))
	{
		// Write VERSION_NOTHING_THERE to all possible locations of the
		// version field. This ensures that a wallet won't accidentally
		// (1 in 2 ^ 31 chance) be recognised as a valid wallet by
		// getWalletInfo().
		writeU32LittleEndian(buffer, VERSION_NOTHING_THERE);
		r = nonVolatileWrite(buffer, OFFSET_VERSION, 4);
		if (r == NV_NO_ERROR)
		{
			last_error = WALLET_NO_ERROR;
		}
		else
		{
			last_error = WALLET_WRITE_ERROR;
		}
	}
	else
	{
		last_error = WALLET_WRITE_ERROR;
	}
	return last_error;
}

/** Writes 4 byte wallet version. This is in its own function because
  * it's used by both newWallet() and changeEncryptionKey().
  * \return See #NonVolatileReturnEnum.
  */
static NonVolatileReturn writeWalletVersion(void)
{
	uint8_t buffer[4];

	if (isEncryptionKeyNonZero())
	{
		writeU32LittleEndian(buffer, VERSION_IS_ENCRYPTED);
	}
	else
	{
		writeU32LittleEndian(buffer, VERSION_UNENCRYPTED);
	}
	return nonVolatileWrite(buffer, OFFSET_VERSION, 4);
}

/** Writes wallet checksum. This is in its own function because
  * it's used by newWallet(), changeEncryptionKey() and changeWalletName().
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
static WalletErrors writeWalletChecksum(void)
{
	uint8_t hash[32];

	if (calculateWalletChecksum(hash) != NV_NO_ERROR)
	{
		return WALLET_READ_ERROR;
	}
	if (encryptedNonVolatileWrite(hash, OFFSET_CHECKSUM, 32) != NV_NO_ERROR)
	{
		return WALLET_WRITE_ERROR;
	}
	return WALLET_NO_ERROR;
}

/** Create new wallet. A brand new wallet contains no addresses and should
  * have a unique, unpredictable deterministic private key generation seed.
  * \param name Should point to #NAME_LENGTH bytes (padded with spaces if
  *             necessary) containing the desired name of the wallet.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred. If this returns #WALLET_NO_ERROR, then the
  *         wallet will also be loaded.
  * \warning This will erase the current one.
  */
WalletErrors newWallet(uint8_t *name)
{
	uint8_t buffer[32];
	WalletErrors r;

	// Erase all traces of the existing wallet.
	r = sanitiseNonVolatileStorage(0, WALLET_RECORD_LENGTH);
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return last_error;
	}

	// Write version.
	if (writeWalletVersion() != NV_NO_ERROR)
	{
		last_error = WALLET_WRITE_ERROR;
		return last_error;
	}
	// Write reserved area 1.
	writeU32LittleEndian(buffer, 0);
	if (nonVolatileWrite(buffer, OFFSET_RESERVED1, 4) != NV_NO_ERROR)
	{
		last_error = WALLET_WRITE_ERROR;
		return last_error;
	}
	// Write name of wallet.
	if (nonVolatileWrite(name, OFFSET_NAME, NAME_LENGTH) != NV_NO_ERROR)
	{
		last_error = WALLET_WRITE_ERROR;
		return last_error;
	}
	// Write number of addresses.
	writeU32LittleEndian(buffer, 0);
	if (encryptedNonVolatileWrite(buffer, OFFSET_NUM_ADDRESSES, 4) != NV_NO_ERROR)
	{
		last_error = WALLET_WRITE_ERROR;
		return last_error;
	}
	// Write nonce 1.
	getRandom256(buffer);
	if (encryptedNonVolatileWrite(buffer, OFFSET_NONCE1, 8) != NV_NO_ERROR)
	{
		last_error = WALLET_WRITE_ERROR;
		return last_error;
	}
	// Write reserved area 2.
	writeU32LittleEndian(buffer, 0);
	if (encryptedNonVolatileWrite(buffer, OFFSET_RESERVED2, 4) != NV_NO_ERROR)
	{
		last_error = WALLET_WRITE_ERROR;
		return last_error;
	}
	// Write seed for deterministic address generator.
	getRandom256(buffer);
	if (encryptedNonVolatileWrite(buffer, OFFSET_SEED, 32) != NV_NO_ERROR)
	{
		last_error = WALLET_WRITE_ERROR;
		return last_error;
	}
	getRandom256(buffer);
	if (encryptedNonVolatileWrite(buffer, OFFSET_SEED + 32, 32) != NV_NO_ERROR)
	{
		last_error = WALLET_WRITE_ERROR;
		return last_error;
	}
	nonVolatileFlush();

	// Write checksum.
	r = writeWalletChecksum();
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return last_error;
	}
	nonVolatileFlush();

	last_error = initWallet();
	return last_error;
}

/** Generate a new address using the deterministic private key generator.
  * \param out_address The new address will be written here (if everything
  *                    goes well). This must be a byte array with space for
  *                    20 bytes.
  * \param out_public_key The public key corresponding to the new address will
  *                       be written here (if everything goes well).
  * \return The address handle of the new address on success,
  *         or #BAD_ADDRESS_HANDLE if an error occurred.
  *         Use walletGetLastError() to get more detail about an error.
  */
AddressHandle makeNewAddress(uint8_t *out_address, PointAffine *out_public_key)
{
	uint8_t buffer[4];

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_THERE;
		return BAD_ADDRESS_HANDLE;
	}
#ifdef TEST_WALLET
	if (num_addresses == MAX_TESTING_ADDRESSES)
#else
	if (num_addresses == MAX_ADDRESSES)
#endif // #ifdef TEST_WALLET
	{
		last_error = WALLET_FULL;
		return BAD_ADDRESS_HANDLE;
	}
	num_addresses++;
	writeU32LittleEndian(buffer, num_addresses);
	if (encryptedNonVolatileWrite(buffer, OFFSET_NUM_ADDRESSES, 4) != NV_NO_ERROR)
	{
		last_error = WALLET_WRITE_ERROR;
		return BAD_ADDRESS_HANDLE;
	}
	last_error = getAddressAndPublicKey(out_address, out_public_key, num_addresses);
	if (last_error != WALLET_NO_ERROR)
	{
		return BAD_ADDRESS_HANDLE;
	}
	else
	{
		return num_addresses;
	}
}

/** Given an address handle, use the deterministic private key
  * generator to generate the address and public key associated
  * with that address handle.
  * \param out_address The address will be written here (if everything
  *                    goes well). This must be a byte array with space for
  *                    20 bytes.
  * \param out_public_key The public key corresponding to the address will
  *                       be written here (if everything goes well).
  * \param ah The address handle to obtain the address/public key of.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getAddressAndPublicKey(uint8_t *out_address, PointAffine *out_public_key, AddressHandle ah)
{
	uint8_t buffer[32];
	HashState hs;
	WalletErrors r;
	uint8_t i;

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_THERE;
		return last_error;
	}
	if (num_addresses == 0)
	{
		last_error = WALLET_EMPTY;
		return last_error;
	}
	if ((ah == 0) || (ah > num_addresses) || (ah == BAD_ADDRESS_HANDLE))
	{
		last_error = WALLET_INVALID_HANDLE;
		return last_error;
	}

	// Calculate private key.
	r = getPrivateKey(buffer, ah);
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return r;
	}
	// Calculate public key.
	setToG(out_public_key);
	pointMultiply(out_public_key, buffer);
	// Calculate address. The Bitcoin convention is to hash the public key in
	// big-endian format, which is why the counters run backwards in the next
	// two loops.
	sha256Begin(&hs);
	sha256WriteByte(&hs, 0x04);
	for (i = 32; i--; )
	{
		sha256WriteByte(&hs, out_public_key->x[i]);
	}
	for (i = 32; i--; )
	{
		sha256WriteByte(&hs, out_public_key->y[i]);
	}
	sha256Finish(&hs);
	writeHashToByteArray(buffer, &hs, 1);
	ripemd160Begin(&hs);
	for (i = 0; i < 32; i++)
	{
		ripemd160WriteByte(&hs, buffer[i]);
	}
	ripemd160Finish(&hs);
	writeHashToByteArray(buffer, &hs, 1);
	memcpy(out_address, buffer, 20);

	last_error = WALLET_NO_ERROR;
	return last_error;
}

/** Get the current number of addresses in a wallet.
  * \return The current number of addresses on success, or 0 if an error
  *         occurred. Use walletGetLastError() to get more detail about
  *         an error.
  */
uint32_t getNumAddresses(void)
{
	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_THERE;
		return 0;
	}
	if (num_addresses == 0)
	{
		last_error = WALLET_EMPTY;
		return 0;
	}
	else
	{
		last_error = WALLET_NO_ERROR;
		return num_addresses;
	}
}

/** Given an address handle, use the deterministic private key
  * generator to generate the private key associated with that address handle.
  * \param out The private key will be written here (if everything goes well).
  *            This must be a byte array with space for 32 bytes.
  * \param ah The address handle to obtain the private key of.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getPrivateKey(uint8_t *out, AddressHandle ah)
{
	uint8_t seed[64];

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_THERE;
		return last_error;
	}
	if (num_addresses == 0)
	{
		last_error = WALLET_EMPTY;
		return last_error;
	}
	if ((ah == 0) || (ah > num_addresses) || (ah == BAD_ADDRESS_HANDLE))
	{
		last_error = WALLET_INVALID_HANDLE;
		return last_error;
	}
	if (encryptedNonVolatileRead(seed, OFFSET_SEED, 64) != NV_NO_ERROR)
	{
		last_error = WALLET_READ_ERROR;
		return last_error;
	}
	generateDeterministic256(out, seed, ah);
	last_error = WALLET_NO_ERROR;
	return last_error;
}

/** Change the encryption key of a wallet.
  * \param new_key A byte array of #WALLET_ENCRYPTION_KEY_LENGTH bytes
  *                specifying the new encryption key.
  *                An encryption key consisting of all zeroes is interpreted
  *                as meaning "no encryption".
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors changeEncryptionKey(uint8_t *new_key)
{
	uint8_t old_key[WALLET_ENCRYPTION_KEY_LENGTH];
	uint8_t buffer[16];
	NonVolatileReturn r;
	uint32_t address;
	uint32_t end;

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_THERE;
		return last_error;
	}

	getEncryptionKey(old_key);
	r = NV_NO_ERROR;
	address = ENCRYPT_START;
	end = WALLET_RECORD_LENGTH;
	while ((r == NV_NO_ERROR) && (address < end))
	{
		setEncryptionKey(old_key);
		r = encryptedNonVolatileRead(buffer, address, 16);
		if (r == NV_NO_ERROR)
		{
			setEncryptionKey(new_key);
			r = encryptedNonVolatileWrite(buffer, address, 16);
			nonVolatileFlush();
		}
		address += 16;
	}

	setEncryptionKey(new_key);
	if (r == NV_NO_ERROR)
	{
		// Update version and checksum.
		if (writeWalletVersion() == NV_NO_ERROR)
		{
			last_error = writeWalletChecksum();;
		}
		else
		{
			last_error = WALLET_WRITE_ERROR;
		}
	}
	else
	{
		last_error = WALLET_WRITE_ERROR;
	}
	return last_error;
}

/** Change the name of the currently loaded wallet.
  * \param new_name This should point to #NAME_LENGTH bytes (padded with
  *                 spaces if necessary) containing the new desired name of
  *                 the wallet.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors changeWalletName(uint8_t *new_name)
{
	WalletErrors r;

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_THERE;
		return last_error;
	}

	// Write wallet name.
	if (nonVolatileWrite(new_name, OFFSET_NAME, NAME_LENGTH) != NV_NO_ERROR)
	{
		last_error = WALLET_WRITE_ERROR;
		return last_error;
	}
	// Write checksum.
	r = writeWalletChecksum();
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return last_error;
	}
	nonVolatileFlush();

	last_error = WALLET_NO_ERROR;
	return last_error;
}

/** Obtain publicly available information about a wallet. "Publicly available"
  * means that the leakage of that information would have a relatively low
  * impact on security (compared to the leaking of, say, the deterministic
  * private key generator seed).
  *
  * Note that unlike most of the other wallet functions, this function does
  * not require the wallet to be loaded. This is so that a user can be
  * presented with a list of all the wallets stored on a hardware Bitcoin
  * wallet, without having to know the encryption key to each wallet.
  * \param out_version The little-endian version of the wallet will be written
  *                    to here (if everything goes well). This should be a
  *                    byte array with enough space to store 4 bytes.
  * \param out_name The (space-padded) name of the wallet will be written
  *                 to here (if everything goes well). This should be a
  *                 byte array with enough space to store #NAME_LENGTH bytes.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getWalletInfo(uint8_t *out_version, uint8_t *out_name)
{
	if (nonVolatileRead(out_version, OFFSET_VERSION, 4) != NV_NO_ERROR)
	{
		last_error = WALLET_READ_ERROR;
		return last_error;
	}
	if (nonVolatileRead(out_name, OFFSET_NAME, NAME_LENGTH) != NV_NO_ERROR)
	{
		last_error = WALLET_READ_ERROR;
		return last_error;
	}

	last_error = WALLET_NO_ERROR;
	return last_error;
}

#ifdef TEST

/** Size of storage area, in bytes. */
#define TEST_FILE_SIZE 1024

/** Write to non-volatile storage.
  * \param data A pointer to the data to be written.
  * \param address Byte offset specifying where in non-volatile storage to
  *                start writing to.
  * \param length The number of bytes to write.
  * \return See #NonVolatileReturnEnum for return values.
  * \warning Writes may be buffered; use nonVolatileFlush() to be sure that
  *          data is actually written to non-volatile storage.
  */
NonVolatileReturn nonVolatileWrite(uint8_t *data, uint32_t address, uint8_t length)
{
#ifndef TEST_XEX
	int i;
#endif // #ifndef TEST_XEX

	if ((address + (uint32_t)length) > TEST_FILE_SIZE)
	{
		return NV_INVALID_ADDRESS;
	}
	// Don't output write debugging info when testing xex.c, otherwise the
	// console will go crazy (since the unit tests in xex.c do a lot of
	// writing).
#ifndef TEST_XEX
	printf("nv write, addr = 0x%08x, length = 0x%04x, data =", (int)address, (int)length);
	for (i = 0; i < length; i++)
	{
		printf(" %02x", data[i]);
	}
	printf("\n");
#endif // #ifndef TEST_XEX
	fseek(wallet_test_file, (long)address, SEEK_SET);
	fwrite(data, (size_t)length, 1, wallet_test_file);
	return NV_NO_ERROR;
}

/** Read from non-volatile storage.
  * \param data A pointer to the buffer which will receive the data.
  * \param address Byte offset specifying where in non-volatile storage to
  *                start reading from.
  * \param length The number of bytes to read.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn nonVolatileRead(uint8_t *data, uint32_t address, uint8_t length)
{
	if ((address + (uint32_t)length) > TEST_FILE_SIZE)
	{
		return NV_INVALID_ADDRESS;
	}
	fseek(wallet_test_file, (long)address, SEEK_SET);
	fread(data, (size_t)length, 1, wallet_test_file);
	return NV_NO_ERROR;
}

/** Ensure that all buffered writes are committed to non-volatile storage. */
void nonVolatileFlush(void)
{
	fflush(wallet_test_file);
}

/** Pretend to overwrite anything in RAM which could contain sensitive
  * data. */
void sanitiseRam(void)
{
	// do nothing
}

#endif // #ifdef TEST

#ifdef TEST_WALLET

/** Call nearly all wallet functions and make sure they
  * return #WALLET_NOT_THERE somehow. This should only be called if a wallet
  * is not loaded. */
static void checkFunctionsReturnWalletNotThere(void)
{
	uint8_t temp[128];
	uint32_t check_num_addresses;
	AddressHandle ah;
	PointAffine public_key;

	// newWallet() not tested because it calls initWallet() when it's done.
	ah = makeNewAddress(temp, &public_key);
	if ((ah == BAD_ADDRESS_HANDLE) && (walletGetLastError() == WALLET_NOT_THERE))
	{
		reportSuccess();
	}
	else
	{
		printf("makeNewAddress() doesn't recognise when wallet isn't there\n");
		reportFailure();
	}
	check_num_addresses = getNumAddresses();
	if ((check_num_addresses == 0) && (walletGetLastError() == WALLET_NOT_THERE))
	{
		reportSuccess();
	}
	else
	{
		printf("getNumAddresses() doesn't recognise when wallet isn't there\n");
		reportFailure();
	}
	if (getAddressAndPublicKey(temp, &public_key, 0) == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise when wallet isn't there\n");
		reportFailure();
	}
	if (getPrivateKey(temp, 0) == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("getPrivateKey() doesn't recognise when wallet isn't there\n");
		reportFailure();
	}
	if (changeEncryptionKey(temp) == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("changeEncryptionKey() doesn't recognise when wallet isn't there\n");
		reportFailure();
	}
	if (changeWalletName(temp) == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("changeWalletName() doesn't recognise when wallet isn't there\n");
		reportFailure();
	}
}

int main(void)
{
	uint8_t temp[128];
	uint8_t address1[20];
	uint8_t address2[20];
	uint8_t name[NAME_LENGTH];
	uint8_t encryption_key[WALLET_ENCRYPTION_KEY_LENGTH];
	uint8_t new_encryption_key[WALLET_ENCRYPTION_KEY_LENGTH];
	uint8_t version[4];
	uint8_t *address_buffer;
	uint8_t one_byte;
	AddressHandle *handles_buffer;
	AddressHandle ah;
	PointAffine public_key;
	PointAffine *public_key_buffer;
	int abort;
	int is_zero;
	int abort_duplicate;
	int abort_error;
	int i;
	int j;

	initTests(__FILE__);

	initWalletTest();
	memset(encryption_key, 0, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	// Blank out non-volatile storage area (set to all nulls).
	temp[0] = 0;
	for (i = 0; i < TEST_FILE_SIZE; i++)
	{
		fwrite(temp, 1, 1, wallet_test_file);
	}

	// sanitiseNonVolatileStorage() should nuke everything.
	if (sanitiseNonVolatileStorage(0, 0xffffffff) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Cannot nuke NV storage using sanitiseNonVolatileStorage()\n");
		reportFailure();
	}

	// Check that the version field is "wallet not there".
	if (getWalletInfo(version, temp) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() failed after sanitiseNonVolatileStorage() was called\n");
		reportFailure();
	}
	if (readU32LittleEndian(version) == VERSION_NOTHING_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitiseNonVolatileStorage() does not set version to nothing there\n");
		reportFailure();
	}

	// initWallet() hasn't been called yet, so nearly every function should
	// return WALLET_NOT_THERE somehow.
	checkFunctionsReturnWalletNotThere();

	// The non-volatile storage area was blanked out, so there shouldn't be a
	// (valid) wallet there.
	if (initWallet() == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("initWallet() doesn't recognise when wallet isn't there\n");
		reportFailure();
	}

	// Try creating a wallet and testing initWallet() on it.
	memcpy(name, "123456789012345678901234567890abcdefghij", NAME_LENGTH);
	if (newWallet(name) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Could not create new wallet\n");
		reportFailure();
	}
	if (initWallet() == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("initWallet() does not recognise new wallet\n");
		reportFailure();
	}
	if ((getNumAddresses() == 0) && (walletGetLastError() == WALLET_EMPTY))
	{
		reportSuccess();
	}
	else
	{
		printf("New wallet isn't empty\n");
		reportFailure();
	}

	// Check that the version field is "unencrypted wallet".
	if (getWalletInfo(version, temp) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() failed after newWallet() was called\n");
		reportFailure();
	}
	if (readU32LittleEndian(version) == VERSION_UNENCRYPTED)
	{
		reportSuccess();
	}
	else
	{
		printf("newWallet() does not set version to unencrypted wallet\n");
		reportFailure();
	}

	// Check that sanitise_nv_wallet() deletes wallet.
	if (sanitiseNonVolatileStorage(0, 0xffffffff) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Cannot nuke NV storage using sanitiseNonVolatileStorage()\n");
		reportFailure();
	}
	if (initWallet() == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitiseNonVolatileStorage() isn't deleting wallet\n");
		reportFailure();
	}

	// Make some new addresses, then create a new wallet and make sure the
	// new wallet is empty (i.e. check that newWallet() deletes existing
	// wallet).
	newWallet(name);
	if (makeNewAddress(temp, &public_key) != BAD_ADDRESS_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		reportFailure();
	}
	newWallet(name);
	if ((getNumAddresses() == 0) && (walletGetLastError() == WALLET_EMPTY))
	{
		reportSuccess();
	}
	else
	{
		printf("newWallet() doesn't delete existing wallet\n");
		reportFailure();
	}

	// Unload wallet and make sure everything realises that the wallet is
	// not loaded.
	if (uninitWallet() == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("uninitWallet() failed to do its basic job\n");
		reportFailure();
	}
	checkFunctionsReturnWalletNotThere();

	// Load wallet again. Since there is actually a wallet there, this
	// should succeed.
	if (initWallet() == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("uninitWallet() appears to be permanent\n");
		reportFailure();
	}

	// Change bytes in non-volatile memory and make sure initWallet() fails
	// because of the checksum check.
	if (uninitWallet() != WALLET_NO_ERROR)
	{
		printf("uninitWallet() failed to do its basic job 2\n");
		reportFailure();
	}
	abort = 0;
	for (i = 0; i < WALLET_RECORD_LENGTH; i++)
	{
		if (nonVolatileRead(&one_byte, (uint32_t)i, 1) != NV_NO_ERROR)
		{
			printf("NV read fail\n");
			abort = 1;
			break;
		}
		one_byte++;
		if (nonVolatileWrite(&one_byte, (uint32_t)i, 1) != NV_NO_ERROR)
		{
			printf("NV write fail\n");
			abort = 1;
			break;
		}
		if (initWallet() == WALLET_NO_ERROR)
		{
			printf("Wallet still loads when wallet checksum is wrong, offset = %d\n", i);
			abort = 1;
			break;
		}
		one_byte--;
		if (nonVolatileWrite(&one_byte, (uint32_t)i, 1) != NV_NO_ERROR)
		{
			printf("NV write fail\n");
			abort = 1;
			break;
		}
	}
	if (!abort)
	{
		reportSuccess();
	}
	else
	{
		reportFailure();
	}

	// Create 2 new wallets and check that their addresses aren't the same
	newWallet(name);
	if (makeNewAddress(address1, &public_key) != BAD_ADDRESS_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		reportFailure();
	}
	newWallet(name);
	memset(address2, 0, 20);
	memset(&public_key, 0, sizeof(PointAffine));
	if (makeNewAddress(address2, &public_key) != BAD_ADDRESS_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		reportFailure();
	}
	if (memcmp(address1, address2, 20))
	{
		reportSuccess();
	}
	else
	{
		printf("New wallets are creating identical addresses\n");
		reportFailure();
	}

	// Check that makeNewAddress() wrote to its outputs.
	is_zero = 1;
	for (i = 0; i < 20; i++)
	{
		if (address2[i] != 0)
		{
			is_zero = 0;
			break;
		}
	}
	if (is_zero)
	{
		printf("makeNewAddress() doesn't write the address\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	if (bigIsZero(public_key.x))
	{
		printf("makeNewAddress() doesn't write the public key\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Make some new addresses, up to a limit.
	// Also check that addresses are unique.
	newWallet(name);
	abort = 0;
	address_buffer = malloc(MAX_TESTING_ADDRESSES * 20);
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		if (makeNewAddress(&(address_buffer[i * 20]), &public_key) == BAD_ADDRESS_HANDLE)
		{
			printf("Couldn't create new address in new wallet\n");
			abort = 1;
			break;
		}
		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(address_buffer[i * 20]), &(address_buffer[j * 20]), 20))
			{
				printf("Wallet addresses aren't unique\n");
				abort = 1;
				break;
			}
		}
		if (abort)
		{
			break;
		}
	}
	free(address_buffer);
	if (!abort)
	{
		reportSuccess();
	}
	else
	{
		reportFailure();
	}

	// The wallet should be full now.
	// Check that making a new address now causes an appropriate error.
	if (makeNewAddress(temp, &public_key) == BAD_ADDRESS_HANDLE)
	{
		if (walletGetLastError() == WALLET_FULL)
		{
			reportSuccess();
		}
		else
		{
			printf("Creating a new address on a full wallet gives incorrect error\n");
			reportFailure();
		}
	}
	else
	{
		printf("Creating a new address on a full wallet succeeds (it's not supposed to)\n");
		reportFailure();
	}

	// Check that getNumAddresses() fails when the wallet is empty.
	newWallet(name);
	if (getNumAddresses() == 0)
	{
		if (walletGetLastError() == WALLET_EMPTY)
		{
			reportSuccess();
		}
		else
		{
			printf("getNumAddresses() doesn't recognise wallet is empty\n");
			reportFailure();
		}
	}
	else
	{
		printf("getNumAddresses() succeeds when used on empty wallet\n");
		reportFailure();
	}

	// Create a bunch of addresses in the (now empty) wallet and check that
	// getNumAddresses() returns the right number.
	address_buffer = malloc(MAX_TESTING_ADDRESSES * 20);
	public_key_buffer = malloc(MAX_TESTING_ADDRESSES * sizeof(PointAffine));
	handles_buffer = malloc(MAX_TESTING_ADDRESSES * sizeof(AddressHandle));
	abort = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		ah = makeNewAddress(&(address_buffer[i * 20]), &(public_key_buffer[i]));
		handles_buffer[i] = ah;
		if (ah == BAD_ADDRESS_HANDLE)
		{
			printf("Couldn't create new address in new wallet\n");
			abort = 1;
			reportFailure();
			break;
		}
	}
	if (!abort)
	{
		reportSuccess();
	}
	if (getNumAddresses() == MAX_TESTING_ADDRESSES)
	{
		reportSuccess();
	}
	else
	{
		printf("getNumAddresses() returns wrong number of addresses\n");
		reportFailure();
	}

	// The wallet should contain unique addresses.
	abort_duplicate = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(address_buffer[i * 20]), &(address_buffer[j * 20]), 20))
			{
				printf("Wallet has duplicate addresses\n");
				abort_duplicate = 1;
				reportFailure();
				break;
			}
		}
	}
	if (!abort_duplicate)
	{
		reportSuccess();
	}

	// The wallet should contain unique public keys.
	abort_duplicate = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		for (j = 0; j < i; j++)
		{
			if (bigCompare(public_key_buffer[i].x, public_key_buffer[j].x) == BIGCMP_EQUAL)
			{
				printf("Wallet has duplicate public keys\n");
				abort_duplicate = 1;
				reportFailure();
				break;
			}
		}
	}
	if (!abort_duplicate)
	{
		reportSuccess();
	}

	// The address handles should start at 1 and be sequential.
	abort = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		if (handles_buffer[i] != (AddressHandle)(i + 1))
		{
			printf("Address handle %d should be %d, but got %d\n", i, i + 1, (int)handles_buffer[i]);
			abort = 1;
			reportFailure();
			break;
		}
	}
	if (!abort)
	{
		reportSuccess();
	}

	// While there's a bunch of addresses in the wallet, check that
	// getAddressAndPublicKey() obtains the same address and public key as
	// makeNewAddress().
	abort_error = 0;
	abort = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		ah = handles_buffer[i];
		if (getAddressAndPublicKey(address1, &public_key, ah) != WALLET_NO_ERROR)
		{
			printf("Couldn't obtain address in wallet\n");
			abort_error = 1;
			reportFailure();
			break;
		}
		if ((memcmp(address1, &(address_buffer[i * 20]), 20))
			|| (bigCompare(public_key.x, public_key_buffer[i].x) != BIGCMP_EQUAL)
			|| (bigCompare(public_key.y, public_key_buffer[i].y) != BIGCMP_EQUAL))
		{
			printf("getAddressAndPublicKey() returned mismatching address or public key, ah = %d\n", i);
			abort = 1;
			reportFailure();
			break;
		}
	}
	if (!abort)
	{
		reportSuccess();
	}
	if (!abort_error)
	{
		reportSuccess();
	}

	// Test getAddressAndPublicKey() and getPrivateKey() functions using
	// invalid and then valid address handles.
	if (getAddressAndPublicKey(temp, &public_key, 0) == WALLET_INVALID_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise 0 as invalid address handle\n");
		reportFailure();
	}
	if (getPrivateKey(temp, 0) == WALLET_INVALID_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("getPrivateKey() doesn't recognise 0 as invalid address handle\n");
		reportFailure();
	}
	if (getAddressAndPublicKey(temp, &public_key, BAD_ADDRESS_HANDLE) == WALLET_INVALID_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise BAD_ADDRESS_HANDLE as invalid address handle\n");
		reportFailure();
	}
	if (getPrivateKey(temp, BAD_ADDRESS_HANDLE) == WALLET_INVALID_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("getPrivateKey() doesn't recognise BAD_ADDRESS_HANDLE as invalid address handle\n");
		reportFailure();
	}
	if (getAddressAndPublicKey(temp, &public_key, handles_buffer[0]) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise valid address handle\n");
		reportFailure();
	}
	if (getPrivateKey(temp, handles_buffer[0]) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getPrivateKey() doesn't recognise valid address handle\n");
		reportFailure();
	}

	free(address_buffer);
	free(public_key_buffer);
	free(handles_buffer);

	// Check that changeEncryptionKey() works.
	memset(new_encryption_key, 0, WALLET_ENCRYPTION_KEY_LENGTH);
	new_encryption_key[0] = 1;
	if (changeEncryptionKey(new_encryption_key) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Couldn't change encryption key\n");
		reportFailure();
	}

	// Check that the version field is "encrypted wallet".
	if (getWalletInfo(version, temp) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() failed after changeEncryptionKey() was called\n");
		reportFailure();
	}
	if (readU32LittleEndian(version) == VERSION_IS_ENCRYPTED)
	{
		reportSuccess();
	}
	else
	{
		printf("changeEncryptionKey() does not set version to encrypted wallet\n");
		reportFailure();
	}

	// Check name matches what was given in newWallet().
	if (!memcmp(temp, name, NAME_LENGTH))
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() doesn't return correct name when wallet is loaded\n");
		reportFailure();
	}

	// Check that getWalletInfo() still works after unloading wallet.
	uninitWallet();
	if (getWalletInfo(version, temp) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() failed after uninitWallet() was called\n");
		reportFailure();
	}
	if (readU32LittleEndian(version) == VERSION_IS_ENCRYPTED)
	{
		reportSuccess();
	}
	else
	{
		printf("uninitWallet() caused wallet version to change\n");
		reportFailure();
	}

	// Check name matches what was given in newWallet().
	if (!memcmp(temp, name, NAME_LENGTH))
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() doesn't return correct name when wallet is not loaded\n");
		reportFailure();
	}

	// Change wallet's name and check that getWalletInfo() reflects the
	// name change.
	initWallet();
	memcpy(name, "HHHHH HHHHHHHHHHHHHHHHH HHHHHHHHHHHHHH  ", NAME_LENGTH);
	if (changeWalletName(name) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("changeWalletName() couldn't change name\n");
		reportFailure();
	}
	getWalletInfo(version, temp);
	if (!memcmp(temp, name, NAME_LENGTH))
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() doesn't reflect name change\n");
		reportFailure();
	}

	// Check that name change is preserved when unloading and loading a
	// wallet.
	uninitWallet();
	getWalletInfo(version, temp);
	if (!memcmp(temp, name, NAME_LENGTH))
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() doesn't reflect name change after unloading wallet\n");
		reportFailure();
	}

	// Check that initWallet() succeeds (changing the name changes the
	// checksum, so this tests whether the checksum was updated).
	if (initWallet() == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("initWallet() failed after name change\n");
		reportFailure();
	}
	getWalletInfo(version, temp);
	if (!memcmp(temp, name, NAME_LENGTH))
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() doesn't reflect name change after reloading wallet\n");
		reportFailure();
	}

	// Check that loading the wallet with the old key fails.
	uninitWallet();
	setEncryptionKey(encryption_key);
	if (initWallet() == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("Loading wallet with old encryption key succeeds\n");
		reportFailure();
	}

	// Check that loading the wallet with the new key succeeds.
	uninitWallet();
	setEncryptionKey(new_encryption_key);
	if (initWallet() == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Loading wallet with new encryption key fails\n");
		reportFailure();
	}

	// Test the getAddressAndPublicKey() and getPrivateKey() functions on an
	// empty wallet.
	newWallet(name);
	if (getAddressAndPublicKey(temp, &public_key, 0) == WALLET_EMPTY)
	{
		reportSuccess();
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't deal with empty wallets correctly\n");
		reportFailure();
	}
	if (getPrivateKey(temp, 0) == WALLET_EMPTY)
	{
		reportSuccess();
	}
	else
	{
		printf("getPrivateKey() doesn't deal with empty wallets correctly\n");
		reportFailure();
	}

	fclose(wallet_test_file);

	finishTests();
	exit(0);
}

#endif // #ifdef TEST_WALLET

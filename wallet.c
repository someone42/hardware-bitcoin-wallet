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
  * non-volatile storage space is needed per wallet.
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
#include <assert.h>
#endif // #ifdef TEST

#ifdef TEST_WALLET
#include "test_helpers.h"
#endif // #ifdef TEST_WALLET

#include <stddef.h>
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
#include "storage_common.h"
#include "hmac_sha512.h"
#include "pbkdf2.h"

/** Length of the checksum field of a wallet record. This is 32 since SHA-256
  * is used to calculate the checksum and the output of SHA-256 is 32 bytes
  * long. */
#define CHECKSUM_LENGTH			32

/** Structure of the unencrypted portion of a wallet record. */
struct WalletRecordUnencryptedStruct
{
	/** Wallet version. Should be one of #WalletVersion. */
	uint32_t version;
	/** Reserved for future use. Set to all zeroes. */
	uint8_t reserved[4];
	/** Name of the wallet. This is purely for the sake of the host; the
	  * name isn't ever used or parsed by the functions in this file. */
	uint8_t name[NAME_LENGTH];
	/** Wallet universal unique identifier (UUID). One way for the host to
	  * identify a wallet. */
	uint8_t uuid[UUID_LENGTH];
};

/** Structure of the encrypted portion of a wallet record. */
struct WalletRecordEncryptedStruct
{
	/** Number of addresses in this wallet. */
	uint32_t num_addresses;
	/** Random padding. This is random to try and thwart known-plaintext
	  * attacks. */
	uint8_t padding[8];
	/** Reserved for future use. Set to all zeroes. */
	uint8_t reserved[4];
	/** Seed for deterministic private key generator. */
	uint8_t seed[SEED_LENGTH];
	/** SHA-256 of everything except this. */
	uint8_t checksum[CHECKSUM_LENGTH];
};

/** Structure of a wallet record. */
typedef struct WalletRecordStruct
{
	/** Unencrypted portion. See #WalletRecordUnencryptedStruct for fields.
	  * \warning readWalletRecord() and writeCurrentWalletRecord() both assume
	  *          that this occurs before the encrypted portion.
	  */
	struct WalletRecordUnencryptedStruct unencrypted;
	/** Encrypted portion. See #WalletRecordEncryptedStruct for fields. */
	struct WalletRecordEncryptedStruct encrypted;
} WalletRecord;

/** The most recent error to occur in a function in this file,
  * or #WALLET_NO_ERROR if no error occurred in the most recent function
  * call. See #WalletErrorsEnum for possible values. */
static WalletErrors last_error;
/** This will be false if a wallet is not currently loaded. This will be true
  * if a wallet is currently loaded. */
static bool wallet_loaded;
/** Whether the currently loaded wallet is a hidden wallet. If
  * #wallet_loaded is false (i.e. no wallet is loaded), then the meaning of
  * this variable is undefined. */
static bool is_hidden_wallet;
/** This will only be valid if a wallet is loaded. It contains a cache of the
  * currently loaded wallet record. If #wallet_loaded is false (i.e. no wallet
  * is loaded), then the contents of this variable are undefined. */
static WalletRecord current_wallet;
/** The address in non-volatile memory where the currently loaded wallet
  * record is. If #wallet_loaded is false (i.e. no wallet is loaded), then the
  * contents of this variable are undefined. */
static uint32_t wallet_nv_address;
/** Cache of number of wallets that can fit in non-volatile storage. This will
  * be 0 if a value hasn't been calculated yet. This is set by
  * getNumberOfWallets(). */
static uint32_t num_wallets;

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

/** Set this to true to stop sanitiseNonVolatileStorage() from
  * updating the persistent entropy pool. This is necessary for some test
  * cases which check where sanitiseNonVolatileStorage() writes; updates
  * of the entropy pool would appear as spurious writes to those test cases.
  */
static bool suppress_set_entropy_pool;
#endif // #ifdef TEST_WALLET

/** Calculate the checksum (SHA-256 hash) of the current wallet's contents.
  * \param hash The resulting SHA-256 hash will be written here. This must
  *             be a byte array with space for #CHECKSUM_LENGTH bytes.
  * \return See #NonVolatileReturnEnum.
  */
static void calculateWalletChecksum(uint8_t *hash)
{
	uint8_t *ptr;
	unsigned int i;
	HashState hs;

	sha256Begin(&hs);
	ptr = (uint8_t *)&current_wallet;
	for (i = 0; i < sizeof(WalletRecord); i++)
	{
		// Skip checksum when calculating the checksum.
		if (i == offsetof(WalletRecord, encrypted.checksum))
		{
			i += sizeof(current_wallet.encrypted.checksum);
		}
		if (i < sizeof(WalletRecord))
		{
			sha256WriteByte(&hs, ptr[i]);
		}
	}
	sha256Finish(&hs);
	writeHashToByteArray(hash, &hs, true);
}

/** Load contents of non-volatile memory into a #WalletRecord structure. This
  * doesn't care if there is or isn't actually a wallet at the specified
  * address.
  * \param wallet_record Where to load the wallet record into.
  * \param address The address in non-volatile memory to read from.
  * \return See #WalletErrors.
  */
static WalletErrors readWalletRecord(WalletRecord *wallet_record, uint32_t address)
{
	uint32_t unencrypted_size;
	uint32_t encrypted_size;

	unencrypted_size = sizeof(wallet_record->unencrypted);
	encrypted_size = sizeof(wallet_record->encrypted);
	// Before doing any reading, do some sanity checks. These ensure that the
	// size of the unencrypted and encrypted portions are an integer multiple
	// of the AES block size.
	if (((unencrypted_size % 16) != 0) || ((encrypted_size % 16) != 0))
	{
		return WALLET_INVALID_OPERATION;
	}

	if (nonVolatileRead(
		(uint8_t *)&(wallet_record->unencrypted),
		PARTITION_ACCOUNTS,
		address + offsetof(WalletRecord, unencrypted),
		unencrypted_size) != NV_NO_ERROR)
	{
		return WALLET_READ_ERROR;
	}
	if (encryptedNonVolatileRead(
		(uint8_t *)&(wallet_record->encrypted),
		PARTITION_ACCOUNTS,
		address + offsetof(WalletRecord, encrypted),
		encrypted_size) != NV_NO_ERROR)
	{
		return WALLET_READ_ERROR;
	}
	return WALLET_NO_ERROR;
}

/** Store contents of #current_wallet into non-volatile memory. This will also
  * call nonVolatileFlush(), since that's usually what's wanted anyway.
  * \param address The address in non-volatile memory to write to.
  * \return See #WalletErrors.
  */
static WalletErrors writeCurrentWalletRecord(uint32_t address)
{
	if (nonVolatileWrite(
		(uint8_t *)&(current_wallet.unencrypted),
		PARTITION_ACCOUNTS,
		address + offsetof(WalletRecord, unencrypted),
		sizeof(current_wallet.unencrypted)) != NV_NO_ERROR)
	{
		return WALLET_WRITE_ERROR;
	}
	if (encryptedNonVolatileWrite(
		(uint8_t *)&(current_wallet.encrypted),
		PARTITION_ACCOUNTS,
		address + sizeof(current_wallet.unencrypted),
		sizeof(current_wallet.encrypted)) != NV_NO_ERROR)
	{
		return WALLET_WRITE_ERROR;
	}
	if (nonVolatileFlush() != NV_NO_ERROR)
	{
		return WALLET_WRITE_ERROR;
	}
	return WALLET_NO_ERROR;
}

/** Using the specified password and UUID (as the salt), derive an encryption
  * key and begin using it.
  *
  * This needs to be in wallet.c because there are situations (creating and
  * restoring a wallet) when the wallet UUID is not known before the beginning
  * of the appropriate function call.
  * \param uuid Byte array containing the wallet UUID. This must be
  *             exactly #UUID_LENGTH bytes long.
  * \param password Password to use in key derivation.
  * \param password_length Length of password, in bytes. Use 0 to specify no
  *                        password (i.e. wallet is unencrypted).
  */
static void deriveAndSetEncryptionKey(const uint8_t *uuid, const uint8_t *password, const unsigned int password_length)
{
	uint8_t derived_key[SHA512_HASH_LENGTH];

	if (sizeof(derived_key) < WALLET_ENCRYPTION_KEY_LENGTH)
	{
		fatalError(); // this should never happen
	}
	if (password_length > 0)
	{
		pbkdf2(derived_key, password, password_length, uuid, UUID_LENGTH);
		setEncryptionKey(derived_key);
	}
	else
	{
		// No password i.e. wallet is unencrypted.
		memset(derived_key, 0, sizeof(derived_key));
		setEncryptionKey(derived_key);
	}
}

/** Initialise a wallet (load it if it's there).
  * \param wallet_spec The wallet number of the wallet to load.
  * \param password Password to use to derive wallet encryption key.
  * \param password_length Length of password, in bytes. Use 0 to specify no
  *                        password (i.e. wallet is unencrypted).
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors initWallet(uint32_t wallet_spec, const uint8_t *password, const unsigned int password_length)
{
	WalletErrors r;
	uint8_t hash[CHECKSUM_LENGTH];
	uint8_t uuid[UUID_LENGTH];

	if (uninitWallet() != WALLET_NO_ERROR)
	{
		return last_error; // propagate error code
	}

	if (getNumberOfWallets() == 0)
	{
		return last_error; // propagate error code
	}
	if (wallet_spec >= num_wallets)
	{
		last_error = WALLET_INVALID_WALLET_NUM;
		return last_error;
	}
	wallet_nv_address = wallet_spec * sizeof(WalletRecord);

	if (nonVolatileRead(uuid, PARTITION_ACCOUNTS, wallet_nv_address + offsetof(WalletRecord, unencrypted.uuid), UUID_LENGTH) != NV_NO_ERROR)
	{
		last_error = WALLET_READ_ERROR;
		return last_error;
	}
	deriveAndSetEncryptionKey(uuid, password, password_length);

	r = readWalletRecord(&current_wallet, wallet_nv_address);
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return last_error;
	}

	if (current_wallet.unencrypted.version == VERSION_NOTHING_THERE)
	{
		is_hidden_wallet = true;
	}
	else if ((current_wallet.unencrypted.version == VERSION_UNENCRYPTED)
		|| (current_wallet.unencrypted.version == VERSION_IS_ENCRYPTED))
	{
		is_hidden_wallet = false;
	}
	else
	{
		last_error = WALLET_NOT_THERE;
		return last_error;
	}

	// Calculate checksum and check that it matches.
	calculateWalletChecksum(hash);
	if (bigCompareVariableSize(current_wallet.encrypted.checksum, hash, CHECKSUM_LENGTH) != BIGCMP_EQUAL)
	{
		last_error = WALLET_NOT_THERE;
		return last_error;
	}

	wallet_loaded = true;
	last_error = WALLET_NO_ERROR;
	return last_error;
}

/** Unload wallet, so that it cannot be used until initWallet() is called.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors uninitWallet(void)
{
	clearParentPublicKeyCache();
	wallet_loaded = false;
	is_hidden_wallet = false;
	wallet_nv_address = 0;
	memset(&current_wallet, 0, sizeof(WalletRecord));
	last_error = WALLET_NO_ERROR;
	return last_error;
}

#ifdef TEST_WALLET
void logVersionFieldWrite(uint32_t address);
#endif // #ifdef TEST_WALLET

/** Sanitise (clear) a selected area of non-volatile storage.
  * \param partition The partition the area is contained in. Must be one
  *                  of #NVPartitions.
  * \param start The first address within the partition which will be cleared.
  *              Must be a multiple of 4.
  * \param length The number of bytes to clear. Must be a multiple of 4.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
static WalletErrors sanitiseNonVolatileStorage(NVPartitions partition, uint32_t start, uint32_t length)
{
	uint8_t buffer[32];
	uint8_t pool_state[ENTROPY_POOL_LENGTH];
	uint32_t address;
	uint32_t bytes_written;
	uint32_t bytes_to_write;
	NonVolatileReturn r;
	uint8_t pass;

	if (getEntropyPool(pool_state))
	{
		last_error = WALLET_RNG_FAILURE;
		return last_error;
	}

	// The following check guards all occurrences of (address + length + offset)
	// from integer overflow, for all reasonable values of "offset".
	if ((start > 0x10000000) || (length >  0x10000000))
	{
		// address might overflow.
		last_error = WALLET_BAD_ADDRESS;
		return last_error;
	}

	// The "must be a multiple of 4" checks are there so that version fields
	// (which are 4 bytes long) are always either completely cleared or not
	// touched at all.
	if (((start % 4) != 0) || ((length % 4) != 0))
	{
		// start and length not multiples of 4.
		last_error = WALLET_BAD_ADDRESS;
		return last_error;
	}

	// 4 pass format: all 0s, all 1s, random, random. This ensures that
	// every bit is cleared at least once, set at least once and ends up
	// in an unpredictable state.
	// It is crucial that the last pass is random for two reasons:
	// 1. A new device UUID is written, if necessary.
	// 2. Hidden wallets are actually plausibly deniable.
	for (pass = 0; pass < 4; pass++)
	{
		address = start;
		bytes_written = 0;
		while (bytes_written < length)
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
				if (getRandom256TemporaryPool(buffer, pool_state))
				{
					// Before returning, attempt to write the persistent
					// entropy pool state back into non-volatile memory.
					// The return value of setEntropyPool() is ignored because
					// if a failure occurs, then WALLET_RNG_FAILURE is a
					// suitable return value anyway.
#ifdef TEST_WALLET
					if (!suppress_set_entropy_pool)
#endif // #ifdef TEST_WALLET
					{
						setEntropyPool(pool_state);
					}
					last_error = WALLET_RNG_FAILURE;
					return last_error;
				}
			}
			bytes_to_write = length - bytes_written;
			if (bytes_to_write > sizeof(buffer))
			{
				bytes_to_write = sizeof(buffer);
			}
			if (bytes_to_write > 0)
			{
				r = nonVolatileWrite(buffer, partition, address, bytes_to_write);
				if (r != NV_NO_ERROR)
				{
					last_error = WALLET_WRITE_ERROR;
					return last_error;
				}
			}
			address += bytes_to_write;
			bytes_written += bytes_to_write;
		} // end while (bytes_written < length)

		// After each pass, flush write buffers to ensure that
		// non-volatile memory is actually overwritten.
		r = nonVolatileFlush();
		if (r != NV_NO_ERROR)
		{
			last_error = WALLET_WRITE_ERROR;
			return last_error;
		}
	} // end for (pass = 0; pass < 4; pass++)

#ifdef TEST_WALLET
	if (!suppress_set_entropy_pool)
#endif // #ifdef TEST_WALLET
	{
		// Write back persistent entropy pool state.
		if (setEntropyPool(pool_state))
		{
			last_error = WALLET_RNG_FAILURE;
			return last_error;
		}
	}

	// At this point the selected area is now filled with random data.
	// Some functions in this file expect non-random data in certain locations.

	// If the selected area includes the device UUID, then a new device
	// UUID needs to be written. But if the selected area includes the
	// device UUID, then it will be overwritten with random data in the
	// above loop. Thus no additional work is needed.

	// Write VERSION_NOTHING_THERE to all possible locations of the
	// version field. This ensures that a wallet won't accidentally
	// (1 in 2 ^ 31 chance) be recognised as a valid wallet by
	// getWalletInfo().
	if (partition == PARTITION_ACCOUNTS)
	{
		address = start;
		address /= sizeof(WalletRecord);
		address *= sizeof(WalletRecord);
		address += offsetof(WalletRecord, unencrypted.version);
		// address is now rounded down to the first possible address where
		// the version field of a wallet could be stored.
		memset(buffer, 0, sizeof(uint32_t));
		while ((address + sizeof(uint32_t)) <= (start + length))
		{
			// An additional range check against start is needed because the
			// initial value of address is rounded down; thus it could be
			// rounded down below start.
			if (address >= start)
			{
				r = nonVolatileWrite(buffer, partition, address, sizeof(uint32_t));
				if (r == NV_NO_ERROR)
				{
					r = nonVolatileFlush();
				}
				else if (r != NV_NO_ERROR)
				{
					last_error = WALLET_WRITE_ERROR;
					return last_error;
				}
#ifdef TEST_WALLET
				if (r == NV_NO_ERROR)
				{
					logVersionFieldWrite(address);
				}
#endif // #ifdef TEST_WALLET
			}
			address += sizeof(WalletRecord);
		} // end while ((address + sizeof(uint32_t)) <= (start + length))
	} // end if (partition == PARTITION_ACCOUNTS)

	last_error = WALLET_NO_ERROR;
	return last_error;
}

/** Sanitise (clear) the entire contents of a partition.
  * \param partition The partition to clear. Must be one of #NVPartitions.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
static WalletErrors sanitisePartition(NVPartitions partition)
{
	uint32_t size;

	if (nonVolatileGetSize(&size, partition) != NV_NO_ERROR)
	{
		last_error = WALLET_BAD_ADDRESS;
		return last_error;
	}
	last_error = sanitiseNonVolatileStorage(partition, 0, size);
	return last_error;
}

/** Sanitise (clear) all partitions.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors sanitiseEverything(void)
{
	last_error = sanitisePartition(PARTITION_GLOBAL);
	if (last_error == WALLET_NO_ERROR)
	{
		last_error = sanitisePartition(PARTITION_ACCOUNTS);
	}
	return last_error;
}

/** Computes wallet version of current wallet. This is in its own function
  * because it's used by both newWallet() and changeEncryptionKey().
  * \return See #WalletErrors.
  */
static WalletErrors updateWalletVersion(void)
{
	if (is_hidden_wallet)
	{
		// Hidden wallets should not ever have their version fields updated;
		// that would give away their presence.
		return WALLET_INVALID_OPERATION;
	}
	if (isEncryptionKeyNonZero())
	{
		current_wallet.unencrypted.version = VERSION_IS_ENCRYPTED;
	}
	else
	{
		current_wallet.unencrypted.version = VERSION_UNENCRYPTED;
	}
	return WALLET_NO_ERROR;
}

/** Delete a wallet, so that it's contents can no longer be retrieved from
  * non-volatile storage.
  * \param wallet_spec The wallet number of the wallet to delete. The wallet
  *                    doesn't have to "exist"; calling this function for a
  *                    non-existent wallet will clear the non-volatile space
  *                    associated with it. This is useful for deleting a
  *                    hidden wallet.
  * \warning This is irreversible; the only way to access the wallet after
  *          deletion is to restore a backup.
  */
WalletErrors deleteWallet(uint32_t wallet_spec)
{
	uint32_t address;

	if (getNumberOfWallets() == 0)
	{
		return last_error; // propagate error code
	}
	if (wallet_spec >= num_wallets)
	{
		last_error = WALLET_INVALID_WALLET_NUM;
		return last_error;
	}
	// Always unload current wallet, just in case the current wallet is the
	// one being deleted.
	if (uninitWallet() != WALLET_NO_ERROR)
	{
		return last_error; // propagate error code
	}
	address = wallet_spec * sizeof(WalletRecord);
	last_error = sanitiseNonVolatileStorage(PARTITION_ACCOUNTS, address, sizeof(WalletRecord));
	return last_error;
}

/** Create new wallet. A brand new wallet contains no addresses and should
  * have a unique, unpredictable deterministic private key generation seed.
  * \param wallet_spec The wallet number of the new wallet.
  * \param name Should point to #NAME_LENGTH bytes (padded with spaces if
  *             necessary) containing the desired name of the wallet.
  * \param use_seed If this is true, then the contents of seed will be
  *                 used as the deterministic private key generation seed.
  *                 If this is false, then the contents of seed will be
  *                 ignored.
  * \param seed The deterministic private key generation seed to use in the
  *             new wallet. This should be a byte array of length #SEED_LENGTH
  *             bytes. This parameter will be ignored if use_seed is false.
  * \param make_hidden Whether to make the new wallet a hidden wallet.
  * \param password Password to use to derive wallet encryption key.
  * \param password_length Length of password, in bytes. Use 0 to specify no
  *                        password (i.e. wallet is unencrypted).
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred. If this returns #WALLET_NO_ERROR, then the
  *         wallet will also be loaded.
  * \warning This will erase the current one.
  */
WalletErrors newWallet(uint32_t wallet_spec, uint8_t *name, bool use_seed, uint8_t *seed, bool make_hidden, const uint8_t *password, const unsigned int password_length)
{
	uint8_t random_buffer[32];
	uint8_t uuid[UUID_LENGTH];
	WalletErrors r;

	if (uninitWallet() != WALLET_NO_ERROR)
	{
		return last_error; // propagate error code
	}

	if (getNumberOfWallets() == 0)
	{
		return last_error; // propagate error code
	}
	if (wallet_spec >= num_wallets)
	{
		last_error = WALLET_INVALID_WALLET_NUM;
		return last_error;
	}
	wallet_nv_address = wallet_spec * sizeof(WalletRecord);

	// Check for existing wallet.
	r = readWalletRecord(&current_wallet, wallet_nv_address);
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return last_error;
	}
	if (current_wallet.unencrypted.version != VERSION_NOTHING_THERE)
	{
		last_error = WALLET_ALREADY_EXISTS;
		return last_error;
	}

	if (make_hidden)
	{
		// The creation of a hidden wallet is supposed to be discreet, so
		// all unencrypted fields should be left untouched. This forces us to
		// use the existing UUID.
		memcpy(uuid, current_wallet.unencrypted.uuid, UUID_LENGTH);
	}
	else
	{
		// Generate wallet UUID now, because it is needed to derive the wallet
		// encryption key.
		if (getRandom256(random_buffer))
		{
			last_error = WALLET_RNG_FAILURE;
			return last_error;
		}
		memcpy(uuid, random_buffer, UUID_LENGTH);
	}
	deriveAndSetEncryptionKey(uuid, password, password_length);

	// Update unencrypted fields of current_wallet.
	if (!make_hidden)
	{
		r = updateWalletVersion();
		if (r != WALLET_NO_ERROR)
		{
			last_error = r;
			return last_error;
		}
		memset(current_wallet.unencrypted.reserved, 0, sizeof(current_wallet.unencrypted.reserved));
		memcpy(current_wallet.unencrypted.name, name, NAME_LENGTH);
		memcpy(current_wallet.unencrypted.uuid, uuid, UUID_LENGTH);
	}

	// Update encrypted fields of current_wallet.
	current_wallet.encrypted.num_addresses = 0;
	if (getRandom256(random_buffer))
	{
		last_error = WALLET_RNG_FAILURE;
		return last_error;
	}
	memcpy(current_wallet.encrypted.padding, random_buffer, sizeof(current_wallet.encrypted.padding));
	memset(current_wallet.encrypted.reserved, 0, sizeof(current_wallet.encrypted.reserved));
	if (use_seed)
	{
		memcpy(current_wallet.encrypted.seed, seed, SEED_LENGTH);
	}
	else
	{
		if (getRandom256(random_buffer))
		{
			last_error = WALLET_RNG_FAILURE;
			return last_error;
		}
		memcpy(current_wallet.encrypted.seed, random_buffer, 32);
		if (getRandom256(random_buffer))
		{
			last_error = WALLET_RNG_FAILURE;
			return last_error;
		}
		memcpy(&(current_wallet.encrypted.seed[32]), random_buffer, 32);
	}
	calculateWalletChecksum(current_wallet.encrypted.checksum);

	r = writeCurrentWalletRecord(wallet_nv_address);
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return last_error;
	}

	last_error = initWallet(wallet_spec, password, password_length);
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
	WalletErrors r;

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_LOADED;
		return BAD_ADDRESS_HANDLE;
	}
#ifdef TEST_WALLET
	if (current_wallet.encrypted.num_addresses >= MAX_TESTING_ADDRESSES)
#else
	if (current_wallet.encrypted.num_addresses >= MAX_ADDRESSES)
#endif // #ifdef TEST_WALLET
	{
		last_error = WALLET_FULL;
		return BAD_ADDRESS_HANDLE;
	}
	(current_wallet.encrypted.num_addresses)++;
	calculateWalletChecksum(current_wallet.encrypted.checksum);
	r = writeCurrentWalletRecord(wallet_nv_address);
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return BAD_ADDRESS_HANDLE;
	}
	last_error = getAddressAndPublicKey(out_address, out_public_key, current_wallet.encrypted.num_addresses);
	if (last_error != WALLET_NO_ERROR)
	{
		return BAD_ADDRESS_HANDLE;
	}
	else
	{
		return current_wallet.encrypted.num_addresses;
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
	uint8_t serialised[ECDSA_MAX_SERIALISE_SIZE];
	uint8_t serialised_size;
	HashState hs;
	WalletErrors r;
	uint8_t i;

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_LOADED;
		return last_error;
	}
	if (current_wallet.encrypted.num_addresses == 0)
	{
		last_error = WALLET_EMPTY;
		return last_error;
	}
	if ((ah == 0) || (ah > current_wallet.encrypted.num_addresses) || (ah == BAD_ADDRESS_HANDLE))
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
	// Calculate address.
	serialised_size = ecdsaSerialise(serialised, out_public_key, true);
	if (serialised_size < 2)
	{
		// Somehow, the public ended up as the point at infinity.
		last_error = WALLET_INVALID_HANDLE;
		return last_error;
	}
	sha256Begin(&hs);
	for (i = 0; i < serialised_size; i++)
	{
		sha256WriteByte(&hs, serialised[i]);
	}
	sha256Finish(&hs);
	writeHashToByteArray(buffer, &hs, true);
	ripemd160Begin(&hs);
	for (i = 0; i < 32; i++)
	{
		ripemd160WriteByte(&hs, buffer[i]);
	}
	ripemd160Finish(&hs);
	writeHashToByteArray(buffer, &hs, true);
	memcpy(out_address, buffer, 20);

	last_error = WALLET_NO_ERROR;
	return last_error;
}

/** Get the master public key of the currently loaded wallet. Every public key
  * (and address) in a wallet can be derived from the master public key and
  * chain code. However, even with posession of the master public key, all
  * private keys are still secret.
  * \param out_public_key The master public key will be written here.
  * \param out_chain_code The chain code will be written here. This must be a
  *                       byte array with space for 32 bytes.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getMasterPublicKey(PointAffine *out_public_key, uint8_t *out_chain_code)
{
	uint8_t local_seed[SEED_LENGTH]; // need a local copy to modify
	BigNum256 k_par;

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_LOADED;
		return last_error;
	}
	memcpy(local_seed, current_wallet.encrypted.seed, SEED_LENGTH);
	memcpy(out_chain_code, &(local_seed[32]), 32);
	k_par = (BigNum256)local_seed;
	swapEndian256(k_par); // since seed is big-endian
	setFieldToN();
	bigModulo(k_par, k_par); // just in case
	setToG(out_public_key);
	pointMultiply(out_public_key, k_par);
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
		last_error = WALLET_NOT_LOADED;
		return 0;
	}
	if (current_wallet.encrypted.num_addresses == 0)
	{
		last_error = WALLET_EMPTY;
		return 0;
	}
	else
	{
		last_error = WALLET_NO_ERROR;
		return current_wallet.encrypted.num_addresses;
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
	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_LOADED;
		return last_error;
	}
	if (current_wallet.encrypted.num_addresses == 0)
	{
		last_error = WALLET_EMPTY;
		return last_error;
	}
	if ((ah == 0) || (ah > current_wallet.encrypted.num_addresses) || (ah == BAD_ADDRESS_HANDLE))
	{
		last_error = WALLET_INVALID_HANDLE;
		return last_error;
	}
	if (generateDeterministic256(out, current_wallet.encrypted.seed, ah))
	{
		// This should never happen.
		last_error = WALLET_RNG_FAILURE;
		return last_error;
	}
	last_error = WALLET_NO_ERROR;
	return last_error;
}

/** Change the encryption key of a wallet.
  * \param password Password to use to derive wallet encryption key.
  * \param password_length Length of password, in bytes. Use 0 to specify no
  *                        password (i.e. wallet is unencrypted).
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors changeEncryptionKey(const uint8_t *password, const unsigned int password_length)
{
	WalletErrors r;

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_LOADED;
		return last_error;
	}

	deriveAndSetEncryptionKey(current_wallet.unencrypted.uuid, password, password_length);
	// Updating the version field for a hidden wallet would reveal
	// where it is, so don't do it.
	if (!is_hidden_wallet)
	{
		r = updateWalletVersion();
		if (r != WALLET_NO_ERROR)
		{
			last_error = r;
			return last_error;
		}
	}

	calculateWalletChecksum(current_wallet.encrypted.checksum);
	last_error = writeCurrentWalletRecord(wallet_nv_address);
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
	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_LOADED;
		return last_error;
	}
	if (is_hidden_wallet)
	{
		// Wallet name updates on a hidden wallet would reveal where it is
		// (since names are publicly visible), so don't allow name changes.
		last_error = WALLET_INVALID_OPERATION;
		return last_error;
	}

	memcpy(current_wallet.unencrypted.name, new_name, NAME_LENGTH);
	calculateWalletChecksum(current_wallet.encrypted.checksum);
	last_error = writeCurrentWalletRecord(wallet_nv_address);
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
  * \param out_version The version (see #WalletVersion) of the wallet will be
  *                    written to here (if everything goes well).
  * \param out_name The (space-padded) name of the wallet will be written
  *                 to here (if everything goes well). This should be a
  *                 byte array with enough space to store #NAME_LENGTH bytes.
  * \param out_uuid The wallet UUID will be written to here (if everything
  *                 goes well). This should be a byte array with enough space
  *                 to store #UUID_LENGTH bytes.
  * \param wallet_spec The wallet number of the wallet to query.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors getWalletInfo(uint32_t *out_version, uint8_t *out_name, uint8_t *out_uuid, uint32_t wallet_spec)
{
	WalletErrors r;
	WalletRecord local_wallet_record;
	uint32_t local_wallet_nv_address;

	if (getNumberOfWallets() == 0)
	{
		return last_error; // propagate error code
	}
	if (wallet_spec >= num_wallets)
	{
		last_error = WALLET_INVALID_WALLET_NUM;
		return last_error;
	}
	local_wallet_nv_address = wallet_spec * sizeof(WalletRecord);
	r = readWalletRecord(&local_wallet_record, local_wallet_nv_address);
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return last_error;
	}
	*out_version = local_wallet_record.unencrypted.version;
	memcpy(out_name, local_wallet_record.unencrypted.name, NAME_LENGTH);
	memcpy(out_uuid, local_wallet_record.unencrypted.uuid, UUID_LENGTH);

	last_error = WALLET_NO_ERROR;
	return last_error;
}

/** Initiate a wallet backup of the currently loaded wallet.
  * \param do_encrypt Whether the wallet backup will be written in encrypted
  *                   form.
  * \param destination_device See writeBackupSeed().
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors backupWallet(bool do_encrypt, uint32_t destination_device)
{
	uint8_t encrypted_seed[SEED_LENGTH];
	uint8_t n[16];
	bool r;
	uint8_t i;

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_LOADED;
		return last_error;
	}

	if (do_encrypt)
	{
#ifdef TEST
		assert(SEED_LENGTH % 16 == 0);
#endif
		memset(n, 0, 16);
		for (i = 0; i < SEED_LENGTH; i = (uint8_t)(i + 16))
		{
			writeU32LittleEndian(n, i);
			xexEncrypt(&(encrypted_seed[i]), &(current_wallet.encrypted.seed[i]), n, 1);
		}
		r = writeBackupSeed(encrypted_seed, do_encrypt, destination_device);
	}
	else
	{
		r = writeBackupSeed(current_wallet.encrypted.seed, do_encrypt, destination_device);
	}
	if (r)
	{
		last_error = WALLET_BACKUP_ERROR;
		return last_error;
	}
	else
	{
		last_error = WALLET_NO_ERROR;
		return last_error;
	}
}

/** Get the number of wallets which can fit in non-volatile storage, assuming
  * the storage format specified in storage_common.h.
  * This will set #num_wallets.
  * \return The number of wallets on success, or 0 if a read error occurred.
  */
uint32_t getNumberOfWallets(void)
{
	uint32_t size;

	last_error = WALLET_NO_ERROR;
	if (num_wallets == 0)
	{
		// Need to calculate number of wallets that can fit in non-volatile
		// storage.
		if (nonVolatileGetSize(&size, PARTITION_ACCOUNTS) == NV_NO_ERROR)
		{
			num_wallets = size / sizeof(WalletRecord);
		}
		else
		{
			last_error = WALLET_READ_ERROR;
			num_wallets = 0;
		}
	}
	return num_wallets;
}

#ifdef TEST

/** Size of global partition, in bytes. */
#define TEST_GLOBAL_PARTITION_SIZE		512
/** Size of accounts partition, in bytes. */
#define TEST_ACCOUNTS_PARTITION_SIZE	1024

/** Use this to stop nonVolatileWrite() from logging
  * all non-volatile writes to stdout. */
static bool suppress_write_debug_info;

/** Size of accounts partition. This can be modified to test the behaviour of
  * getNumberOfWallets(). */
static uint32_t accounts_partition_size = TEST_ACCOUNTS_PARTITION_SIZE;

#ifdef TEST_WALLET
/** Highest non-volatile address that nonVolatileWrite() has written to.
  * Index to this array = partition number. */
static uint32_t maximum_address_written[2];
/** Lowest non-volatile address that nonVolatileWrite() has written to.
  * Index to this array = partition number. */
static uint32_t minimum_address_written[2];
#endif // #ifdef TEST_WALLET

/** Get size of a partition.
  * \param out_size On success, the size of the partition (in number of bytes)
  *                 will be written here.
  * \param partition Partition to query. Must be one of #NVPartitions.
  * \return See #NonVolatileReturnEnum for return values.
  */
extern NonVolatileReturn nonVolatileGetSize(uint32_t *out_size, NVPartitions partition)
{
	if (partition == PARTITION_GLOBAL)
	{
		*out_size = TEST_GLOBAL_PARTITION_SIZE;
		return NV_NO_ERROR;
	}
	else if (partition == PARTITION_ACCOUNTS)
	{
		*out_size = accounts_partition_size;
		return NV_NO_ERROR;
	}
	else
	{
		return NV_INVALID_ADDRESS;
	}
}

/** Write to non-volatile storage. All platform-independent code assumes that
  * non-volatile memory acts like NOR flash/EEPROM: arbitrary bits may be
  * reset from 1 to 0 ("programmed") in any order, but setting bits
  * from 0 to 1 ("erasing") is very expensive.
  * \param data A pointer to the data to be written.
  * \param partition The partition to write to. Must be one of #NVPartitions.
  * \param address Byte offset specifying where in the partition to
  *                start writing to.
  * \param length The number of bytes to write.
  * \return See #NonVolatileReturnEnum for return values.
  * \warning Writes may be buffered; use nonVolatileFlush() to be sure that
  *          data is actually written to non-volatile storage.
  */
NonVolatileReturn nonVolatileWrite(uint8_t *data, NVPartitions partition, uint32_t address, uint32_t length)
{
	uint32_t partition_offset;
	uint32_t size;
	NonVolatileReturn r;
#if !defined(TEST_XEX) && !defined(TEST_PRANDOM)
	uint32_t i;
#endif // #if !defined(TEST_XEX) && !defined(TEST_PRANDOM)

	if ((address > 0x10000000) || (length > 0x10000000))
	{
		// address + length might overflow.
		return NV_INVALID_ADDRESS;
	}
	r = nonVolatileGetSize(&size, partition);
	if (r != NV_NO_ERROR)
	{
		return r;
	}
	if ((address + length) > size)
	{
		return NV_INVALID_ADDRESS;
	}

#ifdef TEST_WALLET
	if (length > 0)
	{
		if (address < minimum_address_written[partition])
		{
			minimum_address_written[partition] = address;
		}
		if ((address + length - 1) > maximum_address_written[partition])
		{
			maximum_address_written[partition] = address + length - 1;
		}
	}
#endif // #ifdef TEST_WALLET

	// Don't output write debugging info when testing xex.c or prandom.c,
	// otherwise the console will go crazy (since they do a lot of writing).
#if !defined(TEST_XEX) && !defined(TEST_PRANDOM)
	if (!suppress_write_debug_info)
	{
		printf("nv write, part = %d, addr = 0x%08x, length = 0x%04x, data =", (int)partition, (int)address, (int)length);
		for (i = 0; i < length; i++)
		{
			printf(" %02x", data[i]);
		}
		printf("\n");
	}
#endif // #if !defined(TEST_XEX) && !defined(TEST_PRANDOM)
	if (partition == PARTITION_GLOBAL)
	{
		partition_offset = 0;
	}
	else
	{
		assert(nonVolatileGetSize(&partition_offset, PARTITION_GLOBAL) == NV_NO_ERROR);
	}
	fseek(wallet_test_file, (long)(partition_offset + address), SEEK_SET);
	fwrite(data, (size_t)length, 1, wallet_test_file);
	return NV_NO_ERROR;
}

/** Read from non-volatile storage.
  * \param data A pointer to the buffer which will receive the data.
  * \param partition The partition to read from. Must be one of #NVPartitions.
  * \param address Byte offset specifying where in the partition to
  *                start reading from.
  * \param length The number of bytes to read.
  * \return See #NonVolatileReturnEnum for return values.
  */
extern NonVolatileReturn nonVolatileRead(uint8_t *data, NVPartitions partition, uint32_t address, uint32_t length)
{
	uint32_t partition_offset;
	uint32_t size;
	NonVolatileReturn r;

	if ((address > 0x10000000) || (length > 0x10000000))
	{
		// address + length might overflow.
		return NV_INVALID_ADDRESS;
	}
	r = nonVolatileGetSize(&size, partition);
	if (r != NV_NO_ERROR)
	{
		return r;
	}
	if ((address + length) > size)
	{
		return NV_INVALID_ADDRESS;
	}

	if (partition == PARTITION_GLOBAL)
	{
		partition_offset = 0;
	}
	else
	{
		assert(nonVolatileGetSize(&partition_offset, PARTITION_GLOBAL) == NV_NO_ERROR);
	}
	fseek(wallet_test_file, (long)(partition_offset + address), SEEK_SET);
	fread(data, (size_t)length, 1, wallet_test_file);
	return NV_NO_ERROR;
}

/** Ensure that all buffered writes are committed to non-volatile storage.
  * Since this is for testing only, this probably doesn't need to be called
  * at all.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn nonVolatileFlush(void)
{
	fflush(wallet_test_file);
	return NV_NO_ERROR;
}

/** Pretend to overwrite anything in RAM which could contain sensitive
  * data. */
void sanitiseRam(void)
{
	// do nothing
}

/** Where test wallet backups will be written to, for comparison. */
static uint8_t test_wallet_backup[SEED_LENGTH];

/** Write backup seed to some output device. The choice of output device and
  * seed representation is up to the platform-dependent code. But a typical
  * example would be displaying the seed as a hexadecimal string on a LCD.
  * \param seed A byte array of length #SEED_LENGTH bytes which contains the
  *             backup seed.
  * \param is_encrypted Specifies whether the seed has been encrypted.
  * \param destination_device Specifies which (platform-dependent) device the
  *                           backup seed should be sent to.
  * \return false on success, true if the backup seed could not be written
  *         to the destination device.
  */
bool writeBackupSeed(uint8_t *seed, bool is_encrypted, uint32_t destination_device)
{
	int i;

	if (destination_device > 0)
	{
		return true;
	}
	else
	{
		printf("Test wallet seed written:");
		for (i = 0; i < SEED_LENGTH; i++)
		{
			printf(" %02x", seed[i]);
		}
		printf("\n");
		if (is_encrypted)
		{
			printf("Seed is encrypted\n");
		}
		else
		{
			printf("Seed is unencrypted\n");
		}
		memcpy(test_wallet_backup, seed, SEED_LENGTH);
		return false;
	}
}

#endif // #ifdef TEST

#ifdef TEST_WALLET

/** List of non-volatile addresses that logVersionFieldWrite() received. */
uint32_t version_field_writes[TEST_ACCOUNTS_PARTITION_SIZE / sizeof(WalletRecord) + 2];
/** Index into #version_field_writes where next entry will be written. */
int version_field_index;

/** This will be called by sanitiseNonVolatileStorage() every time it
  * clears the version field of a wallet. This is used to test whether
  * sanitiseNonVolatileStorage() is clearing version fields properly.
  * \param address The address (in non-volatile storage) where the cleared
  *                version field is.
  */
void logVersionFieldWrite(uint32_t address)
{
	if (version_field_index < (sizeof(version_field_writes) / sizeof(uint32_t)))
	{
		version_field_writes[version_field_index++] = address;
	}
}

/** Clear the list of version field writes. */
void clearVersionFieldWriteLog(void)
{
	version_field_index = 0;
}

/** Call nearly all wallet functions and make sure they
  * return #WALLET_NOT_LOADED somehow. This should only be called if a wallet
  * is not loaded. */
static void checkFunctionsReturnWalletNotLoaded(void)
{
	uint8_t temp[128];
	uint32_t check_num_addresses;
	AddressHandle ah;
	PointAffine public_key;

	// newWallet() not tested because it calls initWallet() when it's done.
	ah = makeNewAddress(temp, &public_key);
	if ((ah == BAD_ADDRESS_HANDLE) && (walletGetLastError() == WALLET_NOT_LOADED))
	{
		reportSuccess();
	}
	else
	{
		printf("makeNewAddress() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	check_num_addresses = getNumAddresses();
	if ((check_num_addresses == 0) && (walletGetLastError() == WALLET_NOT_LOADED))
	{
		reportSuccess();
	}
	else
	{
		printf("getNumAddresses() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (getAddressAndPublicKey(temp, &public_key, 0) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (getPrivateKey(temp, 0) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("getPrivateKey() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (changeEncryptionKey(temp, 0) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("changeEncryptionKey() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (changeWalletName(temp) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("changeWalletName() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (backupWallet(false, 0) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("backupWallet() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (getMasterPublicKey(&public_key, temp) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("getMasterPublicKey() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
}

/** Call all wallet functions which accept a wallet number and check
  * that they fail or succeed for a given wallet number.
  * \param wallet_spec The wallet number to check.
  * \param should_succeed true if the wallet number is valid (and thus the
  *                       wallet functions should succeed), false if the wallet
  *                       number is not valid (and thus the wallet functions
  *                       should fail).
  */
static void checkWalletSpecFunctions(uint32_t wallet_spec, bool should_succeed)
{
	uint8_t wallet_uuid[UUID_LENGTH];
	uint8_t name[NAME_LENGTH];
	uint32_t version;
	WalletErrors wallet_return;

	memset(name, ' ', NAME_LENGTH);
	uninitWallet();
	wallet_return = newWallet(wallet_spec, name, false, NULL, false, NULL, 0);
	if (should_succeed && (wallet_return != WALLET_NO_ERROR))
	{
		printf("newWallet() failed with wallet number %u when it should have succeeded\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	if (!should_succeed && (wallet_return != WALLET_INVALID_WALLET_NUM))
	{
		printf("newWallet() did not return WALLET_INVALID_WALLET_NUM with wallet number %u when it should have\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	uninitWallet();
	// This call to initWallet() must be placed after the call to newWallet()
	// so that if should_succeed is true, there's a valid wallet in the
	// specified place.
	wallet_return = initWallet(wallet_spec, NULL, 0);
	if (should_succeed && (wallet_return != WALLET_NO_ERROR))
	{
		printf("initWallet() failed with wallet number %u when it should have succeeded\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	if (!should_succeed && (wallet_return != WALLET_INVALID_WALLET_NUM))
	{
		printf("initWallet() did not return WALLET_INVALID_WALLET_NUM with wallet number %u when it should have\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	uninitWallet();
	wallet_return = getWalletInfo(&version, name, wallet_uuid, wallet_spec);
	if (should_succeed && (wallet_return != WALLET_NO_ERROR))
	{
		printf("getWalletInfo() failed with wallet number %u when it should have succeeded\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	if (!should_succeed && (wallet_return != WALLET_INVALID_WALLET_NUM))
	{
		printf("getWalletInfo() did not return WALLET_INVALID_WALLET_NUM with wallet number %u when it should have\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
}

const uint8_t test_password0[] = "1234";
const uint8_t test_password1[] = "ABCDEFGHJ!!!!";
const uint8_t new_test_password[] = "new password";

int main(void)
{
	uint8_t temp[128];
	uint8_t address1[20];
	uint8_t address2[20];
	uint8_t compare_address[20];
	uint8_t name[NAME_LENGTH];
	uint8_t name2[NAME_LENGTH];
	uint8_t compare_name[NAME_LENGTH];
	uint8_t wallet_uuid[UUID_LENGTH];
	uint8_t wallet_uuid2[UUID_LENGTH];
	uint32_t version;
	uint8_t seed1[SEED_LENGTH];
	uint8_t seed2[SEED_LENGTH];
	uint8_t encrypted_seed[SEED_LENGTH];
	uint8_t chain_code[32];
	struct WalletRecordUnencryptedStruct unencrypted_part;
	struct WalletRecordUnencryptedStruct compare_unencrypted_part;
	uint8_t *address_buffer;
	uint8_t one_byte;
	uint32_t start_address;
	uint32_t end_address;
	uint32_t version_field_address;
	uint32_t returned_num_wallets;
	uint32_t stupidly_calculated_num_wallets;
	AddressHandle *handles_buffer;
	AddressHandle ah;
	PointAffine master_public_key;
	PointAffine public_key;
	PointAffine compare_public_key;
	PointAffine *public_key_buffer;
	bool abort;
	bool is_zero;
	bool abort_duplicate;
	bool abort_error;
	int i;
	int j;
	int version_field_counter;
	bool found;
	uint32_t histogram[256];
	uint32_t histogram_count;
	uint8_t copy_of_nv[TEST_GLOBAL_PARTITION_SIZE + TEST_ACCOUNTS_PARTITION_SIZE];
	uint8_t copy_of_nv2[TEST_GLOBAL_PARTITION_SIZE + TEST_ACCOUNTS_PARTITION_SIZE];
	uint8_t pool_state[ENTROPY_POOL_LENGTH];

	initTests(__FILE__);

	initWalletTest();
	initialiseDefaultEntropyPool();
	suppress_set_entropy_pool = false;
	// Blank out non-volatile storage area (set to all nulls).
	temp[0] = 0;
	for (i = 0; i < (TEST_GLOBAL_PARTITION_SIZE + TEST_ACCOUNTS_PARTITION_SIZE); i++)
	{
		fwrite(temp, 1, 1, wallet_test_file);
	}

	// Check that sanitiseEverything() is able to function with NV
	// storage in this state.
	minimum_address_written[PARTITION_GLOBAL] = 0xffffffff;
	maximum_address_written[PARTITION_GLOBAL] = 0;
	minimum_address_written[PARTITION_ACCOUNTS] = 0xffffffff;
	maximum_address_written[PARTITION_ACCOUNTS] = 0;
	if (sanitiseEverything() == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Cannot nuke NV storage using sanitiseEverything()\n");
		reportFailure();
	}

	// Check that sanitiseNonVolatileStorage() overwrote (almost) everything
	// with random data.
	memset(histogram, 0, sizeof(histogram));
	histogram_count = 0;
	fseek(wallet_test_file, 0, SEEK_SET);
	for (i = 0; i < (TEST_GLOBAL_PARTITION_SIZE + TEST_ACCOUNTS_PARTITION_SIZE); i++)
	{
		fread(temp, 1, 1, wallet_test_file);
		histogram[temp[0]]++;
		histogram_count++;
	}
	// "Random data" here is defined as: no value appears more than 1/16 of the time.
	abort = false;
	for (i = 0; i < 256; i++)
	{
		if (histogram[i] > (histogram_count / 16))
		{
			printf("sanitiseNonVolatileStorage() causes %02x to appear improbably often\n", i);
			reportFailure();
			abort = true;
		}
	}
	if (!abort)
	{
		reportSuccess();
	}

	// Check that sanitiseEverything() overwrote everything.
	if ((minimum_address_written[PARTITION_GLOBAL] != 0)
		|| (maximum_address_written[PARTITION_GLOBAL] != (TEST_GLOBAL_PARTITION_SIZE - 1))
		|| (minimum_address_written[PARTITION_ACCOUNTS] != 0)
		|| (maximum_address_written[PARTITION_ACCOUNTS] != (TEST_ACCOUNTS_PARTITION_SIZE - 1)))
	{
		printf("sanitiseEverything() did not overwrite everything\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that the version field is "wallet not there".
	if (getWalletInfo(&version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() failed after sanitiseNonVolatileStorage() was called\n");
		reportFailure();
	}
	if (version == VERSION_NOTHING_THERE)
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
	checkFunctionsReturnWalletNotLoaded();

	// The non-volatile storage area was blanked out, so there shouldn't be a
	// (valid) wallet there.
	if (initWallet(0, NULL, 0) == WALLET_NOT_THERE)
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
	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Could not create new wallet\n");
		reportFailure();
	}
	if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
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
	if (getWalletInfo(&version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() failed after newWallet() was called\n");
		reportFailure();
	}
	if (version == VERSION_UNENCRYPTED)
	{
		reportSuccess();
	}
	else
	{
		printf("newWallet() does not set version to unencrypted wallet\n");
		reportFailure();
	}

	// Check that sanitise_nv_wallet() deletes wallet.
	if (sanitiseEverything() == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Cannot nuke NV storage using sanitiseNonVolatileStorage()\n");
		reportFailure();
	}
	if (initWallet(0, NULL, 0) == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitiseEverything() isn't deleting wallet\n");
		reportFailure();
	}

	// Check that newWallet() works.
	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("newWallet() fails for recently sanitised NV storage\n");
		reportFailure();
	}
	if (makeNewAddress(temp, &public_key) != BAD_ADDRESS_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		reportFailure();
	}

	// newWallet() shouldn't overwrite an existing wallet.
	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_ALREADY_EXISTS)
	{
		reportSuccess();
	}
	else
	{
		printf("newWallet() overwrites existing wallet\n");
		reportFailure();
	}

	// Check that a deleteWallet()/newWallet() sequence does overwrite an
	// existing wallet.
	if (deleteWallet(0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("deleteWallet() failed\n");
		reportFailure();
	}
	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("newWallet() fails for recently deleted wallet\n");
		reportFailure();
	}

	// Check that deleteWallet() deletes wallet.
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("initWallet() failed just after calling newWallet()\n");
		reportFailure();
	}
	deleteWallet(0);
	if (initWallet(0, NULL, 0) == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("deleteWallet() isn't deleting wallet\n");
		reportFailure();
	}

	// Check that deleteWallet() doesn't affect other wallets.
	deleteWallet(0);
	deleteWallet(1);
	newWallet(0, name, false, NULL, false, NULL, 0);
	newWallet(1, name, false, NULL, false, NULL, 0);
	deleteWallet(1);
	if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("deleteWallet() collateral damage to wallet 0\n");
		reportFailure();
	}
	deleteWallet(0);
	deleteWallet(1);
	newWallet(0, name, false, NULL, false, NULL, 0);
	newWallet(1, name, false, NULL, false, NULL, 0);
	deleteWallet(0);
	if (initWallet(1, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("deleteWallet() collateral damage to wallet 1\n");
		reportFailure();
	}

	// Make some new addresses, then delete it and create a new wallet,
	// making sure the new wallet is empty (i.e. check that deleteWallet()
	// actually deletes a wallet).
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	if (makeNewAddress(temp, &public_key) != BAD_ADDRESS_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("Couldn't create new address in new wallet 2\n");
		reportFailure();
	}
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	if ((getNumAddresses() == 0) && (walletGetLastError() == WALLET_EMPTY))
	{
		reportSuccess();
	}
	else
	{
		printf("deleteWallet() doesn't delete existing wallet\n");
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
	checkFunctionsReturnWalletNotLoaded();

	// Load wallet again. Since there is actually a wallet there, this
	// should succeed.
	if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
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
	abort = false;
	for (i = 0; i < sizeof(WalletRecord); i++)
	{
		if (nonVolatileRead(&one_byte, PARTITION_ACCOUNTS, (uint32_t)i, 1) != NV_NO_ERROR)
		{
			printf("NV read fail\n");
			abort = true;
			break;
		}
		one_byte++;
		if (nonVolatileWrite(&one_byte, PARTITION_ACCOUNTS, (uint32_t)i, 1) != NV_NO_ERROR)
		{
			printf("NV write fail\n");
			abort = true;
			break;
		}
		if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
		{
			printf("Wallet still loads when wallet checksum is wrong, offset = %d\n", i);
			abort = true;
			break;
		}
		one_byte--;
		if (nonVolatileWrite(&one_byte, PARTITION_ACCOUNTS, (uint32_t)i, 1) != NV_NO_ERROR)
		{
			printf("NV write fail\n");
			abort = true;
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

	// deleteWallet() should succeed even if aimed at a wallet that
	// "isn't there"; this is how hidden wallets can be deleted.
	deleteWallet(0);
	if (deleteWallet(0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("deleteWallet() can't delete wallet that isn't there\n");
		reportFailure();
	}

	// Create 2 new wallets and check that their addresses aren't the same
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	if (makeNewAddress(address1, &public_key) != BAD_ADDRESS_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		reportFailure();
	}
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
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
	is_zero = true;
	for (i = 0; i < 20; i++)
	{
		if (address2[i] != 0)
		{
			is_zero = false;
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
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	abort = false;
	abort_error = false;
	address_buffer = (uint8_t *)malloc(MAX_TESTING_ADDRESSES * 20);
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		if (makeNewAddress(&(address_buffer[i * 20]), &public_key) == BAD_ADDRESS_HANDLE)
		{
			printf("Couldn't create new address in new wallet\n");
			reportFailure();
			abort_error = true;
			break;
		}
		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(address_buffer[i * 20]), &(address_buffer[j * 20]), 20))
			{
				printf("Wallet addresses aren't unique\n");
				reportFailure();
				abort = true;
				break;
			}
		}
		if (abort || abort_error)
		{
			break;
		}
	}
	free(address_buffer);
	if (!abort)
	{
		reportSuccess();
	}
	if (!abort_error)
	{
		reportSuccess();
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
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
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
	address_buffer = (uint8_t *)malloc(MAX_TESTING_ADDRESSES * 20);
	public_key_buffer = (PointAffine *)malloc(MAX_TESTING_ADDRESSES * sizeof(PointAffine));
	handles_buffer = (AddressHandle *)malloc(MAX_TESTING_ADDRESSES * sizeof(AddressHandle));
	abort = false;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		ah = makeNewAddress(&(address_buffer[i * 20]), &(public_key_buffer[i]));
		handles_buffer[i] = ah;
		if (ah == BAD_ADDRESS_HANDLE)
		{
			printf("Couldn't create new address in new wallet\n");
			abort = true;
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
	abort_duplicate = false;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(address_buffer[i * 20]), &(address_buffer[j * 20]), 20))
			{
				printf("Wallet has duplicate addresses\n");
				abort_duplicate = true;
				reportFailure();
				break;
			}
		}
		if (abort_duplicate)
		{
			break;
		}
	}
	if (!abort_duplicate)
	{
		reportSuccess();
	}

	// The wallet should contain unique public keys.
	abort_duplicate = false;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		for (j = 0; j < i; j++)
		{
			if (bigCompare(public_key_buffer[i].x, public_key_buffer[j].x) == BIGCMP_EQUAL)
			{
				printf("Wallet has duplicate public keys\n");
				abort_duplicate = true;
				reportFailure();
				break;
			}
		}
		if (abort_duplicate)
		{
			break;
		}
	}
	if (!abort_duplicate)
	{
		reportSuccess();
	}

	// The address handles should start at 1 and be sequential.
	abort = false;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		if (handles_buffer[i] != (AddressHandle)(i + 1))
		{
			printf("Address handle %d should be %d, but got %d\n", i, i + 1, (int)handles_buffer[i]);
			abort = true;
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
	abort_error = false;
	abort = false;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		ah = handles_buffer[i];
		if (getAddressAndPublicKey(address1, &public_key, ah) != WALLET_NO_ERROR)
		{
			printf("Couldn't obtain address in wallet\n");
			abort_error = true;
			reportFailure();
			break;
		}
		if ((memcmp(address1, &(address_buffer[i * 20]), 20))
			|| (bigCompare(public_key.x, public_key_buffer[i].x) != BIGCMP_EQUAL)
			|| (bigCompare(public_key.y, public_key_buffer[i].y) != BIGCMP_EQUAL))
		{
			printf("getAddressAndPublicKey() returned mismatching address or public key, ah = %d\n", i);
			abort = true;
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
	if (changeEncryptionKey(new_test_password, sizeof(new_test_password)) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Couldn't change encryption key\n");
		reportFailure();
	}

	// Check that the version field is "encrypted wallet".
	if (getWalletInfo(&version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() failed after changeEncryptionKey() was called\n");
		reportFailure();
	}
	if (version == VERSION_IS_ENCRYPTED)
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
	if (getWalletInfo(&version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() failed after uninitWallet() was called\n");
		reportFailure();
	}
	if (version == VERSION_IS_ENCRYPTED)
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
	initWallet(0, new_test_password, sizeof(new_test_password));
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
	getWalletInfo(&version, temp, wallet_uuid, 0);
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
	getWalletInfo(&version, temp, wallet_uuid, 0);
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
	if (initWallet(0, new_test_password, sizeof(new_test_password)) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("initWallet() failed after name change\n");
		reportFailure();
	}
	getWalletInfo(&version, temp, wallet_uuid, 0);
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
	if (initWallet(0, NULL, 0) == WALLET_NOT_THERE)
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
	if (initWallet(0, new_test_password, sizeof(new_test_password)) == WALLET_NO_ERROR)
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
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
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

	// Test wallet backup to valid device.
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	if (backupWallet(false, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Unencrypted backupWallet() doesn't work\n");
		reportFailure();
	}
	memcpy(seed1, test_wallet_backup, SEED_LENGTH);
	makeNewAddress(address1, &public_key); // save this for later

	// Test wallet backup to invalid device.
	if (backupWallet(false, 1) == WALLET_BACKUP_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("backupWallet() doesn't deal with invalid device correctly\n");
		reportFailure();
	}

	// Delete wallet and check that seed of a new wallet is different.
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	backupWallet(false, 0);
	memcpy(seed2, test_wallet_backup, SEED_LENGTH);
	if (memcmp(seed1, seed2, SEED_LENGTH))
	{
		reportSuccess();
	}
	else
	{
		printf("Seed of new wallet matches older one.\n");
		reportFailure();
	}

	// Try to restore a wallet backup.
	deleteWallet(0);
	if (newWallet(0, name, true, seed1, false, test_password0, sizeof(test_password0)) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Could not restore wallet\n");
		reportFailure();
	}

	// Does the first address of the restored wallet match the old wallet?
	makeNewAddress(address2, &public_key);
	if (!memcmp(address1, address2, 20))
	{
		reportSuccess();
	}
	else
	{
		printf("Restored wallet doesn't generate the same address\n");
		reportFailure();
	}

	// Test wallet backup with encryption.
	if (backupWallet(true, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Encrypted backupWallet() doesn't work\n");
		reportFailure();
	}
	memcpy(encrypted_seed, test_wallet_backup, SEED_LENGTH);

	// Decrypt the encrypted seed and check it matches the unencrypted one.
	memset(temp, 0, 16);
	for (i = 0; i < SEED_LENGTH; i += 16)
	{
		writeU32LittleEndian(temp, (uint32_t)i);
		xexDecrypt(&(seed2[i]), &(encrypted_seed[i]), temp, 1);
	}
	if (!memcmp(seed1, seed2, SEED_LENGTH))
	{
		reportSuccess();
	}
	else
	{
		printf("Decrypted seed does not match encrypted one.\n");
		reportFailure();
	}

	// Test that sanitiseNonVolatileStorage() doesn't accept addresses which
	// aren't a multiple of 4.
	if (sanitiseNonVolatileStorage(PARTITION_GLOBAL, 1, 16) == WALLET_BAD_ADDRESS)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitiseNonVolatileStorage() accepts start address which is not a multiple of 4\n");
		reportFailure();
	}
	if (sanitiseNonVolatileStorage(PARTITION_GLOBAL, 0, 15) == WALLET_BAD_ADDRESS)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitiseNonVolatileStorage() accepts length which is not a multiple of 4\n");
		reportFailure();
	}

	// Test that sanitiseNonVolatileStorage() detects possible overflows.
	if (sanitiseNonVolatileStorage(PARTITION_GLOBAL, 0x80000000, 0x80000000) == WALLET_BAD_ADDRESS)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitiseNonVolatileStorage() not detecting overflow 1\n");
		reportFailure();
	}
	if (sanitiseNonVolatileStorage(PARTITION_GLOBAL, 0xffffffff, 1) == WALLET_BAD_ADDRESS)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitiseNonVolatileStorage() not detecting overflow 2\n");
		reportFailure();
	}
	if (sanitiseNonVolatileStorage(PARTITION_GLOBAL, 1, 0xffffffff) == WALLET_BAD_ADDRESS)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitiseNonVolatileStorage() not detecting overflow 3\n");
		reportFailure();
	}

	// Test that sanitiseNonVolatileStorage() clears the correct area.
	// Previously, sanitiseNonVolatileStorage() required the start and end
	// parameters to be a multiple of 32 (because it uses a write buffer
	// with that length). That restriction has since been relaxed. This test
	// case checks that the code handles non-multiples of 32 properly.
	suppress_write_debug_info = true; // stop console from going crazy
	suppress_set_entropy_pool = true; // avoid spurious entropy pool update writes
	abort = false;
	for (i = 0; i < 2000; i++)
	{
		initialiseDefaultEntropyPool(); // needed in case pool or checksum gets corrupted by writes
		minimum_address_written[PARTITION_ACCOUNTS] = 0xffffffff;
		maximum_address_written[PARTITION_ACCOUNTS] = 0;
		start_address = (uint32_t)((rand() % TEST_ACCOUNTS_PARTITION_SIZE) & 0xfffffffc);
		end_address = start_address + (uint32_t)((rand() % TEST_ACCOUNTS_PARTITION_SIZE) & 0xfffffffc);
		if (end_address > TEST_ACCOUNTS_PARTITION_SIZE)
		{
			end_address = TEST_ACCOUNTS_PARTITION_SIZE;
		}
		if (start_address != end_address)
		{
			sanitiseNonVolatileStorage(PARTITION_ACCOUNTS, start_address, end_address - start_address);
			if ((minimum_address_written[PARTITION_ACCOUNTS] != start_address)
				|| (maximum_address_written[PARTITION_ACCOUNTS] != (end_address - 1)))
			{
				printf("sanitiseNonVolatileStorage() not clearing correct area\n");
				printf("start = 0x%08x, end = 0x%08x\n", start_address, end_address);
				abort = true;
				reportFailure();
				break;
			}
		}
	}
	if (!abort)
	{
		reportSuccess();
	}

	// Also check that sanitiseNonVolatileStorage() does nothing if length is 0.
	initialiseDefaultEntropyPool(); // needed in case pool or checksum gets corrupted by writes
	minimum_address_written[PARTITION_ACCOUNTS] = 0xffffffff;
	maximum_address_written[PARTITION_ACCOUNTS] = 0;
	// Use offsetof(WalletRecord, unencrypted.version) to try and
	// trick the "clear version field" logic.
	start_address = offsetof(WalletRecord, unencrypted.version);
	sanitiseNonVolatileStorage(PARTITION_ACCOUNTS, start_address, 0);
	if ((minimum_address_written[PARTITION_ACCOUNTS] != 0xffffffff) || (maximum_address_written[PARTITION_ACCOUNTS] != 0))
	{
		printf("sanitiseNonVolatileStorage() clearing something when it's not supposed to\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that sanitiseNonVolatileStorage() is clearing the correct version
	// fields of any wallets in range.
	suppress_write_debug_info = true; // stop console from going crazy
	suppress_set_entropy_pool = false;
	abort = false;
	for (i = 0; i < 5000; i++)
	{
		start_address = (uint32_t)((rand() % TEST_ACCOUNTS_PARTITION_SIZE) & 0xfffffffc);
		end_address = start_address + (uint32_t)((rand() % TEST_ACCOUNTS_PARTITION_SIZE) & 0xfffffffc);
		if (end_address > TEST_ACCOUNTS_PARTITION_SIZE)
		{
			end_address = TEST_ACCOUNTS_PARTITION_SIZE;
		}
		initialiseDefaultEntropyPool(); // needed in case pool or checksum gets corrupted by writes
		clearVersionFieldWriteLog();
		sanitiseNonVolatileStorage(PARTITION_ACCOUNTS, start_address, end_address - start_address);
		// version_field_address is stepped through every possible address
		// (ignoring start_address and end_address) that could hold a wallet's
		// version field.
		version_field_address = (uint8_t *)&(current_wallet.unencrypted.version) - (uint8_t *)&current_wallet;
		version_field_counter = 0;
		while ((version_field_address + 4) <= TEST_ACCOUNTS_PARTITION_SIZE)
		{
			if ((version_field_address >= start_address)
				&& ((version_field_address + 4) <= end_address))
			{
				// version_field_address should be in the list somewhere.
				found = false;
				for (j = 0; j < version_field_index; j++)
				{
					if (version_field_address == version_field_writes[j])
					{
						found = true;
						break;
					}
				}
				if (!found)
				{
					printf("sanitiseNonVolatileStorage() did not clear version field at 0x%08x\n", version_field_address);
					reportFailure();
					abort = true;
					break;
				}
				version_field_counter++;
			}
			version_field_address += sizeof(WalletRecord);
		} // end while ((version_field_address + 4) <= TEST_ACCOUNTS_PARTITION_SIZE)
		if (abort)
		{
			break;
		}

		// sanitiseNonVolatileStorage() should clear the version fields of any
		// wallets in range, but it should also ignore all version fields not
		// in range.
		if (version_field_counter != version_field_index)
		{
			printf("sanitiseNonVolatileStorage() is clearing out of range version fields\n");
			reportFailure();
			abort = true;
			break;
		}
	} // end for (i = 0; i < 5000; i++)
	if (!abort)
	{
		reportSuccess();
	}
	suppress_write_debug_info = false; // can start reporting writes again

	// Check that sanitising the global partition does not touch any version
	// fields.
	clearVersionFieldWriteLog();
	sanitisePartition(PARTITION_GLOBAL);
	if (version_field_index == 0)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitisePartition(PARTITION_GLOBAL) is touching version fields\n");
		reportFailure();
	}

	// Check that sanitising the accounts partition touches all version fields.
	clearVersionFieldWriteLog();
	sanitisePartition(PARTITION_ACCOUNTS);
	// version_field_address is stepped through every possible address
	// (ignoring start_address and end_address) that could hold a wallet's
	// version field.
	version_field_address = (uint8_t *)&(current_wallet.unencrypted.version) - (uint8_t *)&current_wallet;
	version_field_counter = 0;
	while ((version_field_address + 4) <= TEST_ACCOUNTS_PARTITION_SIZE)
	{
		version_field_counter++;
		version_field_address += sizeof(WalletRecord);
	} // end while ((version_field_address + 4) <= TEST_ACCOUNTS_PARTITION_SIZE)
	if (version_field_index == version_field_counter)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitisePartition(PARTITION_ACCOUNTS) not touching all version fields\n");
		reportFailure();
	}

	// Check that getNumberOfWallets() works and returns the appropriate value
	// for various non-volatile storage sizes.
	abort = false;
	abort_error = false;
	// Step in increments of 1 byte to look for off-by-one errors.
	for (i = TEST_ACCOUNTS_PARTITION_SIZE; i < TEST_ACCOUNTS_PARTITION_SIZE + 1024; i++)
	{
		accounts_partition_size = i;
		num_wallets = 0; // reset cache
		returned_num_wallets = getNumberOfWallets();
		if (returned_num_wallets == 0)
		{
			printf("getNumberOfWallets() doesn't work\n");
			reportFailure();
			abort_error = true;
			break;
		}
		stupidly_calculated_num_wallets = 0;
		for (j = 0; (int)(j + (sizeof(WalletRecord) - 1)) < i; j += sizeof(WalletRecord))
		{
			stupidly_calculated_num_wallets++;
		}
		if (stupidly_calculated_num_wallets != returned_num_wallets)
		{
			printf("getNumberOfWallets() returning inappropriate value\n");
			reportFailure();
			abort = true;
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
	accounts_partition_size = TEST_ACCOUNTS_PARTITION_SIZE;
	num_wallets = 0; // reset cache for next test

	// For all functions which accept wallet numbers, try some wallet numbers
	// which are in or out of range.
	returned_num_wallets = getNumberOfWallets();
	checkWalletSpecFunctions(0, true); // first one
	// The next line does assume that returned_num_wallets > 1.
	checkWalletSpecFunctions(returned_num_wallets - 1, true); // last one
	checkWalletSpecFunctions(returned_num_wallets, false); // out of range
	// The next line does assume that returned_num_wallets != 0xffffffff.
	checkWalletSpecFunctions(returned_num_wallets + 1, false); // out of range
	checkWalletSpecFunctions(0xffffffff, false); // out of range

	// Create one wallet and some addresses, then create another wallet with a
	// different wallet number and see if it overwrites the first one
	// (it shouldn't).
	uninitWallet();
	memcpy(name, "A wallet with wallet number 0           ", NAME_LENGTH);
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	makeNewAddress(address1, &public_key);
	makeNewAddress(address1, &public_key);
	makeNewAddress(address1, &public_key);
	uninitWallet();
	memcpy(name2, "A wallet with wallet number 1           ", NAME_LENGTH);
	deleteWallet(1);
	newWallet(1, name2, false, NULL, false, NULL, 0);
	makeNewAddress(address2, &public_key);
	makeNewAddress(address2, &public_key);
	uninitWallet();
	initWallet(0, NULL, 0);
	ah = getNumAddresses();
	getAddressAndPublicKey(compare_address, &public_key, ah);
	if (memcmp(address1, compare_address, 20))
	{
		printf("Creating wallet 1 seems to mangle wallet 0\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	// Now:
	// name contains name of wallet 0,
	// name2 contains name of wallet 1,
	// address1 contains the most recently created address in wallet 0,
	// address2 contains the most recently created address in wallet 1.

	// Unload wallet 0 then load wallet 1 and make sure wallet 1 was loaded.
	uninitWallet();
	initWallet(1, NULL, 0);
	ah = getNumAddresses();
	getAddressAndPublicKey(compare_address, &public_key, ah);
	if (memcmp(address2, compare_address, 20))
	{
		printf("Loading wallet 0 seems to prevent wallet 1 from being loaded\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check getWalletInfo() returns the name that was set for both wallets.
	getWalletInfo(&version, compare_name, wallet_uuid, 0);
	if (memcmp(name, compare_name, NAME_LENGTH))
	{
		printf("Wallet 0's name got mangled\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	getWalletInfo(&version, compare_name, wallet_uuid, 1);
	if (memcmp(name2, compare_name, NAME_LENGTH))
	{
		printf("Wallet 1's name got mangled\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Set wallet 1 to have a different encryption key from wallet 0 and
	// check that the correct encryption key (and only that one) works.
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, test_password0, sizeof(test_password0));
	makeNewAddress(address1, &public_key);
	uninitWallet();
	deleteWallet(1);
	newWallet(1, name2, false, NULL, false, test_password1, sizeof(test_password1));
	makeNewAddress(address2, &public_key);
	uninitWallet();
	if (initWallet(0, test_password0, sizeof(test_password0)) != WALLET_NO_ERROR)
	{
		printf("Cannot load wallet 0 with correct key\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();
	if (initWallet(0, test_password1, sizeof(test_password1)) == WALLET_NO_ERROR)
	{
		printf("Wallet 0 can be loaded with wallet 1's key\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();
	if (initWallet(1, test_password0, sizeof(test_password0)) == WALLET_NO_ERROR)
	{
		printf("Wallet 1 can be loaded with wallet 0's key\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();
	if (initWallet(1, test_password1, sizeof(test_password1)) != WALLET_NO_ERROR)
	{
		printf("Cannot load wallet 1 with correct key\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();

	// Change wallet 1's key and check that it doesn't change wallet 0.
	initWallet(1, test_password1, sizeof(test_password1));
	changeEncryptionKey(new_test_password, sizeof(new_test_password));
	uninitWallet();
	if (initWallet(0, test_password0, sizeof(test_password0)) != WALLET_NO_ERROR)
	{
		printf("Cannot load wallet 0 with correct key after wallet 1's key was changed\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();

	// Check that wallet 1 can be loaded with the new key.
	if (initWallet(1, new_test_password, sizeof(new_test_password)) != WALLET_NO_ERROR)
	{
		printf("Cannot load wallet 1 with correct key after wallet 1's key was changed\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();

	// So far, the multiple wallet tests have only looked at wallets 0 and 1.
	// The following test creates the maximum number of wallets that
	// non-volatile storage can hold and checks that they can all create
	// addresses independently.
	returned_num_wallets = getNumberOfWallets();
	address_buffer = (uint8_t *)malloc(returned_num_wallets * 20);
	for (i = 0; i < (int)returned_num_wallets; i++)
	{
		deleteWallet((uint32_t)i);
		newWallet((uint32_t)i, name, false, NULL, false, NULL, 0);
		makeNewAddress(&(address_buffer[i * 20]), &public_key);
		uninitWallet();
	}
	abort = false;
	for (i = 0; i < (int)returned_num_wallets; i++)
	{
		initWallet((uint32_t)i, NULL, 0);
		getAddressAndPublicKey(compare_address, &public_key, 1);
		if (memcmp(&(address_buffer[i * 20]), compare_address, 20))
		{
			printf("Wallet %d got corrupted\n", i);
			reportFailure();
			abort = true;
			break;
		}
		uninitWallet();
	}
	if (!abort)
	{
		reportSuccess();
	}

	// Check that addresses from each wallet are unique.
	abort_duplicate = false;
	for (i = 0; i < (int)returned_num_wallets; i++)
	{
		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(address_buffer[i * 20]), &(address_buffer[j * 20]), 20))
			{
				printf("Different wallets generate the same addresses\n");
				abort_duplicate = true;
				reportFailure();
				break;
			}
		}
		if (abort_duplicate)
		{
			break;
		}
	}
	if (!abort_duplicate)
	{
		reportSuccess();
	}
	free(address_buffer);

	// Clear NV storage, then create a new hidden wallet.
	sanitiseEverything();
	nonVolatileRead((uint8_t *)&unencrypted_part, PARTITION_ACCOUNTS, 0, sizeof(unencrypted_part));
	memcpy(name, "This will be ignored                    ", NAME_LENGTH);
	if (newWallet(0, name, false, NULL, true, test_password0, sizeof(test_password0)) != WALLET_NO_ERROR)
	{
		printf("Couldn't create new hidden wallet\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that the hidden wallet can function as a wallet by creating an
	// address.
	if (makeNewAddress(address1, &public_key) == BAD_ADDRESS_HANDLE)
	{
		printf("Couldn't create new address in hidden wallet\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();

	// Check that unencrypted part (which contains name/version) wasn't
	// touched.
	nonVolatileRead((uint8_t *)&compare_unencrypted_part, PARTITION_ACCOUNTS, 0, sizeof(compare_unencrypted_part));
	if (memcmp(&unencrypted_part, &compare_unencrypted_part, sizeof(unencrypted_part)))
	{
		printf("Creation of hidden wallet writes to unencrypted portion of wallet storage\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Is it possible to load the hidden wallet?
	uninitWallet();
	if (initWallet(0, test_password0, sizeof(test_password0)) != WALLET_NO_ERROR)
	{
		printf("Could not load hidden wallet\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// It should be possible to change the encryption key of a hidden wallet.
	if (changeEncryptionKey(new_test_password, sizeof(new_test_password)) != WALLET_NO_ERROR)
	{
		printf("Couldn't change encryption key for hidden wallet\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that the unencrypted part (which contains name/version) wasn't
	// touched.
	uninitWallet();
	nonVolatileRead((uint8_t *)&compare_unencrypted_part, PARTITION_ACCOUNTS, 0, sizeof(compare_unencrypted_part));
	if (memcmp(&unencrypted_part, &compare_unencrypted_part, sizeof(unencrypted_part)))
	{
		printf("Key change on hidden wallet results in writes to unencrypted portion of wallet storage\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// The hidden wallet should be loadable with the new key but not the old.
	uninitWallet();
	if (initWallet(0, new_test_password, sizeof(new_test_password)) != WALLET_NO_ERROR)
	{
		printf("Could not load hidden wallet after encryption key change\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();
	if (initWallet(0, test_password0, sizeof(test_password0)) != WALLET_NOT_THERE)
	{
		printf("Could load hidden wallet with old encryption key\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Change key to all 00s (representing an "unencrypted" wallet) and do
	// the above key change tests.
	initWallet(0, new_test_password, sizeof(new_test_password));
	if (changeEncryptionKey(NULL, 0) != WALLET_NO_ERROR)
	{
		printf("Couldn't change encryption key for hidden wallet 2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();
	nonVolatileRead((uint8_t *)&compare_unencrypted_part, PARTITION_ACCOUNTS, 0, sizeof(compare_unencrypted_part));
	if (memcmp(&unencrypted_part, &compare_unencrypted_part, sizeof(unencrypted_part)))
	{
		printf("Key change on hidden wallet results in writes to unencrypted portion of wallet storage 2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();
	if (initWallet(0, NULL, 0) != WALLET_NO_ERROR)
	{
		printf("Could not load hidden wallet after encryption key change 2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();
	if (initWallet(0, new_test_password, sizeof(new_test_password)) != WALLET_NOT_THERE)
	{
		printf("Could load hidden wallet with old encryption key 2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Wallet name changes on a hidden wallet should be disallowed.
	initWallet(0, NULL, 0);
	memcpy(name2, "This will also be ignored               ", NAME_LENGTH);
	if (changeWalletName(name2) != WALLET_INVALID_OPERATION)
	{
		printf("Wallet name change is allowed on a hidden wallet\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that the wallet is still intact by getting the previously
	// generated address from it.
	initWallet(0, NULL, 0);
	if (getAddressAndPublicKey(address2, &public_key, 1) != WALLET_NO_ERROR)
	{
		printf("Couldn't get address from hidden wallet\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	if (memcmp(address1, address2, 20))
	{
		printf("Addresses in hidden wallet are getting mangled\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Create a non-hidden wallet, then overwrite it with a hidden wallet.
	// The resulting version field should still be VERSION_NOTHING_THERE.
	uninitWallet();
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	deleteWallet(0);
	newWallet(0, name, false, NULL, true, NULL, 0);
	getWalletInfo(&version, temp, wallet_uuid, 0);
	if (version != VERSION_NOTHING_THERE)
	{
		printf("Hidden wallet's version field is not VERSION_NOTHING_THERE\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Create two wallets. Their UUIDs should not be the same.
	uninitWallet();
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	deleteWallet(1);
	newWallet(1, name, false, NULL, false, NULL, 0);
	getWalletInfo(&version, temp, wallet_uuid, 0);
	getWalletInfo(&version, temp, wallet_uuid2, 1);
	if (!memcmp(wallet_uuid, wallet_uuid2, UUID_LENGTH))
	{
		printf("Wallet UUIDs not unique\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Overwrite wallet 0. The UUID should change.
	uninitWallet();
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, test_password0, sizeof(test_password0));
	getWalletInfo(&version, temp, wallet_uuid2, 0);
	if (!memcmp(wallet_uuid, wallet_uuid2, UUID_LENGTH))
	{
		printf("Wallet UUIDs aren't changing on overwrite\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Perform a few operations on the wallet. The wallet UUID shouldn't change.
	uninitWallet();
	getWalletInfo(&version, temp, wallet_uuid, 0);
	initWallet(0, test_password0, sizeof(test_password0));
	changeEncryptionKey(NULL, 0);
	makeNewAddress(address1, &public_key);
	changeWalletName(name2);
	uninitWallet();
	initWallet(0, NULL, 0);
	getWalletInfo(&version, temp, wallet_uuid2, 0);
	if (memcmp(wallet_uuid, wallet_uuid2, UUID_LENGTH))
	{
		printf("Wallet UUIDs changing when the wallet is used\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that getMasterPublicKey() works.
	uninitWallet();
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	initWallet(0, NULL, 0);
	if (getMasterPublicKey(&master_public_key, chain_code) != WALLET_NO_ERROR)
	{
		printf("getMasterPublicKey() fails in the simplest case\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that wallet public keys can be derived from the public key and
	// chain code that getMasterPublicKey() returned.
	generateDeterministicPublicKey(&public_key, &master_public_key, chain_code, 1);
	makeNewAddress(address1, &compare_public_key);
	if (memcmp(&public_key, &compare_public_key, sizeof(PointAffine)))
	{
		printf("Address 1 can't be derived from master public key\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	generateDeterministicPublicKey(&public_key, &master_public_key, chain_code, 2);
	makeNewAddress(address1, &compare_public_key);
	if (memcmp(&public_key, &compare_public_key, sizeof(PointAffine)))
	{
		printf("Address 2 can't be derived from master public key\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that sanitisePartition() only affects one partition.
	suppress_set_entropy_pool = true; // avoid spurious writes to global partition
	memset(copy_of_nv, 0, sizeof(copy_of_nv));
	memset(copy_of_nv2, 1, sizeof(copy_of_nv2));
	nonVolatileRead(copy_of_nv, PARTITION_GLOBAL, 0, TEST_GLOBAL_PARTITION_SIZE);
	sanitisePartition(PARTITION_ACCOUNTS);
	nonVolatileRead(copy_of_nv2, PARTITION_GLOBAL, 0, TEST_GLOBAL_PARTITION_SIZE);
	if (memcmp(copy_of_nv, copy_of_nv2, TEST_GLOBAL_PARTITION_SIZE))
	{
		printf("sanitisePartition(PARTITION_ACCOUNTS) is touching global partition\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	memset(copy_of_nv, 0, sizeof(copy_of_nv));
	memset(copy_of_nv2, 1, sizeof(copy_of_nv2));
	nonVolatileRead(copy_of_nv, PARTITION_ACCOUNTS, 0, TEST_ACCOUNTS_PARTITION_SIZE);
	sanitisePartition(PARTITION_GLOBAL);
	nonVolatileRead(copy_of_nv2, PARTITION_ACCOUNTS, 0, TEST_ACCOUNTS_PARTITION_SIZE);
	if (memcmp(copy_of_nv, copy_of_nv2, TEST_ACCOUNTS_PARTITION_SIZE))
	{
		printf("sanitisePartition(PARTITION_GLOBAL) is touching accounts partition\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	suppress_set_entropy_pool = false;

	// Check that entropy pool can still be loaded after sanitiseEverything().
	initialiseDefaultEntropyPool();
	sanitiseEverything();
	if (getEntropyPool(pool_state))
	{
		printf("Entropy pool can't be loaded after sanitiseEverything()\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	fclose(wallet_test_file);

	finishTests();
	exit(0);
}

#endif // #ifdef TEST_WALLET

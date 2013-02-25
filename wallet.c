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

/** Length of the checksum field of a wallet record. This is 32 since SHA-256
  * is used to calculate the checksum and the output of SHA-256 is 32 bytes
  * long. */
#define CHECKSUM_LENGTH			32

/** Get the byte offset of a field (specified by "x") within a structure
  * (specified by "base"). Because this uses pointer arithmetic to get the
  * offset, the base needs to be a variable. */
#define OFFSET_OF(base, x)			((unsigned int)(((uint8_t *)&((base).x)) - ((uint8_t *)&(base))))

/** Possible values for the version field of a wallet record. */
typedef enum WalletVersionEnum
{
	/** Version number which means "nothing here". */
	VERSION_NOTHING_THERE		= 0x00000000,
	/** Version number which means "wallet is not encrypted".
	  * \warning A wallet which uses an encryption key consisting of
	  *          all zeroes (see isEncryptionKeyNonZero()) is considered to be
	  *          unencrypted.
	  */
	VERSION_UNENCRYPTED			= 0x00000002,
	/** Version number which means "wallet is encrypted". */
	VERSION_IS_ENCRYPTED		= 0x00000003
} WalletVersion;

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
/** This will be 0 if a wallet is not currently loaded. This will be non-zero
  * if a wallet is currently loaded. */
static uint8_t wallet_loaded;
/** This will be 0 if the currently loaded wallet is not a hidden wallet. This
  * will be non-zero if the currently loaded wallet is a hidden wallet. If
  * #wallet_loaded is 0 (i.e. no wallet is loaded), then the meaning of this
  * variable is undefined. */
static uint8_t is_hidden_wallet;
/** This will only be valid if a wallet is loaded. It contains a cache of the
  * currently loaded wallet record. If #wallet_loaded is 0 (i.e. no wallet is
  * loaded), then the contents of this variable are undefined. */
static WalletRecord current_wallet;
/** The address in non-volatile memory where the currently loaded wallet
  * record is. If #wallet_loaded is 0 (i.e. no wallet is loaded), then the
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

/** Set this to a non-zero value to stop sanitiseNonVolatileStorage() from
  * updating the persistent entropy pool. This is necessary for some test
  * cases which check where sanitiseNonVolatileStorage() writes; updates
  * of the entropy pool would appear as spurious writes to those test cases.
  */
static int suppress_set_entropy_pool;
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
		if (i == OFFSET_OF(current_wallet, encrypted.checksum))
		{
			i += sizeof(current_wallet.encrypted.checksum);
		}
		if (i < sizeof(WalletRecord))
		{
			sha256WriteByte(&hs, ptr[i]);
		}
	}
	sha256Finish(&hs);
	writeHashToByteArray(hash, &hs, 1);
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
	// Before doing any reading, do some sanity checks. These ensure that the
	// size of the unencrypted and encrypted portions are an integer multiple
	// of the AES block size and that the compiler hasn't inserted any padding.
	// between those portions.
	if (((sizeof(wallet_record->unencrypted) % 16) != 0)
		|| ((sizeof(wallet_record->encrypted) % 16) != 0)
		|| ((sizeof(wallet_record->unencrypted) + sizeof(wallet_record->encrypted)) != sizeof(WalletRecord)))
	{
		return WALLET_INVALID_OPERATION;
	}

	if (nonVolatileRead((uint8_t *)&(wallet_record->unencrypted), address, sizeof(wallet_record->unencrypted)) != NV_NO_ERROR)
	{
		return WALLET_READ_ERROR;
	}
	if (encryptedNonVolatileRead((uint8_t *)&(wallet_record->encrypted), address + sizeof(wallet_record->unencrypted), sizeof(wallet_record->encrypted)) != NV_NO_ERROR)
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
	if (nonVolatileWrite((uint8_t *)&(current_wallet.unencrypted), address, sizeof(current_wallet.unencrypted)) != NV_NO_ERROR)
	{
		return WALLET_WRITE_ERROR;
	}
	if (encryptedNonVolatileWrite((uint8_t *)&(current_wallet.encrypted), address + sizeof(current_wallet.unencrypted), sizeof(current_wallet.encrypted)) != NV_NO_ERROR)
	{
		return WALLET_WRITE_ERROR;
	}
	if (nonVolatileFlush() != NV_NO_ERROR)
	{
		return WALLET_WRITE_ERROR;
	}
	return WALLET_NO_ERROR;
}

/** Initialise a wallet (load it if it's there).
  * \param wallet_spec The wallet number of the wallet to load.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors initWallet(uint32_t wallet_spec)
{
	WalletErrors r;
	uint8_t hash[CHECKSUM_LENGTH];

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
	wallet_nv_address = ADDRESS_WALLET_START + wallet_spec * sizeof(WalletRecord);

	r = readWalletRecord(&current_wallet, wallet_nv_address);
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return last_error;
	}

	if (current_wallet.unencrypted.version == VERSION_NOTHING_THERE)
	{
		is_hidden_wallet = 1;
	}
	else if ((current_wallet.unencrypted.version == VERSION_UNENCRYPTED)
		|| (current_wallet.unencrypted.version == VERSION_IS_ENCRYPTED))
	{
		is_hidden_wallet = 0;
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
	clearParentPublicKeyCache();
	wallet_loaded = 0;
	is_hidden_wallet = 0;
	wallet_nv_address = 0;
	memset(&current_wallet, 0, sizeof(WalletRecord));
	last_error = WALLET_NO_ERROR;
	return last_error;
}

#ifdef TEST_WALLET
void logVersionFieldWrite(uint32_t address);
#endif // #ifdef TEST_WALLET

/** Sanitise (clear) a selected area of non-volatile storage. This will clear
  * the area between start (inclusive) and end (exclusive).
  * \param start The first address which will be cleared.
  * \param end One byte past the last address which will be cleared.
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred. This will still return #WALLET_NO_ERROR even if
  *         end is an address beyond the end of the non-volatile storage area.
  *         This is done so that using start = 0 and end = 0xffffffff will
  *         clear the entire non-volatile storage area.
  */
WalletErrors sanitiseNonVolatileStorage(uint32_t start, uint32_t end)
{
	uint8_t buffer[32];
	uint8_t pool_state[ENTROPY_POOL_LENGTH];
	uint32_t address;
	uint32_t remaining;
	NonVolatileReturn r;
	uint8_t pass;

	r = NV_NO_ERROR;
	if (getEntropyPool(pool_state))
	{
		last_error = WALLET_RNG_FAILURE;
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
			remaining = end - address;
			if (remaining > 32)
			{
				remaining = 32;
			}
			if (remaining > 0)
			{
				r = nonVolatileWrite(buffer, address, remaining);
			}
			if (address <= (0xffffffff - 32))
			{
				address += 32;
			}
			else
			{
				// Overflow in address will occur.
				break;
			}
		}

		if ((r == NV_INVALID_ADDRESS) || (r == NV_NO_ERROR))
		{
			// After each pass, flush write buffers to ensure that
			// non-volatile memory is actually overwritten.
			r = nonVolatileFlush();
		}
		if ((r != NV_INVALID_ADDRESS) && (r != NV_NO_ERROR))
		{
			// Uh oh, probably an I/O error.
			break;
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

	if ((r == NV_INVALID_ADDRESS) || (r == NV_NO_ERROR))
	{
		// If the selected area includes the device UUID, then a new device
		// UUID needs to be written. But if the selected area includes the
		// device UUID, then it will be overwritten with random data in the
		// above loop. Thus no additional work is needed.

		// Write VERSION_NOTHING_THERE to all possible locations of the
		// version field. This ensures that a wallet won't accidentally
		// (1 in 2 ^ 31 chance) be recognised as a valid wallet by
		// getWalletInfo().
		if (start < ADDRESS_WALLET_START)
		{
			address = 0;
		}
		else
		{
			address = start - ADDRESS_WALLET_START;
		}
		address /= sizeof(WalletRecord);
		address *= sizeof(WalletRecord);
		address += (ADDRESS_WALLET_START + OFFSET_OF(current_wallet, unencrypted.version));
		// address is now rounded down to the first possible address where
		// the version field of a wallet could be stored.
		r = NV_NO_ERROR;
		writeU32LittleEndian(buffer, VERSION_NOTHING_THERE);
		// The "address <= (0xffffffff - 4)" is there to ensure that
		// (address + 4) cannot overflow.
		while ((r == NV_NO_ERROR) && (address <= (0xffffffff - 4)) && ((address + 4) <= end))
		{
			// An additional range check against start is needed because the
			// initial value of address is rounded down; thus it could be
			// rounded down below start.
			if (address >= start)
			{
				r = nonVolatileWrite(buffer, address, 4);
				if ((r == NV_INVALID_ADDRESS) || (r == NV_NO_ERROR))
				{
					r = nonVolatileFlush();
				}
				if ((r != NV_INVALID_ADDRESS) && (r != NV_NO_ERROR))
				{
					// Uh oh, probably an I/O error.
					break;
				}
#ifdef TEST_WALLET
				if (r == NV_NO_ERROR)
				{
					logVersionFieldWrite(address);
				}
#endif // #ifdef TEST_WALLET
			}
			if (address <= (0xffffffff - sizeof(WalletRecord)))
			{
				address += sizeof(WalletRecord);
			}
			else
			{
				// Overflow in address will occur.
				break;
			}
		} // end while ((r == NV_NO_ERROR) && (address <= (0xffffffff - 4)) && ((address + 4) <= end))
		if ((r == NV_NO_ERROR) || (r == NV_INVALID_ADDRESS))
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
	} // end if ((r == NV_INVALID_ADDRESS) || (r == NV_NO_ERROR))
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

/** Create new wallet. A brand new wallet contains no addresses and should
  * have a unique, unpredictable deterministic private key generation seed.
  * \param wallet_spec The wallet number of the new wallet.
  * \param name Should point to #NAME_LENGTH bytes (padded with spaces if
  *             necessary) containing the desired name of the wallet.
  * \param use_seed If this is non-zero, then the contents of seed will be
  *                 used as the deterministic private key generation seed.
  *                 If this is zero, then the contents of seed will be
  *                 ignored.
  * \param seed The deterministic private key generation seed to use in the
  *             new wallet. This should be a byte array of length #SEED_LENGTH
  *             bytes. This parameter will be ignored if use_seed is zero.
  * \param make_hidden Whether to make the new wallet a hidden wallet
  *                    (non-zero) or not (zero).
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred. If this returns #WALLET_NO_ERROR, then the
  *         wallet will also be loaded.
  * \warning This will erase the current one.
  */
WalletErrors newWallet(uint32_t wallet_spec, uint8_t *name, uint8_t use_seed, uint8_t *seed, uint8_t make_hidden)
{
	uint8_t random_buffer[32];
	uint32_t start_address;
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
	wallet_nv_address = ADDRESS_WALLET_START + wallet_spec * sizeof(WalletRecord);

	// Erase all traces of the existing wallet.
	start_address = wallet_nv_address;
	if (make_hidden)
	{
		// The creation of a hidden wallet is supposed to be discreet; the
		// existing version/name fields should be left untouched. This is
		// so an attacker who has access to before and after snapshots of all
		// the name and version fields can't detect the existence of a hidden
		// wallet.
		// However, if there is already an existing wallet (i.e. the version
		// field is not VERSION_NOTHING_THERE), then the existing version and
		// name fields have to be cleared, otherwise the hidden wallet won't
		// look very hidden.
		r = readWalletRecord(&current_wallet, wallet_nv_address);
		if (r != WALLET_NO_ERROR)
		{
			last_error = r;
			return last_error;
		}
		if (current_wallet.unencrypted.version == VERSION_NOTHING_THERE)
		{
			start_address += sizeof(current_wallet.unencrypted);
		}
	}
	r = sanitiseNonVolatileStorage(start_address, wallet_nv_address + sizeof(WalletRecord));
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return last_error;
	}
	r = readWalletRecord(&current_wallet, wallet_nv_address);
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return last_error;
	}

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
		if (getRandom256(random_buffer))
		{
			last_error = WALLET_RNG_FAILURE;
			return last_error;
		}
		memcpy(current_wallet.unencrypted.uuid, random_buffer, UUID_LENGTH);
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

	last_error = initWallet(wallet_spec);
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
  * \param new_key A byte array of #WALLET_ENCRYPTION_KEY_LENGTH bytes
  *                specifying the new encryption key.
  *                An encryption key consisting of all zeroes is interpreted
  *                as meaning "no encryption".
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors changeEncryptionKey(uint8_t *new_key)
{
	WalletErrors r;

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_LOADED;
		return last_error;
	}

	setEncryptionKey(new_key);
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
  * \param out_version The little-endian version of the wallet will be written
  *                    to here (if everything goes well). This should be a
  *                    byte array with enough space to store 4 bytes.
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
WalletErrors getWalletInfo(uint8_t *out_version, uint8_t *out_name, uint8_t *out_uuid, uint32_t wallet_spec)
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
	local_wallet_nv_address = ADDRESS_WALLET_START + wallet_spec * sizeof(WalletRecord);
	r = readWalletRecord(&local_wallet_record, local_wallet_nv_address);
	if (r != WALLET_NO_ERROR)
	{
		last_error = r;
		return last_error;
	}
	writeU32LittleEndian(out_version, local_wallet_record.unencrypted.version);
	memcpy(out_name, local_wallet_record.unencrypted.name, NAME_LENGTH);
	memcpy(out_uuid, local_wallet_record.unencrypted.uuid, UUID_LENGTH);

	last_error = WALLET_NO_ERROR;
	return last_error;
}

/** Initiate a wallet backup of the currently loaded wallet.
  * \param do_encrypt If this is non-zero, the wallet backup will be written
  *                   in encrypted form. If this is zero, the wallet backup
  *                   will be written in unencrypted form.
  * \param destination_device See writeBackupSeed().
  * \return #WALLET_NO_ERROR on success, or one of #WalletErrorsEnum if an
  *         error occurred.
  */
WalletErrors backupWallet(uint8_t do_encrypt, uint8_t destination_device)
{
	uint8_t encrypted_seed[SEED_LENGTH];
	uint8_t n[16];
	uint8_t r;
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

/** Obtain the size of non-volatile storage by doing a bunch of test reads.
  * \return The size in bytes, less one, of non-volatile storage. 0 indicates
  *         that a read error occurred. For example, a return value of 9999
  *         means that non-volatile storage is 10000 bytes large (or
  *         equivalently, 9999 is the largest valid address).
  */
static uint32_t findOutNonVolatileSize(void)
{
	uint32_t test_bit;
	uint32_t size;
	uint8_t junk;
	NonVolatileReturn r;

	// Find out size using binary search.
	test_bit = 0x80000000;
	size = 0;
	while (test_bit != 0)
	{
		size |= test_bit;
		r = nonVolatileRead(&junk, size, 1);
		if (r == NV_INVALID_ADDRESS)
		{
			size ^= test_bit; // too big; clear it
		}
		else if (r != NV_NO_ERROR)
		{
			last_error = WALLET_READ_ERROR;
			return 0; // read error occurred
		}
		test_bit >>= 1;
	}
	last_error = WALLET_NO_ERROR;
	return size;
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
		size = findOutNonVolatileSize();
		if (size != 0)
		{
			if (size != 0xffffffff)
			{
				// findOutNonVolatileSize() returns the size of non-volatile
				// storage, less one byte.
				size++;
			}
			num_wallets = (size - ADDRESS_WALLET_START) / sizeof(WalletRecord);
		}
		// If findOutNonVolatileSize() returned 0, num_wallets will still be
		// 0, signifying that a read error occurred. last_error will also
		// be set appropriately.
	}
	return num_wallets;
}

#ifdef TEST

/** Size of storage area, in bytes. */
#define TEST_FILE_SIZE 1024

/** Set this to something non-zero to stop nonVolatileWrite() from logging
  * all non-volatile writes to stdout. */
static int suppress_write_debug_info;

#ifdef TEST_WALLET
/** Highest non-volatile address that nonVolatileWrite() has written to. */
static uint32_t maximum_address_written;
/** Lowest non-volatile address that nonVolatileWrite() has written to. */
static uint32_t minimum_address_written;
#endif // #ifdef TEST_WALLET

/** Write to non-volatile storage.
  * \param data A pointer to the data to be written.
  * \param address Byte offset specifying where in non-volatile storage to
  *                start writing to.
  * \param length The number of bytes to write.
  * \return See #NonVolatileReturnEnum for return values.
  * \warning Writes may be buffered; use nonVolatileFlush() to be sure that
  *          data is actually written to non-volatile storage.
  */
NonVolatileReturn nonVolatileWrite(uint8_t *data, uint32_t address, uint32_t length)
{
#if !defined(TEST_XEX) && !defined(TEST_PRANDOM)
	unsigned int i;
#endif // #if !defined(TEST_XEX) && !defined(TEST_PRANDOM)

	if (address > (0xffffffff - length))
	{
		// address + length will overflow.
		return NV_INVALID_ADDRESS;
	}
	if ((address + length) > TEST_FILE_SIZE)
	{
		return NV_INVALID_ADDRESS;
	}
#ifdef TEST_WALLET
	if (length > 0)
	{
		if (address < minimum_address_written)
		{
			minimum_address_written = address;
		}
		if ((address + length - 1) > maximum_address_written)
		{
			maximum_address_written = address + length - 1;
		}
	}
#endif // #ifdef TEST_WALLET
	// Don't output write debugging info when testing xex.c or prandom.c,
	// otherwise the console will go crazy (since they do a lot of writing).
#if !defined(TEST_XEX) && !defined(TEST_PRANDOM)
	if (!suppress_write_debug_info)
	{
		printf("nv write, addr = 0x%08x, length = 0x%04x, data =", (int)address, (int)length);
		for (i = 0; i < length; i++)
		{
			printf(" %02x", data[i]);
		}
		printf("\n");
	}
#endif // #if !defined(TEST_XEX) && !defined(TEST_PRANDOM)
	fseek(wallet_test_file, (long)address, SEEK_SET);
	fwrite(data, (size_t)length, 1, wallet_test_file);
	return NV_NO_ERROR;
}

/** Non-volatile reads between addresses TEST_FILE_SIZE (inclusive) and this
  * value (inclusive) will still succeed, but will do nothing. This
  * behaviour is used to test findOutNonVolatileSize(). If this is
  * set to #TEST_FILE_SIZE - 1, then nothing special will happen. */
static uint32_t allow_test_reads_up_to = TEST_FILE_SIZE - 1;

/** Read from non-volatile storage.
  * \param data A pointer to the buffer which will receive the data.
  * \param address Byte offset specifying where in non-volatile storage to
  *                start reading from.
  * \param length The number of bytes to read.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn nonVolatileRead(uint8_t *data, uint32_t address, uint32_t length)
{
	if (address > (0xffffffff - length))
	{
		// address + length will overflow.
		return NV_INVALID_ADDRESS;
	}
	if ((address + length) > TEST_FILE_SIZE)
	{
		if ((address + length) > (allow_test_reads_up_to + 1))
		{
			return NV_INVALID_ADDRESS;
		}
		else
		{
			// It's just a test read, so allow it, but don't actually read
			// anything.
			return NV_NO_ERROR;
		}
	}
	fseek(wallet_test_file, (long)address, SEEK_SET);
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
  * \param is_encrypted Specifies whether the seed has been encrypted
  *                     (non-zero) or not (zero).
  * \param destination_device Specifies which (platform-dependent) device the
  *                           backup seed should be sent to.
  * \return 0 on success, or non-zero if the backup seed could not be written
  *         to the destination device.
  */
uint8_t writeBackupSeed(uint8_t *seed, uint8_t is_encrypted, uint8_t destination_device)
{
	int i;

	if (destination_device > 0)
	{
		return 1;
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
		return 0;
	}
}

#endif // #ifdef TEST

#ifdef TEST_WALLET

/** List of non-volatile addresses that logVersionFieldWrite() received. */
uint32_t version_field_writes[TEST_FILE_SIZE / sizeof(WalletRecord) + 2];
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
	if (changeEncryptionKey(temp) == WALLET_NOT_LOADED)
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
	if (backupWallet(0, 0) == WALLET_NOT_LOADED)
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
  * \param should_succeed Non-zero if the wallet number is valid (and thus the
  *                       wallet functions should succeed), zero if the wallet
  *                       number is not valid (and thus the wallet functions
  *                       should fail).
  */
static void checkWalletSpecFunctions(uint32_t wallet_spec, int should_succeed)
{
	uint8_t wallet_uuid[UUID_LENGTH];
	uint8_t name[NAME_LENGTH];
	uint8_t version[4];
	WalletErrors wallet_return;

	memset(name, ' ', NAME_LENGTH);
	uninitWallet();
	wallet_return = newWallet(wallet_spec, name, 0, NULL, 0);
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
	// so that if should_succeed is non-zero, there's a valid wallet in the
	// specified place.
	wallet_return = initWallet(wallet_spec);
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
	wallet_return = getWalletInfo(version, name, wallet_uuid, wallet_spec);
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

/** Test findOutNonVolatileSize() for a given non-volatile storage size.
  * \param size The size of non-volatile storage, in number of bytes less
  *             one.
  */
static void testFindOutNonVolatileSize(uint32_t size)
{
	allow_test_reads_up_to = size;
	if (findOutNonVolatileSize() != size)
	{
		printf("findOutNonVolatileSize() failed for size = %u\n", size);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
}

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
	uint8_t encryption_key[WALLET_ENCRYPTION_KEY_LENGTH];
	uint8_t new_encryption_key[WALLET_ENCRYPTION_KEY_LENGTH];
	uint8_t version[4];
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
	int abort;
	int is_zero;
	int abort_duplicate;
	int abort_error;
	int i;
	int j;
	int version_field_counter;
	int found;

	initTests(__FILE__);

	initWalletTest();
	memset(encryption_key, 0, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	initialiseDefaultEntropyPool();
	suppress_set_entropy_pool = 0;
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
	if (getWalletInfo(version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
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
	checkFunctionsReturnWalletNotLoaded();

	// The non-volatile storage area was blanked out, so there shouldn't be a
	// (valid) wallet there.
	if (initWallet(0) == WALLET_NOT_THERE)
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
	if (newWallet(0, name, 0, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Could not create new wallet\n");
		reportFailure();
	}
	if (initWallet(0) == WALLET_NO_ERROR)
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
	if (getWalletInfo(version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
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
	if (initWallet(0) == WALLET_NOT_THERE)
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
	newWallet(0, name, 0, NULL, 0);
	if (makeNewAddress(temp, &public_key) != BAD_ADDRESS_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		reportFailure();
	}
	newWallet(0, name, 0, NULL, 0);
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
	checkFunctionsReturnWalletNotLoaded();

	// Load wallet again. Since there is actually a wallet there, this
	// should succeed.
	if (initWallet(0) == WALLET_NO_ERROR)
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
	for (i = ADDRESS_WALLET_START; i < (ADDRESS_WALLET_START + sizeof(WalletRecord)); i++)
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
		if (initWallet(0) == WALLET_NO_ERROR)
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
	newWallet(0, name, 0, NULL, 0);
	if (makeNewAddress(address1, &public_key) != BAD_ADDRESS_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		reportFailure();
	}
	newWallet(0, name, 0, NULL, 0);
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
	newWallet(0, name, 0, NULL, 0);
	abort = 0;
	abort_error = 0;
	address_buffer = malloc(MAX_TESTING_ADDRESSES * 20);
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		if (makeNewAddress(&(address_buffer[i * 20]), &public_key) == BAD_ADDRESS_HANDLE)
		{
			printf("Couldn't create new address in new wallet\n");
			reportFailure();
			abort_error = 1;
			break;
		}
		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(address_buffer[i * 20]), &(address_buffer[j * 20]), 20))
			{
				printf("Wallet addresses aren't unique\n");
				reportFailure();
				abort = 1;
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
	newWallet(0, name, 0, NULL, 0);
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
	if (getWalletInfo(version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
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
	if (getWalletInfo(version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
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
	initWallet(0);
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
	getWalletInfo(version, temp, wallet_uuid, 0);
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
	getWalletInfo(version, temp, wallet_uuid, 0);
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
	if (initWallet(0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("initWallet() failed after name change\n");
		reportFailure();
	}
	getWalletInfo(version, temp, wallet_uuid, 0);
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
	if (initWallet(0) == WALLET_NOT_THERE)
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
	if (initWallet(0) == WALLET_NO_ERROR)
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
	newWallet(0, name, 0, NULL, 0);
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
	newWallet(0, name, 0, NULL, 0);
	if (backupWallet(0, 0) == WALLET_NO_ERROR)
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
	if (backupWallet(0, 1) == WALLET_BACKUP_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("backupWallet() doesn't deal with invalid device correctly\n");
		reportFailure();
	}

	// Delete wallet and check that seed of a new wallet is different.
	newWallet(0, name, 0, NULL, 0);
	backupWallet(0, 0);
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
	if (newWallet(0, name, 1, seed1, 0) == WALLET_NO_ERROR)
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
	if (backupWallet(1, 0) == WALLET_NO_ERROR)
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

	// Test that sanitiseNonVolatileStorage() clears the correct area.
	// Previously, sanitiseNonVolatileStorage() required the start and end
	// parameters to be a multiple of 32 (because it uses a write buffer
	// with that length). That restriction has since been relaxed. This test
	// case checks that the code handles non-multiples of 32 properly.
	suppress_write_debug_info = 1; // stop console from going crazy
	suppress_set_entropy_pool = 1; // avoid spurious entropy pool update writes
	abort = 0;
	for (i = 0; i < 2000; i++)
	{
		initialiseDefaultEntropyPool(); // needed in case pool or checksum gets corrupted by writes
		minimum_address_written = 0xffffffff;
		maximum_address_written = 0;
		start_address = (uint32_t)(rand() % TEST_FILE_SIZE);
		end_address = start_address + (uint32_t)(rand() % TEST_FILE_SIZE);
		if (end_address > TEST_FILE_SIZE)
		{
			end_address = TEST_FILE_SIZE;
		}
		if (start_address != end_address)
		{
			sanitiseNonVolatileStorage(start_address, end_address);
			if ((minimum_address_written != start_address)
				|| (maximum_address_written != (end_address - 1)))
			{
				printf("sanitiseNonVolatileStorage() not clearing correct area\n");
				printf("start = 0x%08x, end = 0x%08x\n", start_address, end_address);
				abort = 1;
				reportFailure();
				break;
			}
		}
	}
	if (!abort)
	{
		reportSuccess();
	}

	// Also check that sanitiseNonVolatileStorage() does nothing if start
	// and end are the same.
	initialiseDefaultEntropyPool(); // needed in case pool or checksum gets corrupted by writes
	minimum_address_written = 0xffffffff;
	maximum_address_written = 0;
	// Use ADDRESS_WALLET_START + OFFSET_OF(current_wallet, unencrypted.version) to try and
	// trick the "clear version field" logic.
	start_address = ADDRESS_WALLET_START + OFFSET_OF(current_wallet, unencrypted.version);
	sanitiseNonVolatileStorage(start_address, start_address);
	if ((minimum_address_written != 0xffffffff) || (maximum_address_written != 0))
	{
		printf("sanitiseNonVolatileStorage() clearing something when it's not supposed to\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// ..and check that sanitiseNonVolatileStorage() does nothing if start
	// is > end.
	initialiseDefaultEntropyPool(); // needed in case pool or checksum gets corrupted by writes
	minimum_address_written = 0xffffffff;
	maximum_address_written = 0;
	sanitiseNonVolatileStorage(start_address + 1, start_address);
	if ((minimum_address_written != 0xffffffff) || (maximum_address_written != 0))
	{
		printf("sanitiseNonVolatileStorage() clearing something when it's not supposed to 2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that sanitiseNonVolatileStorage() is clearing the correct version
	// fields of any wallets in range.
	suppress_write_debug_info = 1; // stop console from going crazy
	suppress_set_entropy_pool = 0;
	abort = 0;
	for (i = 0; i < 5000; i++)
	{
		start_address = (uint32_t)(rand() % TEST_FILE_SIZE);
		end_address = start_address + (uint32_t)(rand() % TEST_FILE_SIZE);
		if (end_address > TEST_FILE_SIZE)
		{
			end_address = TEST_FILE_SIZE;
		}
		initialiseDefaultEntropyPool(); // needed in case pool or checksum gets corrupted by writes
		clearVersionFieldWriteLog();
		sanitiseNonVolatileStorage(start_address, end_address);
		// version_field_address is stepped through every possible address
		// (ignoring start_address and end_address) that could hold a wallet's
		// version field.
		version_field_address = ADDRESS_WALLET_START + ((uint8_t *)&(current_wallet.unencrypted.version) - (uint8_t *)&current_wallet);
		version_field_counter = 0;
		while ((version_field_address + 4) <= TEST_FILE_SIZE)
		{
			if ((version_field_address >= start_address)
				&& ((version_field_address + 4) <= end_address))
			{
				// version_field_address should be in the list somewhere.
				found = 0;
				for (j = 0; j < version_field_index; j++)
				{
					if (version_field_address == version_field_writes[j])
					{
						found = 1;
						break;
					}
				}
				if (!found)
				{
					printf("sanitiseNonVolatileStorage() did not clear version field at 0x%08x\n", version_field_address);
					reportFailure();
					abort = 1;
					break;
				}
				version_field_counter++;
			}
			version_field_address += sizeof(WalletRecord);
		} // end while ((version_field_address + 4) <= TEST_FILE_SIZE)
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
			abort = 1;
			break;
		}
	} // end for (i = 0; i < 5000; i++)
	if (!abort)
	{
		reportSuccess();
	}
	suppress_write_debug_info = 0; // can start reporting writes again

	// Check that findOutNonVolatileSize() works for various sizes.
	testFindOutNonVolatileSize(TEST_FILE_SIZE - 1);
	testFindOutNonVolatileSize(424242);
	// Cannot do size = 0xffffffff because an overflow would occur in
	// nonVolatileRead().
	testFindOutNonVolatileSize(0xfffffffe);
	testFindOutNonVolatileSize(0x80000000);
	testFindOutNonVolatileSize(0x7fffffff);
	allow_test_reads_up_to = TEST_FILE_SIZE - 1; // disable test read behaviour for next test

	// Check that getNumberOfWallets() works and returns the appropriate value
	// for various non-volatile storage sizes.
	abort = 0;
	abort_error = 0;
	// Step in increments of 1 byte to look for off-by-one errors.
	for (i = TEST_FILE_SIZE; i < TEST_FILE_SIZE + 1024; i++)
	{
		allow_test_reads_up_to = i - 1; // i = size but allow_test_reads_up_to = size - 1
		num_wallets = 0; // reset cache
		returned_num_wallets = getNumberOfWallets();
		if (returned_num_wallets == 0)
		{
			printf("getNumberOfWallets() doesn't work\n");
			reportFailure();
			abort_error = 1;
			break;
		}
		stupidly_calculated_num_wallets = 0;
		for (j = ADDRESS_WALLET_START; (int)(j + (sizeof(WalletRecord) - 1)) < i; j += sizeof(WalletRecord))
		{
			stupidly_calculated_num_wallets++;
		}
		if (stupidly_calculated_num_wallets != returned_num_wallets)
		{
			printf("getNumberOfWallets() returning inappropriate value\n");
			reportFailure();
			abort = 1;
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
	allow_test_reads_up_to = TEST_FILE_SIZE - 1; // disable test read behaviour for next test
	num_wallets = 0; // reset cache for next test

	// For all functions which accept wallet numbers, try some wallet numbers
	// which are in or out of range.
	returned_num_wallets = getNumberOfWallets();
	checkWalletSpecFunctions(0, 1); // first one
	// The next line does assume that returned_num_wallets > 1.
	checkWalletSpecFunctions(returned_num_wallets - 1, 1); // last one
	checkWalletSpecFunctions(returned_num_wallets, 0); // out of range
	// The next line does assume that returned_num_wallets != 0xffffffff.
	checkWalletSpecFunctions(returned_num_wallets + 1, 0); // out of range
	checkWalletSpecFunctions(0xffffffff, 0); // out of range

	// Create one wallet and some addresses, then create another wallet with a
	// different wallet number and see if it overwrites the first one
	// (it shouldn't).
	uninitWallet();
	memcpy(name, "A wallet with wallet number 0           ", NAME_LENGTH);
	newWallet(0, name, 0, NULL, 0);
	makeNewAddress(address1, &public_key);
	makeNewAddress(address1, &public_key);
	makeNewAddress(address1, &public_key);
	uninitWallet();
	memcpy(name2, "A wallet with wallet number 1           ", NAME_LENGTH);
	newWallet(1, name2, 0, NULL, 0);
	makeNewAddress(address2, &public_key);
	makeNewAddress(address2, &public_key);
	uninitWallet();
	initWallet(0);
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
	initWallet(1);
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
	getWalletInfo(version, compare_name, wallet_uuid, 0);
	if (memcmp(name, compare_name, NAME_LENGTH))
	{
		printf("Wallet 0's name got mangled\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	getWalletInfo(version, compare_name, wallet_uuid, 1);
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
	memset(encryption_key, 7, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	newWallet(0, name, 0, NULL, 0);
	makeNewAddress(address1, &public_key);
	uninitWallet();
	memset(encryption_key, 42, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	newWallet(1, name2, 0, NULL, 0);
	makeNewAddress(address2, &public_key);
	uninitWallet();
	memset(encryption_key, 7, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	if (initWallet(0) != WALLET_NO_ERROR)
	{
		printf("Cannot load wallet 0 with correct key\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();
	memset(encryption_key, 42, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	if (initWallet(0) == WALLET_NO_ERROR)
	{
		printf("Wallet 0 can be loaded with wallet 1's key\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();
	memset(encryption_key, 7, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	if (initWallet(1) == WALLET_NO_ERROR)
	{
		printf("Wallet 1 can be loaded with wallet 0's key\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();
	memset(encryption_key, 42, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	if (initWallet(1) != WALLET_NO_ERROR)
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
	memset(encryption_key, 42, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	initWallet(1);
	memset(new_encryption_key, 69, WALLET_ENCRYPTION_KEY_LENGTH);
	changeEncryptionKey(new_encryption_key);
	uninitWallet();
	memset(encryption_key, 7, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	if (initWallet(0) != WALLET_NO_ERROR)
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
	memset(encryption_key, 69, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	if (initWallet(1) != WALLET_NO_ERROR)
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
	address_buffer = malloc(returned_num_wallets * 20);
	memset(encryption_key, 0, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	for (i = 0; i < (int)returned_num_wallets; i++)
	{
		newWallet((uint32_t)i, name, 0, NULL, 0);
		makeNewAddress(&(address_buffer[i * 20]), &public_key);
		uninitWallet();
	}
	abort = 0;
	for (i = 0; i < (int)returned_num_wallets; i++)
	{
		initWallet((uint32_t)i);
		getAddressAndPublicKey(compare_address, &public_key, 1);
		if (memcmp(&(address_buffer[i * 20]), compare_address, 20))
		{
			printf("Wallet %d got corrupted\n", i);
			reportFailure();
			abort = 1;
			break;
		}
		uninitWallet();
	}
	if (!abort)
	{
		reportSuccess();
	}

	// Check that addresses from each wallet are unique.
	abort_duplicate = 0;
	for (i = 0; i < (int)returned_num_wallets; i++)
	{
		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(address_buffer[i * 20]), &(address_buffer[j * 20]), 20))
			{
				printf("Different wallets generate the same addresses\n");
				abort_duplicate = 1;
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
	sanitiseNonVolatileStorage(0, 0xffffffff);
	memset(encryption_key, 1, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	nonVolatileRead((uint8_t *)&unencrypted_part, ADDRESS_WALLET_START, sizeof(unencrypted_part));
	memcpy(name, "This will be ignored                    ", NAME_LENGTH);
	if (newWallet(0, name, 0, NULL, 1) != WALLET_NO_ERROR)
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
	nonVolatileRead((uint8_t *)&compare_unencrypted_part, ADDRESS_WALLET_START, sizeof(compare_unencrypted_part));
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
	if (initWallet(0) != WALLET_NO_ERROR)
	{
		printf("Could not load hidden wallet\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// It should be possible to change the encryption key of a hidden wallet.
	memset(new_encryption_key, 42, WALLET_ENCRYPTION_KEY_LENGTH);
	if (changeEncryptionKey(new_encryption_key) != WALLET_NO_ERROR)
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
	nonVolatileRead((uint8_t *)&compare_unencrypted_part, ADDRESS_WALLET_START, sizeof(compare_unencrypted_part));
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
	setEncryptionKey(new_encryption_key);
	uninitWallet();
	if (initWallet(0) != WALLET_NO_ERROR)
	{
		printf("Could not load hidden wallet after encryption key change\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	setEncryptionKey(encryption_key);
	uninitWallet();
	if (initWallet(0) != WALLET_NOT_THERE)
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
	setEncryptionKey(new_encryption_key);
	initWallet(0);
	memset(new_encryption_key, 0, WALLET_ENCRYPTION_KEY_LENGTH);
	if (changeEncryptionKey(new_encryption_key) != WALLET_NO_ERROR)
	{
		printf("Couldn't change encryption key for hidden wallet 2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	uninitWallet();
	nonVolatileRead((uint8_t *)&compare_unencrypted_part, ADDRESS_WALLET_START, sizeof(compare_unencrypted_part));
	if (memcmp(&unencrypted_part, &compare_unencrypted_part, sizeof(unencrypted_part)))
	{
		printf("Key change on hidden wallet results in writes to unencrypted portion of wallet storage 2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	setEncryptionKey(new_encryption_key);
	uninitWallet();
	if (initWallet(0) != WALLET_NO_ERROR)
	{
		printf("Could not load hidden wallet after encryption key change 2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	setEncryptionKey(encryption_key);
	uninitWallet();
	if (initWallet(0) != WALLET_NOT_THERE)
	{
		printf("Could load hidden wallet with old encryption key 2\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Wallet name changes on a hidden wallet should be disallowed.
	setEncryptionKey(new_encryption_key);
	initWallet(0);
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
	initWallet(0);
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
	newWallet(0, name, 0, NULL, 0);
	newWallet(0, name, 0, NULL, 1);
	getWalletInfo(version, temp, wallet_uuid, 0);
	if (readU32LittleEndian(version) != VERSION_NOTHING_THERE)
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
	newWallet(0, name, 0, NULL, 0);
	newWallet(0, name, 0, NULL, 1);
	getWalletInfo(version, temp, wallet_uuid, 0);
	getWalletInfo(version, temp, wallet_uuid2, 1);
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
	memset(encryption_key, 42, WALLET_ENCRYPTION_KEY_LENGTH);
	setEncryptionKey(encryption_key);
	newWallet(0, name, 0, NULL, 0);
	getWalletInfo(version, temp, wallet_uuid2, 0);
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
	getWalletInfo(version, temp, wallet_uuid, 0);
	initWallet(0);
	memset(new_encryption_key, 0, WALLET_ENCRYPTION_KEY_LENGTH);
	changeEncryptionKey(new_encryption_key);
	makeNewAddress(address1, &public_key);
	changeWalletName(name2);
	uninitWallet();
	setEncryptionKey(new_encryption_key);
	initWallet(0);
	getWalletInfo(version, temp, wallet_uuid2, 0);
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
	newWallet(0, name, 0, NULL, 0);
	initWallet(0);
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

	fclose(wallet_test_file);

	finishTests();
	exit(0);
}

#endif // #ifdef TEST_WALLET

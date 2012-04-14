// ***********************************************************************
// wallet.c
// ***********************************************************************
//
// Manages Bitcoin addresses. Addresses are stored in wallets, which can be
// "loaded" or "unloaded". A loaded wallet can have operations (eg. new
// address) performed on it, whereas an unloaded wallet can only sit dormant.
// Addresses aren't actually physically stored in non-volatile storage;
// rather a seed for a deterministic private key generation algorithm is
// stored and private keys are generated when they are needed. This means
// that obtaining an address is a slow operation (requiring a point multiply),
// so the host should try to remember all public keys and addresses.
//
// This file is licensed as described by the file LICENCE.

// Defining this will facilitate testing
//#define TEST
// Defining this will provide useless stubs for interface functions, to stop
// linker errors from occuring
//#define INTERFACE_STUBS

#include "common.h"
#include "endian.h"
#include "wallet.h"
#include "prandom.h"
#include "sha256.h"
#include "ripemd160.h"
#include "ecdsa.h"
#include "hwinterface.h"
#include "xex.h"

#if defined(TEST) || defined(INTERFACE_STUBS)
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

FILE *wallet_test_file;
#endif // #if defined(TEST) || defined(INTERFACE_STUBS)

static WalletErrors last_error;
static uint8_t wallet_loaded;
static uint32_t num_addresses;

// Returns the last error which occurred in any wallet function.
// If no error occurred in the last wallet function that was called, this
// will return WALLET_NO_ERROR.
WalletErrors walletGetLastError(void)
{
	return last_error;
}

#if defined(TEST) || defined(INTERFACE_STUBS)

void initWalletTest(void)
{
	wallet_test_file = fopen("wallet_test.bin", "w+b");
	if (wallet_test_file == NULL)
	{
		printf("Could not open \"wallet_test.bin\" for writing\n");
		exit(1);
	}
}

#endif // #if defined(TEST) || defined(INTERFACE_STUBS)

#ifdef TEST
// Maximum of addresses which can be stored in storage area - for testing
// only. This should actually be the capacity of the wallet, since one
// of the tests is to see what happens when the wallet is full.
#define MAX_TESTING_ADDRESSES	7
#endif // #ifdef TEST

// Wallet storage format:
// Each record is 160 bytes
// 4 bytes: little endian version
//          0x00000000: nothing here
//          0x00000001: v0.1 wallet format (not supported)
//          0x00000002: unencrypted wallet
//          0x00000003: encrypted wallet, host provides key
// 4 bytes: reserved
// 40 bytes: name of wallet (padded with spaces)
// 4 bytes: little endian number of addresses
// 8 bytes: random data
// 4 bytes: reserved
// 64 bytes: seed for deterministic address generator
// 32 bytes: SHA-256 of everything except number of addresses and this
// The first 48 bytes are unencrypted, the last 112 bytes are encrypted.
#define RECORD_LENGTH			160 // must be multiple of 32 for newWallet() to work properly
#define ENCRYPT_START			48
#define OFFSET_VERSION			0
#define OFFSET_RESERVED1		4
#define OFFSET_NAME				8
#define OFFSET_NUM_ADDRESSES	48
#define OFFSET_NONCE1			52
#define OFFSET_RESERVED2		60
#define OFFSET_SEED				64
#define OFFSET_CHECKSUM			128
#define VERSION_NOTHING_THERE	0x00000000
#define VERSION_UNENCRYPTED		0x00000002
#define VERSION_IS_ENCRYPTED	0x00000003

// Calculate the checksum (SHA-256 hash) of the wallet. The result will be
// written to hash, which must have space for 32 bytes.
// Return values have the same meaning as they do for nonVolatileRead().
static NonVolatileReturn calculateWalletChecksum(uint8_t *hash)
{
	uint16_t i;
	uint8_t buffer[4];
	HashState hs;
	NonVolatileReturn r;

	sha256Begin(&hs);
	for (i = 0; i < RECORD_LENGTH; i += 4)
	{
		// Skip number of addresses and checksum.
		if (i == OFFSET_NUM_ADDRESSES)
		{
			i += 4;
		}
		if (i == OFFSET_CHECKSUM)
		{
			i += 32;
		}
		if (i < RECORD_LENGTH)
		{
			// "The first 48 bytes are unencrypted, the last 112 bytes are
			// encrypted."
			if (i < 48)
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

// Initialise wallet (load it if it's there). A return value of
// WALLET_NO_ERROR indicates success, anything else indicates failure.
WalletErrors initWallet(void)
{
	uint8_t buffer[32];
	uint8_t hash[32];
	uint8_t i;
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
	for (i = 0; i < 32; i++)
	{
		if (buffer[i] != hash[i])
		{
			last_error = WALLET_NOT_THERE;
			return last_error;
		}
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

// Unload wallet, so that it cannot be used until initWallet() is called.
// A return value of WALLET_NO_ERROR indicates success, anything else
// indicates failure.
WalletErrors uninitWallet(void)
{
	wallet_loaded = 0;
	num_addresses = 0;
	last_error = WALLET_NO_ERROR;
	return last_error;
}

// Sanitise (clear) non-volatile storage between the addresses start
// (inclusive) and end (exclusive). start and end must be a multiple of
// 32.
// This will still return WALLET_NO_ERROR even if end is an address beyond the
// end of the non-volatile storage area. This done so that using
// start == 0 and end == 0xffffffff will clear the entire non-volatile storage
// area.
WalletErrors sanitiseNonVolatileStorage(uint32_t start, uint32_t end)
{
	uint8_t buffer[32];
	uint32_t address;
	NonVolatileReturn r;
	uint8_t pass;
	uint8_t i;

	r = NV_NO_ERROR;
	for (pass = 0; pass < 4; pass++)
	{
		address = start;
		r = NV_NO_ERROR;
		while ((r == NV_NO_ERROR) && (address < end))
		{
			if (pass == 0)
			{
				for (i = 0; i < 32; i++)
				{
					buffer[i] = 0;
				}
			}
			else if (pass == 1)
			{
				for (i = 0; i < 32; i++)
				{
					buffer[i] = 0xff;
				}
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

// Writes 4-byte wallet version. This is in its own function because
// it's used by both newWallet() and changeEncryptionKey().
// Return values have the same meaning as they do for nonVolatileWrite().
// Warning: a wallet must be loaded before calling this.
static NonVolatileReturn writeWalletVersion(void)
{
	uint8_t buffer[4];

	if (areEncryptionKeysNonZero())
	{
		writeU32LittleEndian(buffer, VERSION_IS_ENCRYPTED);
	}
	else
	{
		writeU32LittleEndian(buffer, VERSION_UNENCRYPTED);
	}
	return nonVolatileWrite(buffer, OFFSET_VERSION, 4);
}

// Writes wallet checksum. This is in its own function because
// it's used by both newWallet(), changeEncryptionKey() and
// changeWalletName().
// A return value of WALLET_NO_ERROR indicates success, anything else
// indicates failure.
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

// Create new wallet. name should point to 40 bytes (padded with spaces if
// necessary) containing the desired name of the wallet. A brand new wallet
// contains no addresses. A return value of WALLET_NO_ERROR indicates success,
// anything else indicates failure.
// If this returns WALLET_NO_ERROR, then the wallet will also be loaded.
// Warning: this will erase the current one.
WalletErrors newWallet(uint8_t *name)
{
	uint8_t buffer[32];
	WalletErrors r;

	// Erase all traces of the existing wallet.
	r = sanitiseNonVolatileStorage(0, RECORD_LENGTH);
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
	if (nonVolatileWrite(name, OFFSET_NAME, 40) != NV_NO_ERROR)
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

// Generate a new address, writing the address to out_address and the public
// key to out_public_key. out_address must have space for 20 bytes.
// Returns the address handle on success, or BAD_ADDRESS_HANDLE if an error
// occurred.
AddressHandle makeNewAddress(uint8_t *out_address, PointAffine *out_public_key)
{
	uint8_t buffer[4];

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_THERE;
		return BAD_ADDRESS_HANDLE;
	}
#ifdef TEST
	if (num_addresses == MAX_TESTING_ADDRESSES)
#else
	if (num_addresses == MAX_ADDRESSES)
#endif // #ifdef TEST
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

// Given an address handle, generate the address and public key associated
// with that address handle, placing the result in out. out must have space
// for 20 bytes.
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
	setFieldToP();
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
	for (i = 0; i < 20; i++)
	{
		out_address[i] = buffer[i];
	}

	last_error = WALLET_NO_ERROR;
	return last_error;
}

// Get current number of addresses in wallet.
// Returns 0 on error.
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

// Gets the 32-byte private key for a given address handle. out must have
// space for 32 bytes.
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

// Change the encryption key for a wallet to the key specified by new_key.
// new_key should point to an array of 32 bytes.
WalletErrors changeEncryptionKey(uint8_t *new_key)
{
	uint8_t old_key[32];
	uint8_t buffer[16];
	NonVolatileReturn r;
	uint32_t address;
	uint32_t end;

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_THERE;
		return last_error;
	}

	getEncryptionKeys(old_key);
	r = NV_NO_ERROR;
	address = ENCRYPT_START;
	end = RECORD_LENGTH;
	while ((r == NV_NO_ERROR) && (address < end))
	{
		setEncryptionKey(old_key);
		setTweakKey(&(old_key[16]));
		r = encryptedNonVolatileRead(buffer, address, 16);
		if (r == NV_NO_ERROR)
		{
			setEncryptionKey(new_key);
			setTweakKey(&(new_key[16]));
			r = encryptedNonVolatileWrite(buffer, address, 16);
			nonVolatileFlush();
		}
		address += 16;
	}

	setEncryptionKey(new_key);
	setTweakKey(&(new_key[16]));
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

// Change the name of the currently loaded wallet. name should point to 40
// bytes (padded with spaces if necessary) containing the desired name of the
// wallet.
WalletErrors changeWalletName(uint8_t *new_name)
{
	WalletErrors r;

	if (!wallet_loaded)
	{
		last_error = WALLET_NOT_THERE;
		return last_error;
	}

	// Write wallet name.
	if (nonVolatileWrite(new_name, OFFSET_NAME, 40) != NV_NO_ERROR)
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

// Obtain publicly available information about a wallet. out_version should
// have enough space to store 4 bytes. out_name should have enough space to
// store 40 bytes. Upon success, out_version will contain the little-endian
// version of the wallet and out_name will contain the (space-padded) name
// of the wallet.
// The wallet doesn't need to be loaded.
WalletErrors getWalletInfo(uint8_t *out_version, uint8_t *out_name)
{
	if (nonVolatileRead(out_version, OFFSET_VERSION, 4) != NV_NO_ERROR)
	{
		last_error = WALLET_READ_ERROR;
		return last_error;
	}
	if (nonVolatileRead(out_name, OFFSET_NAME, 40) != NV_NO_ERROR)
	{
		last_error = WALLET_READ_ERROR;
		return last_error;
	}

	last_error = WALLET_NO_ERROR;
	return last_error;
}

#if defined(TEST) || defined(INTERFACE_STUBS)

// Size of storage area, in bytes.
#define TEST_FILE_SIZE 1024

NonVolatileReturn nonVolatileWrite(uint8_t *data, uint32_t address, uint8_t length)
{
	int i;
	if ((address + (uint32_t)length) > TEST_FILE_SIZE)
	{
		return NV_INVALID_ADDRESS;
	}
	printf("nv write, addr = 0x%08x, length = 0x%04x, data =", (int)address, (int)length);
	for (i = 0; i < length; i++)
	{
		printf(" %02x", data[i]);
	}
	printf("\n");
	fseek(wallet_test_file, address, SEEK_SET);
	fwrite(data, (size_t)length, 1, wallet_test_file);
	return NV_NO_ERROR;
}

NonVolatileReturn nonVolatileRead(uint8_t *data, uint32_t address, uint8_t length)
{
	if ((address + (uint32_t)length) > TEST_FILE_SIZE)
	{
		return NV_INVALID_ADDRESS;
	}
	fseek(wallet_test_file, address, SEEK_SET);
	fread(data, (size_t)length, 1, wallet_test_file);
	return NV_NO_ERROR;
}

void nonVolatileFlush(void)
{
	fflush(wallet_test_file);
}

void sanitiseRam(void)
{
	// do nothing
}

#endif // #if defined(TEST) || defined(INTERFACE_STUBS)

#ifdef TEST

static int succeeded;
static int failed;

// Call everything without and make sure
// they return WALLET_NOT_THERE somehow.
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
		succeeded++;
	}
	else
	{
		printf("makeNewAddress() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	check_num_addresses = getNumAddresses();
	if ((check_num_addresses == 0) && (walletGetLastError() == WALLET_NOT_THERE))
	{
		succeeded++;
	}
	else
	{
		printf("getNumAddresses() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	if (getAddressAndPublicKey(temp, &public_key, 0) == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	if (getPrivateKey(temp, 0) == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("getPrivateKey() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	if (changeEncryptionKey(temp) == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("changeEncryptionKey() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	if (changeWalletName(temp) == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("changeWalletName() doesn't recognise when wallet isn't there\n");
		failed++;
	}
}

int main(void)
{
	uint8_t temp[128];
	uint8_t address1[20];
	uint8_t address2[20];
	uint8_t name[40];
	uint8_t encryption_key[16];
	uint8_t tweak_key[16];
	uint8_t new_encryption_key[32];
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

	srand(42);
	succeeded = 0;
	failed = 0;
	initWalletTest();
	memset(encryption_key, 0, 16);
	memset(tweak_key, 0, 16);
	setEncryptionKey(encryption_key);
	setTweakKey(tweak_key);
	// Blank out non-volatile storage area (set to all nulls).
	temp[0] = 0;
	for (i = 0; i < TEST_FILE_SIZE; i++)
	{
		fwrite(temp, 1, 1, wallet_test_file);
	}

	// sanitiseNonVolatileStorage() should nuke everything.
	if (sanitiseNonVolatileStorage(0, 0xffffffff) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Cannot nuke NV storage using sanitiseNonVolatileStorage()\n");
		failed++;
	}

	// Check that the version field is "wallet not there".
	if (getWalletInfo(version, temp) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("getWalletInfo() failed after sanitiseNonVolatileStorage() was called\n");
		failed++;
	}
	if (readU32LittleEndian(version) == VERSION_NOTHING_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("sanitiseNonVolatileStorage() does not set version to nothing there\n");
		failed++;
	}

	// initWallet() hasn't been called yet, so nearly every function should
	// return WALLET_NOT_THERE somehow.
	checkFunctionsReturnWalletNotThere();

	// The non-volatile storage area was blanked out, so there shouldn't be a
	// (valid) wallet there.
	if (initWallet() == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("initWallet() doesn't recognise when wallet isn't there\n");
		failed++;
	}

	// Try creating a wallet and testing initWallet() on it.
	memcpy(name, "123456789012345678901234567890abcdefghij", 40);
	if (newWallet(name) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Could not create new wallet\n");
		failed++;
	}
	if (initWallet() == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("initWallet() does not recognise new wallet\n");
		failed++;
	}
	if ((getNumAddresses() == 0) && (walletGetLastError() == WALLET_EMPTY))
	{
		succeeded++;
	}
	else
	{
		printf("New wallet isn't empty\n");
		failed++;
	}

	// Check that the version field is "unencrypted wallet".
	if (getWalletInfo(version, temp) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("getWalletInfo() failed after newWallet() was called\n");
		failed++;
	}
	if (readU32LittleEndian(version) == VERSION_UNENCRYPTED)
	{
		succeeded++;
	}
	else
	{
		printf("newWallet() does not set version to unencrypted wallet\n");
		failed++;
	}

	// Check that sanitise_nv_wallet() deletes wallet.
	if (sanitiseNonVolatileStorage(0, 0xffffffff) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Cannot nuke NV storage using sanitiseNonVolatileStorage()\n");
		failed++;
	}
	if (initWallet() == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("sanitiseNonVolatileStorage() isn't deleting wallet\n");
		failed++;
	}

	// Make some new addresses, then create a new wallet and make sure the
	// new wallet is empty (i.e. check that newWallet() deletes existing
	// wallet).
	newWallet(name);
	if (makeNewAddress(temp, &public_key) != BAD_ADDRESS_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		failed++;
	}
	newWallet(name);
	if ((getNumAddresses() == 0) && (walletGetLastError() == WALLET_EMPTY))
	{
		succeeded++;
	}
	else
	{
		printf("newWallet() doesn't delete existing wallet\n");
		failed++;
	}

	// Unload wallet and make sure everything realises that the wallet is
	// not loaded.
	if (uninitWallet() == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("uninitWallet() failed to do its basic job\n");
		failed++;
	}
	checkFunctionsReturnWalletNotThere();

	// Load wallet again. Since there is actually a wallet there, this
	// should succeed.
	if (initWallet() == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("uninitWallet() appears to be permanent\n");
		failed++;
	}

	// Change bytes in non-volatile memory and make sure initWallet() fails
	// because of the checksum check.
	if (uninitWallet() != WALLET_NO_ERROR)
	{
		printf("uninitWallet() failed to do its basic job 2\n");
		failed++;
	}
	abort = 0;
	for (i = 0; i < RECORD_LENGTH; i++)
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
		succeeded++;
	}
	else
	{
		failed++;
	}

	// Create 2 new wallets and check that their addresses aren't the same
	newWallet(name);
	if (makeNewAddress(address1, &public_key) != BAD_ADDRESS_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		failed++;
	}
	newWallet(name);
	memset(address2, 0, 20);
	memset(&public_key, 0, sizeof(PointAffine));
	if (makeNewAddress(address2, &public_key) != BAD_ADDRESS_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		failed++;
	}
	if (memcmp(address1, address2, 20))
	{
		succeeded++;
	}
	else
	{
		printf("New wallets are creating identical addresses\n");
		failed++;
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
		failed++;
	}
	else
	{
		succeeded++;
	}
	if (bigIsZero(public_key.x))
	{
		printf("makeNewAddress() doesn't write the public key\n");
		failed++;
	}
	else
	{
		succeeded++;
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
		succeeded++;
	}
	else
	{
		failed++;
	}

	// The wallet should be full now.
	// Check that making a new address now causes an appropriate error.
	if (makeNewAddress(temp, &public_key) == BAD_ADDRESS_HANDLE)
	{
		if (walletGetLastError() == WALLET_FULL)
		{
			succeeded++;
		}
		else
		{
			printf("Creating a new address on a full wallet gives incorrect error\n");
			failed++;
		}
	}
	else
	{
		printf("Creating a new address on a full wallet succeeds (it's not supposed to)\n");
		failed++;
	}

	// Check that getNumAddresses() fails when the wallet is empty.
	newWallet(name);
	if (getNumAddresses() == 0)
	{
		if (walletGetLastError() == WALLET_EMPTY)
		{
			succeeded++;
		}
		else
		{
			printf("getNumAddresses() doesn't recognise wallet is empty\n");
			failed++;
		}
	}
	else
	{
		printf("getNumAddresses() succeeds when used on empty wallet\n");
		failed++;
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
			failed++;
			break;
		}
	}
	if (!abort)
	{
		succeeded++;
	}
	if (getNumAddresses() == MAX_TESTING_ADDRESSES)
	{
		succeeded++;
	}
	else
	{
		printf("getNumAddresses() returns wrong number of addresses\n");
		failed++;
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
				failed++;
				break;
			}
		}
	}
	if (!abort_duplicate)
	{
		succeeded++;
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
				failed++;
				break;
			}
		}
	}
	if (!abort_duplicate)
	{
		succeeded++;
	}

	// The address handles should start at 1 and be sequential.
	abort = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		if (handles_buffer[i] != (AddressHandle)(i + 1))
		{
			printf("Address handle %d should be %d, but got %d\n", i, i + 1, (int)handles_buffer[i]);
			abort = 1;
			failed++;
			break;
		}
	}
	if (!abort)
	{
		succeeded++;
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
			failed++;
			break;
		}
		if ((memcmp(address1, &(address_buffer[i * 20]), 20))
			|| (bigCompare(public_key.x, public_key_buffer[i].x) != BIGCMP_EQUAL)
			|| (bigCompare(public_key.y, public_key_buffer[i].y) != BIGCMP_EQUAL))
		{
			printf("getAddressAndPublicKey() returned mismatching address or public key, ah = %d\n", i);
			abort = 1;
			failed++;
			break;
		}
	}
	if (!abort)
	{
		succeeded++;
	}
	if (!abort_error)
	{
		succeeded++;
	}

	// Test getAddressAndPublicKey() and getPrivateKey() functions using
	// invalid and then valid address handles.
	if (getAddressAndPublicKey(temp, &public_key, 0) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise 0 as invalid address handle\n");
		failed++;
	}
	if (getPrivateKey(temp, 0) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("getPrivateKey() doesn't recognise 0 as invalid address handle\n");
		failed++;
	}
	if (getAddressAndPublicKey(temp, &public_key, BAD_ADDRESS_HANDLE) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise BAD_ADDRESS_HANDLE as invalid address handle\n");
		failed++;
	}
	if (getPrivateKey(temp, BAD_ADDRESS_HANDLE) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("getPrivateKey() doesn't recognise BAD_ADDRESS_HANDLE as invalid address handle\n");
		failed++;
	}
	if (getAddressAndPublicKey(temp, &public_key, handles_buffer[0]) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise valid address handle\n");
		failed++;
	}
	if (getPrivateKey(temp, handles_buffer[0]) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("getPrivateKey() doesn't recognise valid address handle\n");
		failed++;
	}

	free(address_buffer);
	free(public_key_buffer);
	free(handles_buffer);

	// Check that changeEncryptionKey() works.
	memset(new_encryption_key, 0, 32);
	new_encryption_key[0] = 1;
	if (changeEncryptionKey(new_encryption_key) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Couldn't change encryption key\n");
		failed++;
	}

	// Check that the version field is "encrypted wallet".
	if (getWalletInfo(version, temp) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("getWalletInfo() failed after changeEncryptionKey() was called\n");
		failed++;
	}
	if (readU32LittleEndian(version) == VERSION_IS_ENCRYPTED)
	{
		succeeded++;
	}
	else
	{
		printf("changeEncryptionKey() does not set version to encrypted wallet\n");
		failed++;
	}

	// Check name matches what was given in newWallet().
	if (!memcmp(temp, name, 40))
	{
		succeeded++;
	}
	else
	{
		printf("getWalletInfo() doesn't return correct name when wallet is loaded\n");
		failed++;
	}

	// Check that getWalletInfo() still works after unloading wallet.
	uninitWallet();
	if (getWalletInfo(version, temp) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("getWalletInfo() failed after uninitWallet() was called\n");
		failed++;
	}
	if (readU32LittleEndian(version) == VERSION_IS_ENCRYPTED)
	{
		succeeded++;
	}
	else
	{
		printf("uninitWallet() caused wallet version to change\n");
		failed++;
	}

	// Check name matches what was given in newWallet().
	if (!memcmp(temp, name, 40))
	{
		succeeded++;
	}
	else
	{
		printf("getWalletInfo() doesn't return correct name when wallet is not loaded\n");
		failed++;
	}

	// Change wallet's name and check that getWalletInfo() reflects the
	// name change.
	initWallet();
	memcpy(name, "HHHHH HHHHHHHHHHHHHHHHH HHHHHHHHHHHHHH  ", 40);
	if (changeWalletName(name) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("changeWalletName() couldn't change name\n");
		failed++;
	}
	getWalletInfo(version, temp);
	if (!memcmp(temp, name, 40))
	{
		succeeded++;
	}
	else
	{
		printf("getWalletInfo() doesn't reflect name change\n");
		failed++;
	}

	// Check that name change is preserved when unloading and loading a
	// wallet.
	uninitWallet();
	getWalletInfo(version, temp);
	if (!memcmp(temp, name, 40))
	{
		succeeded++;
	}
	else
	{
		printf("getWalletInfo() doesn't reflect name change after unloading wallet\n");
		failed++;
	}

	// Check that initWallet() succeeds (changing the name changes the
	// checksum, so this tests whether the checksum was updated).
	if (initWallet() == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("initWallet() failed after name change\n");
		failed++;
	}
	getWalletInfo(version, temp);
	if (!memcmp(temp, name, 40))
	{
		succeeded++;
	}
	else
	{
		printf("getWalletInfo() doesn't reflect name change after reloading wallet\n");
		failed++;
	}

	// Check that loading the wallet with the old key fails.
	uninitWallet();
	setEncryptionKey(encryption_key);
	setTweakKey(tweak_key);
	if (initWallet() == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("Loading wallet with old encryption key succeeds\n");
		failed++;
	}

	// Check that loading the wallet with the new key succeeds.
	uninitWallet();
	setEncryptionKey(&(new_encryption_key[0]));
	setTweakKey(&(new_encryption_key[16]));
	if (initWallet() == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Loading wallet with new encryption key fails\n");
		failed++;
	}

	// Test the getAddressAndPublicKey() and getPrivateKey() functions on an
	// empty wallet.
	newWallet(name);
	if (getAddressAndPublicKey(temp, &public_key, 0) == WALLET_EMPTY)
	{
		succeeded++;
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't deal with empty wallets correctly\n");
		failed++;
	}
	if (getPrivateKey(temp, 0) == WALLET_EMPTY)
	{
		succeeded++;
	}
	else
	{
		printf("getPrivateKey() doesn't deal with empty wallets correctly\n");
		failed++;
	}

	fclose(wallet_test_file);

	printf("Tests which succeeded: %d\n", succeeded);
	printf("Tests which failed: %d\n", failed);
	exit(0);
}

#endif // #ifdef TEST

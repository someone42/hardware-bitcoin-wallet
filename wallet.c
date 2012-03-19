// ***********************************************************************
// wallet.c
// ***********************************************************************
//
// Manages BitCoin addresses.
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

static wallet_errors lasterror;
static u8 wallet_loaded = 0;
static u32 num_addresses;

// Returns the last error which occurred in any wallet function.
// If no error occurred in the last wallet function that was called, this
// will return WALLET_NO_ERROR.
wallet_errors wallet_get_last_error(void)
{
	return lasterror;
}

#if defined(TEST) || defined(INTERFACE_STUBS)

void wallet_test_init(void)
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
#define RECORD_LENGTH			160 // must be multiple of 32 for new_wallet() to work properly
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

// Calculate the checksum (SHA-256 hash) of the wallet using hs as
// storage for the hash state. The result will be written to hash, which
// must have space for 32 bytes.
// Return values have the same meaning as they do for nonvolatile_read().
static nonvolatile_return calculate_wallet_checksum(u8 *hash, hash_state *hs)
{
	u16 i;
	u8 buffer[4];
	nonvolatile_return r;

	sha256_begin(hs);
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
				r = nonvolatile_read(buffer, i, 4);
			}
			else
			{
				r = encrypted_nonvolatile_read(buffer, i, 4);
			}
			if (r != NV_NO_ERROR)
			{
				return r;
			}
			sha256_writebyte(hs, buffer[0]);
			sha256_writebyte(hs, buffer[1]);
			sha256_writebyte(hs, buffer[2]);
			sha256_writebyte(hs, buffer[3]);
		}
	}
	sha256_finish(hs);
	convertHtobytearray(hash, hs, 1);
	return NV_NO_ERROR;
}

// Initialise wallet (load it if it's there). A return value of
// WALLET_NO_ERROR indicates success, anything else indicates failure.
wallet_errors init_wallet(void)
{
	u8 buffer[32];
	u8 hash[32];
	u8 i;
	u32 version;
	hash_state hs;

	wallet_loaded = 0;

	// Read version.
	if (nonvolatile_read(buffer, OFFSET_VERSION, 4) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return lasterror;
	}
	version = read_u32_littleendian(buffer);
	if ((version != VERSION_UNENCRYPTED) && (version != VERSION_IS_ENCRYPTED))
	{
		lasterror = WALLET_NOT_THERE;
		return lasterror;
	}

	// Calculate checksum and check that it matches.
	if (calculate_wallet_checksum(hash, &hs) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return lasterror;
	}
	if (encrypted_nonvolatile_read(buffer, OFFSET_CHECKSUM, 32) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return lasterror;
	}
	for (i = 0; i < 32; i++)
	{
		if (buffer[i] != hash[i])
		{
			lasterror = WALLET_NOT_THERE;
			return lasterror;
		}
	}

	// Read number of addresses.
	if (encrypted_nonvolatile_read(buffer, OFFSET_NUM_ADDRESSES, 4) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return lasterror;
	}
	num_addresses = read_u32_littleendian(buffer);

	wallet_loaded = 1;
	lasterror = WALLET_NO_ERROR;
	return lasterror;
}

// Unload wallet, so that it cannot be used until init_wallet() is called.
// A return value of WALLET_NO_ERROR indicates success, anything else
// indicates failure.
wallet_errors uninit_wallet(void)
{
	wallet_loaded = 0;
	num_addresses = 0;
	lasterror = WALLET_NO_ERROR;
	return lasterror;
}

// Sanitise (clear) non-volatile storage between the addresses start
// (inclusive) and end (exclusive). start and end must be a multiple of
// 32.
// This will still return WALLET_NO_ERROR even if end is an address beyond the
// end of the non-volatile storage area. This done so that using
// start == 0 and end == 0xffffffff will clear the entire non-volatile storage
// area.
wallet_errors sanitise_nv_storage(u32 start, u32 end)
{
	u8 buffer[32];
	u32 address;
	nonvolatile_return r;
	u8 pass;
	u8 i;

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
				get_random_256(buffer);
			}
			r = nonvolatile_write(buffer, address, 32);
			nonvolatile_flush();
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
		lasterror = WALLET_NO_ERROR;
	}
	else
	{
		lasterror = WALLET_WRITE_ERROR;
	}
	return lasterror;
}

// Create new wallet. name should point to 40 bytes (padded with spaces if
// necessary) containing the desired name of the wallet. A brand new wallet
// contains no addresses. A return value of WALLET_NO_ERROR indicates success,
// anything else indicates failure.
// Warning: this will erase the current one.
wallet_errors new_wallet(u8 *name)
{
	u8 buffer[32];
	u8 hash[32];
	hash_state hs;
	wallet_errors r;

	// Erase all traces of the existing wallet.
	r = sanitise_nv_storage(0, RECORD_LENGTH);
	if (r != WALLET_NO_ERROR)
	{
		lasterror = r;
		return lasterror;
	}

	// Write version.
	if (are_encryption_keys_nonzero())
	{
		write_u32_littleendian(buffer, VERSION_IS_ENCRYPTED);
	}
	else
	{
		write_u32_littleendian(buffer, VERSION_UNENCRYPTED);
	}
	if (nonvolatile_write(buffer, OFFSET_VERSION, 4) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	// Write reserved area 1.
	write_u32_littleendian(buffer, 0);
	if (nonvolatile_write(buffer, OFFSET_RESERVED1, 4) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	// Write name of wallet.
	if (nonvolatile_write(name, OFFSET_NAME, 40) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	// Write number of addresses.
	write_u32_littleendian(buffer, 0);
	if (encrypted_nonvolatile_write(buffer, OFFSET_NUM_ADDRESSES, 4) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	// Write nonce 1.
	get_random_256(buffer);
	if (encrypted_nonvolatile_write(buffer, OFFSET_NONCE1, 8) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	// Write reserved area 2.
	write_u32_littleendian(buffer, 0);
	if (encrypted_nonvolatile_write(buffer, OFFSET_RESERVED2, 4) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	// Write seed for deterministic address generator.
	get_random_256(buffer);
	if (encrypted_nonvolatile_write(buffer, OFFSET_SEED, 32) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	get_random_256(buffer);
	if (encrypted_nonvolatile_write(buffer, OFFSET_SEED + 32, 32) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	nonvolatile_flush();

	// Write checksum.
	if (calculate_wallet_checksum(hash, &hs) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return lasterror;
	}
	if (encrypted_nonvolatile_write(hash, OFFSET_CHECKSUM, 32) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	nonvolatile_flush();

	lasterror = init_wallet();
	return lasterror;
}

// Generate a new address, writing the address to out_address and the public
// key to out_pubkey. out_address must have space for 20 bytes.
// Returns the address handle on success, or BAD_ADDRESS_HANDLE if an error
// occurred.
address_handle make_new_address(u8 *out_address, point_affine *out_pubkey)
{
	u8 buffer[4];

	if (!wallet_loaded)
	{
		lasterror = WALLET_NOT_THERE;
		return BAD_ADDRESS_HANDLE;
	}
#ifdef TEST
	if (num_addresses == MAX_TESTING_ADDRESSES)
#else
	if (num_addresses == MAX_ADDRESSES)
#endif // #ifdef TEST
	{
		lasterror = WALLET_FULL;
		return BAD_ADDRESS_HANDLE;
	}
	num_addresses++;
	write_u32_littleendian(buffer, num_addresses);
	if (encrypted_nonvolatile_write(buffer, OFFSET_NUM_ADDRESSES, 4) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return BAD_ADDRESS_HANDLE;
	}
	lasterror = get_address_and_pubkey(out_address, out_pubkey, num_addresses);
	if (lasterror != WALLET_NO_ERROR)
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
wallet_errors get_address_and_pubkey(u8 *out_address, point_affine *out_pubkey, address_handle ah)
{
	u8 buffer[32];
	hash_state hs;
	wallet_errors r;
	u8 i;

	if (!wallet_loaded)
	{
		lasterror = WALLET_NOT_THERE;
		return lasterror;
	}
	if (num_addresses == 0)
	{
		lasterror = WALLET_EMPTY;
		return lasterror;
	}
	if ((ah == 0) || (ah > num_addresses) || (ah == BAD_ADDRESS_HANDLE))
	{
		lasterror = WALLET_INVALID_HANDLE;
		return lasterror;
	}

	// Calculate private key.
	r = get_privkey(buffer, ah);
	if (r != WALLET_NO_ERROR)
	{
		lasterror = r;
		return r;
	}
	// Calculate public key.
	set_field_to_p();
	set_to_G(out_pubkey);
	point_multiply(out_pubkey, buffer);
	// Calculate address. The BitCoin convention is to hash the public key in
	// big-endian format, which is why the counters run backwards in the next
	// two loops.
	sha256_begin(&hs);
	sha256_writebyte(&hs, 0x04);
	for (i = 32; i--; )
	{
		sha256_writebyte(&hs, out_pubkey->x[i]);
	}
	for (i = 32; i--; )
	{
		sha256_writebyte(&hs, out_pubkey->y[i]);
	}
	sha256_finish(&hs);
	convertHtobytearray(buffer, &hs, 1);
	ripemd160_begin(&hs);
	for (i = 0; i < 32; i++)
	{
		ripemd160_writebyte(&hs, buffer[i]);
	}
	ripemd160_finish(&hs);
	convertHtobytearray(buffer, &hs, 1);
	for (i = 0; i < 20; i++)
	{
		out_address[i] = buffer[i];
	}

	lasterror = WALLET_NO_ERROR;
	return lasterror;
}

// Get current number of addresses in wallet.
// Returns 0 on error.
u32 get_num_addresses(void)
{
	if (!wallet_loaded)
	{
		lasterror = WALLET_NOT_THERE;
		return 0;
	}
	if (num_addresses == 0)
	{
		lasterror = WALLET_EMPTY;
		return 0;
	}
	else
	{
		lasterror = WALLET_NO_ERROR;
		return num_addresses;
	}
}

// Gets the 32-byte private key for a given address handle. out must have
// space for 32 bytes.
wallet_errors get_privkey(u8 *out, address_handle ah)
{
	u8 seed[64];

	if (!wallet_loaded)
	{
		lasterror = WALLET_NOT_THERE;
		return lasterror;
	}
	if (num_addresses == 0)
	{
		lasterror = WALLET_EMPTY;
		return lasterror;
	}
	if ((ah == 0) || (ah > num_addresses) || (ah == BAD_ADDRESS_HANDLE))
	{
		lasterror = WALLET_INVALID_HANDLE;
		return lasterror;
	}
	if (encrypted_nonvolatile_read(seed, OFFSET_SEED, 64) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return lasterror;
	}
	generate_deterministic_256(out, seed, ah);
	lasterror = WALLET_NO_ERROR;
	return lasterror;
}

// Change the encryption key for a wallet to the key specified by new_key.
// new_key should point to an array of 32 bytes.
wallet_errors change_encryption_key(u8 *new_key)
{
	u8 old_key[32];
	u8 buffer[16];
	nonvolatile_return r;
	u32 address;
	u32 end;

	if (!wallet_loaded)
	{
		lasterror = WALLET_NOT_THERE;
		return lasterror;
	}

	get_encryption_keys(old_key);
	r = NV_NO_ERROR;
	address = ENCRYPT_START;
	end = RECORD_LENGTH;
	while ((r == NV_NO_ERROR) && (address < end))
	{
		set_encryption_key(old_key);
		set_tweak_key(&(old_key[16]));
		r = encrypted_nonvolatile_read(buffer, address, 16);
		if (r == NV_NO_ERROR)
		{
			set_encryption_key(new_key);
			set_tweak_key(&(new_key[16]));
			r = encrypted_nonvolatile_write(buffer, address, 16);
			nonvolatile_flush();
		}
		address += 16;
	}

	set_encryption_key(new_key);
	set_tweak_key(&(new_key[16]));
	if ((r == NV_INVALID_ADDRESS) || (r == NV_NO_ERROR))
	{
		lasterror = WALLET_NO_ERROR;
	}
	else
	{
		lasterror = WALLET_WRITE_ERROR;
	}
	return lasterror;
}

#if defined(TEST) || defined(INTERFACE_STUBS)

// Size of storage area, in bytes.
#define TEST_FILE_SIZE 1024

nonvolatile_return nonvolatile_write(u8 *data, u32 address, u8 length)
{
	int i;
	if ((address + (u32)length) > TEST_FILE_SIZE)
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

nonvolatile_return nonvolatile_read(u8 *data, u32 address, u8 length)
{
	if ((address + (u32)length) > TEST_FILE_SIZE)
	{
		return NV_INVALID_ADDRESS;
	}
	fseek(wallet_test_file, address, SEEK_SET);
	fread(data, (size_t)length, 1, wallet_test_file);
	return NV_NO_ERROR;
}

void nonvolatile_flush(void)
{
	fflush(wallet_test_file);
}

void sanitise_ram(void)
{
	// do nothing
}

#endif // #if defined(TEST) || defined(INTERFACE_STUBS)

#ifdef TEST

int main(void)
{
	u8 temp[128];
	u8 address1[20];
	u8 address2[20];
	u8 name[40];
	u8 *addressbuffer;
	u8 *addressfound;
	address_handle *handles;
	u32 numaddresses;
	address_handle ah;
	point_affine pubkey;
	int abort;
	int abortduplicate;
	int aborterror;
	int i;
	int j;
	int succeeded;
	int failed;

	srand(42);
	succeeded = 0;
	failed = 0;
	wallet_test_init();
	// Blank out non-volatile storage area (set to all nulls).
	temp[0] = 0;
	for (i = 0; i < TEST_FILE_SIZE; i++)
	{
		fwrite(temp, 1, 1, wallet_test_file);
	}

	// Call everything without first calling init_wallet() and make sure
	// they return WALLET_NOT_THERE somehow.
	// new_wallet() not tested because it calls init_wallet() when it's done.
	ah = make_new_address(temp, &pubkey);
	if ((ah == BAD_ADDRESS_HANDLE) && (wallet_get_last_error() == WALLET_NOT_THERE))
	{
		succeeded++;
	}
	else
	{
		printf("make_new_address() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	numaddresses = get_num_addresses();
	if ((numaddresses == 0) && (wallet_get_last_error() == WALLET_NOT_THERE))
	{
		succeeded++;
	}
	else
	{
		printf("get_num_addresses() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	if (get_address_and_pubkey(temp, &pubkey, 0) == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("get_address_and_pubkey() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	if (get_privkey(temp, 0) == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("get_privkey() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	if (change_encryption_key(temp) == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("change_encryption_key() doesn't recognise when wallet isn't there\n");
		failed++;
	}

	// The non-volatile storage area was blanked out, so there shouldn't be a
	// (valid) wallet there.
	if (init_wallet() == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("init_wallet() doesn't recognise when wallet isn't there\n");
		failed++;
	}

	// Try creating a wallet and testing init_wallet() on it.
	memcpy(name, "123456789012345678901234567890abcdefghij", 40);
	if (new_wallet(name) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Could not create new wallet\n");
		failed++;
	}
	if (init_wallet() == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("init_wallet() does not recognise new wallet\n");
		failed++;
	}
	if ((get_num_addresses() == 0) && (wallet_get_last_error() == WALLET_EMPTY))
	{
		succeeded++;
	}
	else
	{
		printf("New wallet isn't empty\n");
		failed++;
	}

	// Make some new addresses, then create a new wallet and make sure the
	// new wallet is empty (i.e. check that new_wallet() deletes existing
	// wallet).
	if (make_new_address(temp, &pubkey) != BAD_ADDRESS_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		failed++;
	}
	if (new_wallet(name) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Could not create new wallet\n");
		failed++;
	}
	if ((get_num_addresses() == 0) && (wallet_get_last_error() == WALLET_EMPTY))
	{
		succeeded++;
	}
	else
	{
		printf("new_wallet() doesn't delete existing wallet\n");
		failed++;
	}

	// Create 2 new wallets and check that their addresses aren't the same
	if (new_wallet(name) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Could not create new wallet\n");
		failed++;
	}
	if (make_new_address(address1, &pubkey) != BAD_ADDRESS_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		failed++;
	}
	if (new_wallet(name) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Could not create new wallet\n");
		failed++;
	}
	if (make_new_address(address2, &pubkey) != BAD_ADDRESS_HANDLE)
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

	// Make some new addresses, up to a limit.
	// Also check that addresses are unique.
	if (new_wallet(name) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Could not create new wallet\n");
		failed++;
	}
	abort = 0;
	addressbuffer = malloc(MAX_TESTING_ADDRESSES * 20);
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		if (make_new_address(&(addressbuffer[i * 20]), &pubkey) == BAD_ADDRESS_HANDLE)
		{
			printf("Couldn't create new address in new wallet\n");
			abort = 1;
			break;
		}
		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(addressbuffer[i * 20]), &(addressbuffer[j * 20]), 20))
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
	free(addressbuffer);
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
	if (make_new_address(temp, &pubkey) == BAD_ADDRESS_HANDLE)
	{
		if (wallet_get_last_error() == WALLET_FULL)
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

	// Check that get_num_addresses fails when the wallet is empty.
	if (new_wallet(name) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Could not create new wallet\n");
		failed++;
	}
	if (get_num_addresses() == 0)
	{
		if (wallet_get_last_error() == WALLET_EMPTY)
		{
			succeeded++;
		}
		else
		{
			printf("get_num_addresses() doesn't recognise wallet is empty\n");
			failed++;
		}
	}
	else
	{
		printf("get_num_addresses() succeeds when used on empty wallet\n");
		failed++;
	}

	// Create a bunch of addresses in the (now empty) wallet and check that
	// get_num_addresses returns the right number.
	addressbuffer = malloc(MAX_TESTING_ADDRESSES * 20);
	addressfound = malloc(MAX_TESTING_ADDRESSES);
	handles = malloc(MAX_TESTING_ADDRESSES * sizeof(address_handle));
	abort = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		ah = make_new_address(&(addressbuffer[i * 20]), &pubkey);
		handles[i] = ah;
		if (ah == BAD_ADDRESS_HANDLE)
		{
			printf("Couldn't create new address in new wallet\n");
			abort = 1;
			failed++;
			break;
		}
		addressfound[i] = 0;
	}
	if (!abort)
	{
		succeeded++;
	}
	if (get_num_addresses() == MAX_TESTING_ADDRESSES)
	{
		succeeded++;
	}
	else
	{
		printf("get_num_addresses() returns wrong number of addresses\n");
		failed++;
	}

	// The wallet should contain unique addresses.
	abortduplicate = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		for (j = 0; j < i; j++)
		{
			if (!memcmp(&(addressbuffer[i * 20]), &(addressbuffer[j * 20]), 20))
			{
				printf("Wallet has duplicate addresses\n");
				abortduplicate = 1;
				failed++;
				break;
			}
		}
	}
	if (!abortduplicate)
	{
		succeeded++;
	}

	// While there's a bunch of addresses in the wallet, check that getting
	// the address of every address handle returns every address.
	aborterror = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		ah = (address_handle)(i + 1);
		if (get_address_and_pubkey(address1, &pubkey, ah) != WALLET_NO_ERROR)
		{
			printf("Couldn't obtain address in wallet\n");
			aborterror = 1;
			failed++;
			break;
		}
		for (j = 0; j < MAX_TESTING_ADDRESSES; j++)
		{
			if (!memcmp(address1, &(addressbuffer[j * 20]), 20))
			{
				addressfound[j] = 1;
			}
		}
	}
	abort = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		if (!addressfound[i])
		{
			printf("get_address_and_pubkey() returned addresses which are not in wallet\n");
			abort = 1;
			failed++;
			break;
		}
	}
	if (!abort)
	{
		succeeded++;
	}
	if (!aborterror)
	{
		succeeded++;
	}

	// Test get_address_and_pubkey and get_privkey functions using invalid
	// and then valid address handles.
	if (get_address_and_pubkey(temp, &pubkey, 0) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("get_address_and_pubkey() doesn't recognise 0 as invalid address handle\n");
		failed++;
	}
	if (get_privkey(temp, 0) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("get_privkey() doesn't recognise 0 as invalid address handle\n");
		failed++;
	}
	if (get_address_and_pubkey(temp, &pubkey, BAD_ADDRESS_HANDLE) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("get_address_and_pubkey() doesn't recognise BAD_ADDRESS_HANDLE as invalid address handle\n");
		failed++;
	}
	if (get_privkey(temp, BAD_ADDRESS_HANDLE) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("get_privkey() doesn't recognise BAD_ADDRESS_HANDLE as invalid address handle\n");
		failed++;
	}
	if (get_address_and_pubkey(temp, &pubkey, handles[0]) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("get_address_and_pubkey() doesn't recognise valid address handle\n");
		failed++;
	}
	if (get_privkey(temp, handles[0]) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("get_privkey() doesn't recognise valid address handle\n");
		failed++;
	}

	free(addressbuffer);
	free(addressfound);
	free(handles);

	// Test the get_address_and_pubkey and get_privkey functions on an empty
	// wallet.
	if (new_wallet(name) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Could not create new wallet\n");
		failed++;
	}
	if (get_address_and_pubkey(temp, &pubkey, 0) == WALLET_EMPTY)
	{
		succeeded++;
	}
	else
	{
		printf("get_address_and_pubkey() doesn't deal with empty wallets correctly\n");
		failed++;
	}
	if (get_privkey(temp, 0) == WALLET_EMPTY)
	{
		succeeded++;
	}
	else
	{
		printf("get_privkey() doesn't deal with empty wallets correctly\n");
		failed++;
	}

	fclose(wallet_test_file);

	printf("Tests which succeeded: %d\n", succeeded);
	printf("Tests which failed: %d\n", failed);
	exit(0);
}

u8 stream_get_one_byte(u8 *onebyte)
{
	*onebyte = 0;
	return 0; // success
}

#endif // #ifdef TEST

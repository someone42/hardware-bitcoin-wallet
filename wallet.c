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

#if defined(TEST) || defined(INTERFACE_STUBS)
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>

FILE *wallet_test_file;
#endif // #if defined(TEST) || defined(INTERFACE_STUBS)

static wallet_errors lasterror;
static u8 wallet_loaded = 0;
static u32 num_records;
static u32 list_counter;

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

// Wallet storage format:
// Each record is 128 bytes
// First record:
// 4 bytes: little endian version (0 = nothing here)
// 4 bytes: little endian number of records (including this)
// 24 bytes: reserved
// 16 bytes: random number
// 16 bytes: first 16 bytes of SHA-256 of random number
// 64 bytes: seed for deterministic address generator
//
// Other records:
// 20 bytes: address
// 12 bytes: reserved
// 32 bytes: private key (little endian)
// 64 bytes: public key (x then y, no preceding 0x04, little endian)

// Initialise wallet (load it if it's there). A return value of
// WALLET_NO_ERROR indicates success, anything else indicates failure.
wallet_errors init_wallet(void)
{
	u8 buffer[32];
	u8 hash[32];
	u8 i;
	hash_state hs;

	wallet_loaded = 0;
	// Read version and number of records.
	if (nonvolatile_read(0, buffer, 8) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return lasterror;
	}
	if ((buffer[0] != 1) || (buffer[1] != 0)
		|| (buffer[2] != 0) || (buffer[3] != 0))
	{
		lasterror = WALLET_NOT_THERE;
		return lasterror;
	}
	num_records = read_u32_littleendian(&(buffer[4]));
	// Check nonce and hash of nonce.
	if (nonvolatile_read(32, buffer, 32) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return lasterror;
	}
	sha256_begin(&hs);
	for (i = 0; i < 16; i++)
	{
		sha256_writebyte(&hs, buffer[i]);
	}
	sha256_finish(&hs);
	convertHtobytearray(&hs, hash, 1);
	for (i = 0; i < 16; i++)
	{
		if (hash[i] != buffer[i + 16])
		{
			lasterror = WALLET_NOT_THERE;
			return lasterror;
		}
	}
	wallet_loaded = 1;
	lasterror = WALLET_NO_ERROR;
	return lasterror;
}

// Create new wallet. A brand new wallet contains no addresses. A return value
// of WALLET_NO_ERROR indicates success, anything else indicates failure.
// Warning: this will erase the current one.
wallet_errors new_wallet(void)
{
	u8 buffer[32];
	u8 hash[32];
	u8 i;
	hash_state hs;

	// version and number of records
	for (i = 0; i < 32; i++)
	{
		buffer[i] = 0;
	}
	buffer[0] = 1;
	buffer[4] = 1;
	if (nonvolatile_write(0, buffer, 32) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	// nonce and hash of nonce
	get_random_256(buffer);
	if (nonvolatile_write(32, buffer, 16) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	sha256_begin(&hs);
	for (i = 0; i < 16; i++)
	{
		sha256_writebyte(&hs, buffer[i]);
	}
	sha256_finish(&hs);
	convertHtobytearray(&hs, hash, 1);
	if (nonvolatile_write(48, hash, 16) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	// seed for deterministic address generator
	get_random_256(buffer);
	if (nonvolatile_write(64, buffer, 32) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	get_random_256(buffer);
	if (nonvolatile_write(96, buffer, 32) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return lasterror;
	}
	nonvolatile_flush();
	lasterror = init_wallet();
	return lasterror;
}

// Generate a new private/public key pair and write the resulting address
// into the buffer specified by out (which must have space for 20 bytes).
// On success, this returns the address handle of the new address, so that
// you can do other things (such as get the public key) with it. This returns
// BAD_ADDRESS_HANDLE on failure.
address_handle make_new_address(u8 *out)
{
	u32 baseaddress;
	u8 buffer[32];
	u8 seed[64];
	point_affine pubkey;
	hash_state hs;
	nonvolatile_return r;
	u8 i;

	if (!wallet_loaded)
	{
		lasterror = WALLET_NOT_THERE;
		return BAD_ADDRESS_HANDLE;
	}
	baseaddress = num_records << 7;
	// Generate and write private key.
	if (nonvolatile_read(64, seed, 64) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return BAD_ADDRESS_HANDLE;
	}
	generate_deterministic_256(buffer, seed, num_records);
	r = nonvolatile_write(baseaddress + 32, buffer, 32);
	if (r == NV_INVALID_ADDRESS)
	{
		// Attempted to write past end of storage device, so there's no more
		// space left.
		lasterror = WALLET_FULL;
		return BAD_ADDRESS_HANDLE;
	}
	else if (r != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return BAD_ADDRESS_HANDLE;
	}
	// Generate and write public key.
	set_field_to_p();
	set_to_G(&pubkey);
	point_multiply(&pubkey, buffer);
	if (nonvolatile_write(baseaddress + 64, pubkey.x, 32) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return BAD_ADDRESS_HANDLE;
	}
	if (nonvolatile_write(baseaddress + 96, pubkey.y, 32) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return BAD_ADDRESS_HANDLE;
	}
	// Generate and write address. The BitCoin convention is to hash the
	// public key in big-endian format, which is why the counters
	// run backwards in the next two loops.
	sha256_begin(&hs);
	sha256_writebyte(&hs, 0x04);
	for (i = 32; i--; )
	{
		sha256_writebyte(&hs, pubkey.x[i]);
	}
	for (i = 32; i--; )
	{
		sha256_writebyte(&hs, pubkey.y[i]);
	}
	sha256_finish(&hs);
	convertHtobytearray(&hs, buffer, 1);
	ripemd160_begin(&hs);
	for (i = 0; i < 32; i++)
	{
		ripemd160_writebyte(&hs, buffer[i]);
	}
	ripemd160_finish(&hs);
	convertHtobytearray(&hs, buffer, 1);
	for (i = 0; i < 20; i++)
	{
		out[i] = buffer[i];
	}
	for (i = 20; i < 32; i++)
	{
		buffer[i] = 0;
	}
	if (nonvolatile_write(baseaddress, buffer, 32) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return BAD_ADDRESS_HANDLE;
	}
	nonvolatile_flush();
	// Update num_records in RAM and non-volatile storage.
	num_records++;
	write_u32_littleendian(buffer, num_records);
	if (nonvolatile_write(4, buffer, 4) != NV_NO_ERROR)
	{
		lasterror = WALLET_WRITE_ERROR;
		return BAD_ADDRESS_HANDLE;
	}
	nonvolatile_flush();
	lasterror = WALLET_NO_ERROR;
	return num_records - 1;
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
	if (num_records == 1)
	{
		lasterror = WALLET_EMPTY;
		return 0;
	}
	else
	{
		lasterror = WALLET_NO_ERROR;
		return num_records - 1;
	}
}

// Get the first (in ascending order of time created) address in the wallet.
// On success, this returns the address handle for that first address and
// writes the address to out. out must be at least 20 bytes large. Returns
// BAD_ADDRESS_HANDLE on failure.
address_handle list_first_address(u8 *out)
{
	if (!wallet_loaded)
	{
		lasterror = WALLET_NOT_THERE;
		return BAD_ADDRESS_HANDLE;
	}
	if (num_records == 1)
	{
		lasterror = WALLET_EMPTY;
		return BAD_ADDRESS_HANDLE;
	}
	if (nonvolatile_read(128, out, 20) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return BAD_ADDRESS_HANDLE;
	}
	lasterror = WALLET_NO_ERROR;
	list_counter = 2;
	return 1;
}

// Get the next (in ascending order of time created) address in the wallet.
// This can be called repeatedly to obtain all addresses in a wallet. The
// error code WALLET_END_OF_LIST is used when attempting to read past the
// end of the list of addresses.
// On success, this returns the address handle for that next address and
// writes the address to out. out must be at least 20 bytes large. Returns
// BAD_ADDRESS_HANDLE on failure.
// Warning: this assumes most recent call to list_first_address() returned
// successfully.
address_handle list_next_address(u8 *out)
{
	if (!wallet_loaded)
	{
		lasterror = WALLET_NOT_THERE;
		return BAD_ADDRESS_HANDLE;
	}
	if (list_counter >= num_records)
	{
		lasterror = WALLET_END_OF_LIST;
		return BAD_ADDRESS_HANDLE;
	}
	if (nonvolatile_read(list_counter << 7, out, 20) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return BAD_ADDRESS_HANDLE;
	}
	lasterror = WALLET_NO_ERROR;
	return list_counter++;
}

// Check whether an address is in the wallet. address must point to 20 bytes
// which are the address to query. This returns a valid address handle on
// success, or BAD_ADDRESS_HANDLE if an error occurred (eg. if the address
// was not found in the wallet).
address_handle is_mine(u8 *address)
{
	u32 i;
	u8 j;
	u8 buffer[20];
	u8 match;

	if (!wallet_loaded)
	{
		lasterror = WALLET_NOT_THERE;
		return BAD_ADDRESS_HANDLE;
	}
	for (i = 1; i < num_records; i++)
	{
		if (nonvolatile_read(i << 7, buffer, 20) != NV_NO_ERROR)
		{
			lasterror = WALLET_READ_ERROR;
			return BAD_ADDRESS_HANDLE;
		}
		match = 1;
		for (j = 0; j < 20; j++)
		{
			if (address[j] != buffer[j])
			{
				match = 0;
				break;
			}
		}
		if (match)
		{
			lasterror = WALLET_NO_ERROR;
			return i;
		}
	}
	lasterror = WALLET_ADDRESS_NOT_FOUND;
	return BAD_ADDRESS_HANDLE;
}

// Obtains a field from a record. The record number is specified by ah
// (address handles are just record numbers). On success, the contents of
// the field will be written to out. offset specifies the offset (in
// bytes) of the start of the field from the start of the record. length
// specifies the length of the field.
// A return value of WALLET_NO_ERROR indicates success, anything else
// indicates failure.
static wallet_errors get_field(address_handle ah, u8 *out, u32 offset, u8 length)
{
	if (!wallet_loaded)
	{
		lasterror = WALLET_NOT_THERE;
		return lasterror;
	}
	if (num_records == 1)
	{
		lasterror = WALLET_EMPTY;
		return lasterror;
	}
	if ((ah == 0) || (ah >= num_records))
	{
		lasterror = WALLET_INVALID_HANDLE;
		return lasterror;
	}
	if (nonvolatile_read((ah << 7) + offset, out, length) != NV_NO_ERROR)
	{
		lasterror = WALLET_READ_ERROR;
		return lasterror;
	}
	lasterror = WALLET_NO_ERROR;
	return lasterror;
}

// Gets the 20-byte address for a given address handle. See get_field().
wallet_errors get_address(address_handle ah, u8 *out)
{
	return get_field(ah, out, 0, 20);
}

// Gets the 64-byte public key for a given address handle. See get_field().
wallet_errors get_pubkey(address_handle ah, u8 *out)
{
	return get_field(ah, out, 64, 64);
}

// Gets the 32-byte private key for a given address handle. See get_field().
wallet_errors get_privkey(address_handle ah, u8 *out)
{
	return get_field(ah, out, 32, 32);
}

#if defined(TEST) || defined(INTERFACE_STUBS)

// Size of storage area, in bytes.
#define TEST_FILE_SIZE 1024
// Maximum of addresses which can be stored in storage area - for testing
// only. This should actually be the capacity of the wallet, since one
// of the tests is to see what happens when the wallet is full.
#define MAX_TESTING_ADDRESSES	7

nonvolatile_return nonvolatile_write(u32 address, u8 *data, u8 length)
{
	if ((address + (u32)length) > TEST_FILE_SIZE)
	{
		return NV_INVALID_ADDRESS;
	}
	fseek(wallet_test_file, address, SEEK_SET);
	fwrite(data, (size_t)length, 1, wallet_test_file);
	return NV_NO_ERROR;
}

nonvolatile_return nonvolatile_read(u32 address, u8 *data, u8 length)
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

#endif // #if defined(TEST) || defined(INTERFACE_STUBS)

#ifdef TEST

int main(int argc, char **argv)
{
	u8 temp[128];
	u8 address1[20];
	u8 address2[20];
	u8 *addressbuffer;
	u8 *addressfound;
	address_handle *handles;
	u32 numaddresses;
	address_handle ah;
	int abort;
	int abortduplicate;
	int aborterror;
	int i;
	int j;
	int succeeded;
	int failed;

	// Reference argc and argv just to make certain compilers happy.
	if (argc == 2)
	{
		printf("%s\n", argv[1]);
	}

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
	ah = make_new_address(temp);
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
	ah = list_first_address(temp);
	if ((ah == BAD_ADDRESS_HANDLE) && (wallet_get_last_error() == WALLET_NOT_THERE))
	{
		succeeded++;
	}
	else
	{
		printf("list_first_address() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	ah = list_next_address(temp);
	if ((ah == BAD_ADDRESS_HANDLE) && (wallet_get_last_error() == WALLET_NOT_THERE))
	{
		succeeded++;
	}
	else
	{
		printf("list_next_address() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	ah = is_mine(temp);
	if ((ah == BAD_ADDRESS_HANDLE) && (wallet_get_last_error() == WALLET_NOT_THERE))
	{
		succeeded++;
	}
	else
	{
		printf("is_mine() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	if (get_address(0, temp) == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("get_address() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	if (get_pubkey(0, temp) == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("get_pubkey() doesn't recognise when wallet isn't there\n");
		failed++;
	}
	if (get_privkey(0, temp) == WALLET_NOT_THERE)
	{
		succeeded++;
	}
	else
	{
		printf("get_privkey() doesn't recognise when wallet isn't there\n");
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
	if (new_wallet() == WALLET_NO_ERROR)
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
	if (make_new_address(temp) != BAD_ADDRESS_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("Couldn't create new address is new wallet\n");
		failed++;
	}
	if (new_wallet() == WALLET_NO_ERROR)
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
	if (new_wallet() == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Could not create new wallet\n");
		failed++;
	}
	if (make_new_address(address1) != BAD_ADDRESS_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("Couldn't create new address is new wallet\n");
		failed++;
	}
	if (new_wallet() == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Could not create new wallet\n");
		failed++;
	}
	if (make_new_address(address2) != BAD_ADDRESS_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("Couldn't create new address is new wallet\n");
		failed++;
	}
	if (memcmp(address1, address2, 20) != 0)
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
	if (new_wallet() == WALLET_NO_ERROR)
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
		if (make_new_address(&(addressbuffer[i * 20])) == BAD_ADDRESS_HANDLE)
		{
			printf("Couldn't create new address is new wallet\n");
			abort = 1;
			break;
		}
		for (j = 0; j < i; j++)
		{
			if (memcmp(&(addressbuffer[i * 20]), &(addressbuffer[j * 20]), 20) == 0)
			{
				printf("Wallet addresses aren't unique\n");
				abort = 1;
				break;
			}
		}
		if (abort != 0)
		{
			break;
		}
	}
	free(addressbuffer);
	if (abort == 0)
	{
		succeeded++;
	}
	else
	{
		failed++;
	}

	// The wallet should be full now.
	// Check that making a new address now causes an appropriate error.
	if (make_new_address(temp) == BAD_ADDRESS_HANDLE)
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

	// Check that get_num_addresses and the list functions fail when the
	// wallet is empty.
	if (new_wallet() == WALLET_NO_ERROR)
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
	ah = list_first_address(temp);
	if (ah == BAD_ADDRESS_HANDLE)
	{
		if (wallet_get_last_error() == WALLET_EMPTY)
		{
			succeeded++;
		}
		else
		{
			printf("list_first_address() doesn't recognise wallet is empty\n");
			failed++;
		}
	}
	else
	{
		printf("list_first_address() succeeds when used on empty wallet\n");
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
		ah = make_new_address(&(addressbuffer[i * 20]));
		handles[i] = ah;
		if (ah == BAD_ADDRESS_HANDLE)
		{
			printf("Couldn't create new address is new wallet\n");
			abort = 1;
			failed++;
			break;
		}
		addressfound[i] = 0;
	}
	if (abort == 0)
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
			if (memcmp(&(addressbuffer[i * 20]), &(addressbuffer[j * 20]), 20) == 0)
			{
				printf("Wallet has duplicate addresses\n");
				abortduplicate = 1;
				failed++;
				break;
			}
		}
	}
	if (abortduplicate == 0)
	{
		succeeded++;
	}

	// While there's a bunch of addresses in the wallet, check that:
	// - The list functions succeed and
	// - The list functions return every address
	aborterror = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		if (i == 0)
		{
			if (list_first_address(address1) == BAD_ADDRESS_HANDLE)
			{
				printf("Couldn't list first address in wallet\n");
				aborterror = 1;
				failed++;
				break;
			}
		}
		else
		{
			if (list_next_address(address1) == BAD_ADDRESS_HANDLE)
			{
				printf("Couldn't list next address in wallet\n");
				aborterror = 1;
				failed++;
				break;
			}
		}
		for (j = 0; j < MAX_TESTING_ADDRESSES; j++)
		{
			if (memcmp(address1, &(addressbuffer[j * 20]), 20) == 0)
			{
				addressfound[j] = 1;
			}
		}
	}
	abort = 0;
	for (i = 0; i < MAX_TESTING_ADDRESSES; i++)
	{
		if (addressfound[i] == 0)
		{
			printf("List functions return addresses which are not in wallet\n");
			abort = 1;
			failed++;
			break;
		}
	}
	if (abort == 0)
	{
		succeeded++;
	}
	if (aborterror == 0)
	{
		succeeded++;
	}

	// Test is_mine with an address known to be in the wallet and one known
	// not to be in the wallet.
	if (list_first_address(address1) == BAD_ADDRESS_HANDLE)
	{
		printf("Couldn't re-list first address in wallet\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	if (is_mine(address1) == BAD_ADDRESS_HANDLE)
	{
		printf("is_mine() claims that wallet's address is not in wallet\n");
		failed++;
	}
	else
	{
		succeeded++;
	}
	memset(address1, 3, 20);
	if ((is_mine(address1) == BAD_ADDRESS_HANDLE) && (wallet_get_last_error() == WALLET_ADDRESS_NOT_FOUND))
	{
		succeeded++;
	}
	else
	{
		printf("is_mine() claims that wallet contains junk addresses\n");
		failed++;
	}

	// Test get_address, get_privkey and get_pubkey functions using invalid
	// and then valid address handles.
	if (get_address(0, temp) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("get_address() doesn't recognise 0 as invalid address handle\n");
		failed++;
	}
	if (get_pubkey(0, temp) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("get_pubkey() doesn't recognise 0 as invalid address handle\n");
		failed++;
	}
	if (get_privkey(0, temp) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("get_privkey() doesn't recognise 0 as invalid address handle\n");
		failed++;
	}
	if (get_address(BAD_ADDRESS_HANDLE, temp) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("get_address() doesn't recognise BAD_ADDRESS_HANDLE as invalid address handle\n");
		failed++;
	}
	if (get_pubkey(BAD_ADDRESS_HANDLE, temp) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("get_pubkey() doesn't recognise BAD_ADDRESS_HANDLE as invalid address handle\n");
		failed++;
	}
	if (get_privkey(BAD_ADDRESS_HANDLE, temp) == WALLET_INVALID_HANDLE)
	{
		succeeded++;
	}
	else
	{
		printf("get_privkey() doesn't recognise BAD_ADDRESS_HANDLE as invalid address handle\n");
		failed++;
	}
	if (get_address(handles[0], temp) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("get_address() doesn't recognise valid address handle\n");
		failed++;
	}
	if (get_pubkey(handles[0], temp) == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("get_pubkey() doesn't recognise valid address handle\n");
		failed++;
	}
	if (get_privkey(handles[0], temp) == WALLET_NO_ERROR)
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

	// Test is_mine on empty wallet.
	if (new_wallet() == WALLET_NO_ERROR)
	{
		succeeded++;
	}
	else
	{
		printf("Could not create new wallet\n");
		failed++;
	}
	// Both WALLET_EMPTY and WALLET_ADDRESS_NOT_FOUND seem like valid
	// responses to an is_mine query on an empty wallet.
	if ((is_mine(address1) == BAD_ADDRESS_HANDLE) &&
		((wallet_get_last_error() == WALLET_EMPTY) || (wallet_get_last_error() == WALLET_ADDRESS_NOT_FOUND)))
	{
		succeeded++;
	}
	else
	{
		printf("is_mine() doesn't deal with empty wallets correctly\n");
		failed++;
	}

	// While the wallet is empty, test the get_address, get_privkey and
	// get_pubkey functions.
	if (get_address(0, temp) == WALLET_EMPTY)
	{
		succeeded++;
	}
	else
	{
		printf("get_address() doesn't deal with empty wallets correctly\n");
		failed++;
	}
	if (get_pubkey(0, temp) == WALLET_EMPTY)
	{
		succeeded++;
	}
	else
	{
		printf("get_pubkey() doesn't deal with empty wallets correctly\n");
		failed++;
	}
	if (get_privkey(0, temp) == WALLET_EMPTY)
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

#endif // #ifdef TEST

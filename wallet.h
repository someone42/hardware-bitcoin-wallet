// ***********************************************************************
// wallet.h
// ***********************************************************************
//
// This describes functions exported by wallet.c
//
// This file is licensed as described by the file LICENCE.

#ifndef WALLET_H_INCLUDED
#define WALLET_H_INCLUDED

#include "common.h"

// A value which has a one-to-one association with BitCoin addresses. Handles
// are more efficient to deal with than the actual addresses themselves, since
// they are much smaller.
typedef u32 address_handle;

// For functions which return an address_handle, this is an address handle
// which indicates that an error occurred.
#define BAD_ADDRESS_HANDLE	0xFFFFFFFF

// Return values for wallet_get_last_error()
typedef enum wallet_errors_type
{
	// No error actually occurred.
	WALLET_NO_ERROR				=	0,
	// Insufficient space on non-volatile storage device.
	WALLET_FULL					=	1,
	// No addresses in wallet.
	WALLET_EMPTY				=	2,
	// Problems reading from non-volatile storage device.
	WALLET_READ_ERROR			=	3,
	// Problems writing to non-volatile storage device.
	WALLET_WRITE_ERROR			=	4,
	// Address not in wallet (or, invalid address supplied).
	WALLET_ADDRESS_NOT_FOUND	=	5,
	// Wallet doesn't exist.
	WALLET_NOT_THERE			=	6,
	// End of list of addresses.
	WALLET_END_OF_LIST			=	7,
	// Invalid address handle.
	WALLET_INVALID_HANDLE		=	8
} wallet_errors;

extern wallet_errors wallet_get_last_error(void);
extern wallet_errors init_wallet(void);
extern wallet_errors sanitise_nv_storage(u32 start, u32 end);
extern wallet_errors new_wallet(void);
extern address_handle make_new_address(u8 *out);
extern u32 get_num_addresses(void);
extern address_handle list_first_address(u8 *out);
extern address_handle list_next_address(u8 *out);
extern address_handle is_mine(u8 *address);
extern wallet_errors get_address(address_handle ah, u8 *out);
extern wallet_errors get_pubkey(address_handle ah, u8 *out);
extern wallet_errors get_privkey(address_handle ah, u8 *out);

#ifdef TEST
extern void wallet_test_init(void);
#endif // #ifdef TEST

#endif // #ifndef WALLET_H_INCLUDED

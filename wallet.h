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
#include "ecdsa.h"

// A value which has a one-to-one association with Bitcoin addresses. Handles
// are more efficient to deal with than the actual addresses themselves, since
// they are much smaller.
typedef uint32_t AddressHandle;

// For functions which return an address_handle, this is an address handle
// which indicates that an error occurred.
#define BAD_ADDRESS_HANDLE	0xFFFFFFFF
// Absolute maximum number of addresses that can be in a wallet. Practical
// constraints will probably limit the number of addresses to something lower
// than this.
#define MAX_ADDRESSES		0xFFFFFFFE

// Return values for walletGetLastError()
typedef enum WalletErrorsEnum
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
} WalletErrors;

extern WalletErrors walletGetLastError(void);
extern WalletErrors initWallet(void);
extern WalletErrors uninitWallet(void);
extern WalletErrors sanitiseNonVolatileStorage(uint32_t start, uint32_t end);
extern WalletErrors newWallet(uint8_t *name);
extern AddressHandle makeNewAddress(uint8_t *out_address, PointAffine *out_public_key);
extern WalletErrors getAddressAndPublicKey(uint8_t *out_address, PointAffine *out_public_key, AddressHandle ah);
extern uint32_t getNumAddresses(void);
extern WalletErrors getPrivateKey(uint8_t *out, AddressHandle ah);
extern WalletErrors changeEncryptionKey(uint8_t *new_key);
extern WalletErrors changeWalletName(uint8_t *new_name);
extern WalletErrors getWalletInfo(uint8_t *out_version, uint8_t *out_name);

#ifdef TEST
extern void initWalletTest(void);
#endif // #ifdef TEST

#endif // #ifndef WALLET_H_INCLUDED

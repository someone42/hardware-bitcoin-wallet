/** \file wallet.h
  *
  * \brief Describes functions, types and constants exported by wallet.c
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef WALLET_H_INCLUDED
#define WALLET_H_INCLUDED

#include "common.h"
#include "ecdsa.h"
#include "hwinterface.h"

/** A value which has a one-to-one association with Bitcoin addresses in a
  * given wallet. Address handles are more efficient to deal with than the
  * actual addresses themselves, since address handles are much smaller. */
typedef uint32_t AddressHandle;

/** For functions which return an address handle (#AddressHandle), this is an
  * address handle which indicates that an error occurred. */
#define BAD_ADDRESS_HANDLE	0xFFFFFFFF
/** Absolute maximum number of addresses that can be in a wallet. Practical
  * constraints will probably limit the number of addresses to something lower
  * than this. */
#define MAX_ADDRESSES		0xFFFFFFFE

/** Maximum length, in bytes, of the name of a wallet. */
#define NAME_LENGTH			40

/** Possible values for the version field of a wallet record. */
typedef enum WalletVersionEnum
{
	/** Version number which means "nothing here".
	  * \warning This must be 0 or sanitiseNonVolatileStorage() won't clear
	  *          version fields correctly.
	  */
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

/** Return values for walletGetLastError(). Many other wallet functions will
  * also return one of these values. */
typedef enum WalletErrorsEnum
{
	/** No error actually occurred. */
	WALLET_NO_ERROR				=	0,
	/** Insufficient space on non-volatile storage device. */
	WALLET_FULL					=	1,
	/** No addresses in wallet. */
	WALLET_EMPTY				=	2,
	/** Problem(s) reading from non-volatile storage device. */
	WALLET_READ_ERROR			=	3,
	/** Problem(s) writing to non-volatile storage device. */
	WALLET_WRITE_ERROR			=	4,
	/** There is no wallet at the specified location (or, wrong encryption key
	  * used). */
	WALLET_NOT_THERE			=	6,
	/** The operation requires a wallet to be loaded, but no wallet is
	  * loaded. */
	WALLET_NOT_LOADED			=	7,
	/** Invalid address handle. */
	WALLET_INVALID_HANDLE		=	8,
	/** Backup seed could not be written to specified device. */
	WALLET_BACKUP_ERROR			=	9,
	/** Problem with random number generation system. */
	WALLET_RNG_FAILURE			=	10,
	/** Invalid wallet number specified. */
	WALLET_INVALID_WALLET_NUM	=	11,
	/** The specified operation is not allowed on this type of wallet. */
	WALLET_INVALID_OPERATION	=	12,
	/** A wallet already exists at the specified location. */
	WALLET_ALREADY_EXISTS		=	13,
	/** Bad non-volatile storage address or partition number. */
	WALLET_BAD_ADDRESS			=	14
} WalletErrors;

extern WalletErrors walletGetLastError(void);
extern WalletErrors initWallet(uint32_t wallet_spec, const uint8_t *password, const unsigned int password_length);
extern WalletErrors uninitWallet(void);
extern WalletErrors sanitiseEverything(void);
extern WalletErrors deleteWallet(uint32_t wallet_spec);
extern WalletErrors newWallet(uint32_t wallet_spec, uint8_t *name, bool use_seed, uint8_t *seed, bool make_hidden, const uint8_t *password, const unsigned int password_length);
extern AddressHandle makeNewAddress(uint8_t *out_address, PointAffine *out_public_key);
extern WalletErrors getAddressAndPublicKey(uint8_t *out_address, PointAffine *out_public_key, AddressHandle ah);
extern WalletErrors getMasterPublicKey(PointAffine *out_public_key, uint8_t *out_chain_code);
extern uint32_t getNumAddresses(void);
extern WalletErrors getPrivateKey(uint8_t *out, AddressHandle ah);
extern WalletErrors changeEncryptionKey(const uint8_t *password, const unsigned int password_length);
extern WalletErrors changeWalletName(uint8_t *new_name);
extern WalletErrors getWalletInfo(uint32_t *out_version, uint8_t *out_name, uint8_t *out_uuid, uint32_t wallet_spec);
extern WalletErrors backupWallet(bool do_encrypt, uint32_t destination_device);
extern uint32_t getNumberOfWallets(void);

#ifdef TEST
extern void initWalletTest(void);
#endif // #ifdef TEST

#endif // #ifndef WALLET_H_INCLUDED

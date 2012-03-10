// ***********************************************************************
// transaction.h
// ***********************************************************************
//
// This describes functions and types exported by transaction.c
//
// This file is licensed as described by the file LICENCE.

#ifndef TRANSACTION_H_INCLUDED
#define TRANSACTION_H_INCLUDED

#include "common.h"
#include "bignum256.h"

typedef enum tx_errors_type
{
	// No error actually occurred.
	TX_NO_ERROR					=	0,
	// Format of transaction is unknown or invalid.
	TX_INVALID_FORMAT			=	1,
	// Too many inputs in transaction.
	TX_TOO_MANY_INPUTS			=	2,
	// Too many outputs in transaction.
	TX_TOO_MANY_OUTPUTS			=	3,
	// Transaction's size (in bytes) is too large.
	TX_TOO_LARGE				=	4,
	// Transaction not recognised (i.e. non-standard).
	TX_NONSTANDARD				=	5,
	// Read error occurred when trying to read from input stream.
	TX_READ_ERROR				=	6
} tx_errors;

extern u16 get_transaction_num_inputs(void);
extern tx_errors parse_transaction(bignum256 sighash, bignum256 txhash, u32 length);
extern u8 sign_transaction(u8 *signature, bignum256 sighash, bignum256 privatekey);

#endif // #ifndef TRANSACTION_H_INCLUDED

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

typedef enum TransactionErrorsEnum
{
	// No error actually occurred.
	TRANSACTION_NO_ERROR				=	0,
	// Format of transaction is unknown or invalid.
	TRANSACTION_INVALID_FORMAT			=	1,
	// Too many inputs in transaction.
	TRANSACTION_TOO_MANY_INPUTS			=	2,
	// Too many outputs in transaction.
	TRANSACTION_TOO_MANY_OUTPUTS		=	3,
	// Transaction's size (in bytes) is too large.
	TRANSACTION_TOO_LARGE				=	4,
	// Transaction not recognised (i.e. non-standard).
	TRANSACTION_NON_STANDARD			=	5,
	// Read error occurred when trying to read from input stream.
	TRANSACTION_READ_ERROR				=	6
} TransactionErrors;

extern u16 getTransactionNumInputs(void);
extern TransactionErrors parseTransaction(BigNum256 sig_hash, BigNum256 transaction_hash, u32 length);
extern u8 signTransaction(u8 *signature, BigNum256 sig_hash, BigNum256 private_key);

#endif // #ifndef TRANSACTION_H_INCLUDED

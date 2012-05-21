/** \file transaction.h
  *
  * \brief Describes functions and types exported by transaction.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef TRANSACTION_H_INCLUDED
#define TRANSACTION_H_INCLUDED

#include "common.h"
#include "bignum256.h"

/** Maximum size (in number of bytes) of the DER format ECDSA signature which
  * signTransaction() generates. */
#define MAX_SIGNATURE_LENGTH		73

/** Return values for parseTransaction(). */
typedef enum TransactionErrorsEnum
{
	/** No error actually occurred. */
	TRANSACTION_NO_ERROR				=	0,
	/** Format of transaction is unknown or invalid. */
	TRANSACTION_INVALID_FORMAT			=	1,
	/** Too many inputs in transaction. */
	TRANSACTION_TOO_MANY_INPUTS			=	2,
	/** Too many outputs in transaction. */
	TRANSACTION_TOO_MANY_OUTPUTS		=	3,
	/** Transaction's size (in bytes) is too large. */
	TRANSACTION_TOO_LARGE				=	4,
	/** Transaction not recognised (i.e. non-standard). */
	TRANSACTION_NON_STANDARD			=	5,
	/** Read error occurred when trying to read from input stream. */
	TRANSACTION_READ_ERROR				=	6
} TransactionErrors;

extern uint16_t getTransactionNumInputs(void);
extern TransactionErrors parseTransaction(BigNum256 sig_hash, BigNum256 transaction_hash, uint32_t length);
extern uint8_t signTransaction(uint8_t *signature, uint8_t *out_length, BigNum256 sig_hash, BigNum256 private_key);
extern void swapEndian256(BigNum256 buffer);

#endif // #ifndef TRANSACTION_H_INCLUDED

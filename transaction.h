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
	/** Output amount too high in transaction. This can also be returned if
	  * the calculated transaction fee is negative. */
	TRANSACTION_INVALID_AMOUNT			=	7,
	/** Reference to an inner transaction is invalid. */
	TRANSACTION_INVALID_REFERENCE		=	8
} TransactionErrors;

extern TransactionErrors parseTransaction(BigNum256 sig_hash, BigNum256 transaction_hash, uint32_t length);
extern void signTransaction(uint8_t *signature, uint8_t *out_length, BigNum256 sig_hash, BigNum256 private_key);

#endif // #ifndef TRANSACTION_H_INCLUDED

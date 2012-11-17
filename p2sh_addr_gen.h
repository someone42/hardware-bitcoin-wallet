/** \file p2sh_addr_gen.h
  *
  * \brief Describes functions and types exported by p2sh_addr_gen.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef P2SH_ADDR_GEN_H_INCLUDED
#define P2SH_ADDR_GEN_H_INCLUDED

#include "common.h"
#include "ecdsa.h"

/** Return values for generateMultiSigAddress(). */
typedef enum P2SHGeneratorErrorsEnum
{
	/** No error actually occurred. */
	P2SHGEN_NO_ERROR			=	0,
	/** Format of public key list is unknown or invalid. */
	P2SHGEN_INVALID_FORMAT		=	1,
	/** Invalid number of public keys, number of required signatures or
	  * supplied public key number. */
	P2SHGEN_BAD_NUMBER			=	2,
	/** Unknown or invalid public key format. */
	P2SHGEN_UNKNOWN_PUBLIC_KEY	=	3
} P2SHGeneratorErrors;

extern P2SHGeneratorErrors generateMultiSigAddress(uint8_t num_sigs, uint8_t num_pubkeys, uint8_t wallet_pubkey_num, PointAffine *public_key, uint32_t length);

#endif // #ifndef P2SH_ADDR_GEN_H_INCLUDED

/** \file hmac_drbg.h
  *
  * \brief Describes functions and types aexported and used by hmac_drbg.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef HMAC_DRBG_H_INCLUDED
#define HMAC_DRBG_H_INCLUDED

#include "common.h"
#include "sha256.h"

/** Internal state of a HMAC_DRBG instance. The internal state can be
  * instantiated via. drbgInstantiate(), updated via. drbgReseed() and
  * used for bit generation via. drbgGenerate(). */
typedef struct HMACDRBGStateStruct
{
	/** This is sometimes called "K" in NIST SP 800-90A. It is usually used as
	  * the key in HMAC invocations. */
	uint8_t key[SHA256_HASH_LENGTH];
	/** This is sometimes called "V" in NIST SP 800-90A This is usually used as
	  * the message/value in HMAC invocations. */
	uint8_t v[SHA256_HASH_LENGTH];
} HMACDRBGState;

extern void drbgInstantiate(HMACDRBGState *state, const uint8_t *seed_material, const unsigned int seed_material_length);
extern void drbgReseed(HMACDRBGState *state, const uint8_t *reseed_material, const unsigned int reseed_material_length);
extern void drbgGenerate(uint8_t *out, HMACDRBGState *state, const unsigned int requested_bytes, const uint8_t *additional_input, const unsigned int additional_input_length);

#endif // #ifndef HMAC_DRBG_H_INCLUDED

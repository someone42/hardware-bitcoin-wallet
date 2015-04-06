/** \file baseconv.h
  *
  * \brief This describes functions and constants exported by baseconv.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef BASECONV_H_INCLUDED
#define BASECONV_H_INCLUDED

#include "common.h"

/** Address version to use when converting 160 bit hashes to human-readable
  * non-P2SH ("pubkey hash") Bitcoin addresses. This should be 0x00 for the
  * main network or 0x6f for testnet. */
#ifndef TESTNET
#define ADDRESS_VERSION_PUBKEY		0x00
#else // #ifndef TESTNET
#define ADDRESS_VERSION_PUBKEY		0x6f
#endif // #ifndef TESTNET
/** Address version to use when converting 160 bit hashes to human-readable
  * P2SH ("script hash") Bitcoin addresses. This should be 0x05 for the main
  * network or 0xc4 for testnet. */
#ifndef TESTNET
#define ADDRESS_VERSION_P2SH		0x05
#else // #ifndef TESTNET
#define ADDRESS_VERSION_P2SH		0xc4
#endif // #ifndef TESTNET

/** Required size of a buffer which stores the text of a transaction output
  * amount. This includes the terminating null. */
#define TEXT_AMOUNT_LENGTH	22
/** Required size of a buffer which stores the text of a transaction output
  * address. This includes the terminating null. */
#define TEXT_ADDRESS_LENGTH	36

extern void amountToText(char *out, uint8_t *in);
extern void hashToAddr(char *out, uint8_t *in, uint8_t address_version);

#endif // #ifndef BASECONV_H_INCLUDED


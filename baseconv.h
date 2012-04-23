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
  * Bitcoin addresses. This should be 0x00 for the main network or 0x6f for
  * testnet. */
#define ADDRESSVERSION		0x00

/** Required size of a buffer which stores the text of a transaction output
  * amount. This includes the terminating null. */
#define TEXT_AMOUNT_LENGTH	22
/** Required size of a buffer which stores the text of a transaction output
  * address. This includes the terminating null. */
#define TEXT_ADDRESS_LENGTH	36

extern void amountToText(char *out, uint8_t *in);
extern void hashToAddr(char *out, uint8_t *in);

#endif // #ifndef BASECONV_H_INCLUDED


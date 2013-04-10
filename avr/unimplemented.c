/** \file unimplemented.c
  *
  * \brief Provides do-nothing stubs for unimplemented functions.
  *
  * One day this file won't exist.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "../common.h"
#include "../hwinterface.h"

/** Inform the user that an address has been generated.
  * \param address The output address, as a null-terminated text string
  *                such as "1RaTTuSEN7jJUDiW1EGogHwtek7g9BiEn".
  * \param num_sigs The number of required signatures to redeem Bitcoins from
  *                 the address. For a non-multi-signature address, this
  *                 should be 1.
  * \param num_pubkeys The number of public keys involved in the address. For
  *                    a non-multi-signature address, this should be 1.
  */
void displayAddress(char *address, uint8_t num_sigs, uint8_t num_pubkeys)
{
}

/** \file unimplemented.c
  *
  * \brief Provides do-nothing stubs for unimplemented functions.
  *
  * One day this file won't exist.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
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

/** Fill buffer with 32 random bytes from a hardware random number generator.
  * \param buffer The buffer to fill. This should have enough space for 32
  *               bytes.
  * \return An estimate of the total number of bits (not bytes) of entropy in
  *         the buffer on success, or a negative number if the hardware random
  *         number generator failed in any way. This may also return 0 to tell
  *         the caller that more samples are needed in order to do any
  *         meaningful statistical testing. If this returns 0, the caller
  *         should continue to call this until it returns a non-zero value.
  */
int hardwareRandom32Bytes(uint8_t *buffer)
{
	return -1;
}

/** Overwrite anything in RAM which could contain sensitive data. "Sensitive
  * data" includes secret things like encryption keys and wallet private keys.
  * It also includes derived things like expanded keys and intermediate
  * results from elliptic curve calculations. Even past transaction data,
  * addresses and intermediate results from hash calculations could be
  * considered sensitive and should be overwritten.
  */
void sanitiseRam(void)
{
}

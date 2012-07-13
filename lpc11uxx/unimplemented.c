/** \file unimplemented.c
  *
  * \brief Provides non-functional stubs for unimplemented functions.
  *
  * Delete these as stuff is implemented.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "../common.h"
#include "../hwinterface.h"

/** Fill buffer with random bytes from a hardware random number generator.
  * \param buffer The buffer to fill. This should have enough space for n
  *               bytes.
  * \param n The size of the buffer.
  * \return An estimate of the total number of bits (not bytes) of entropy in
  *         the buffer.
  */
uint16_t hardwareRandomBytes(uint8_t *buffer, uint8_t n)
{
	return 8;
}

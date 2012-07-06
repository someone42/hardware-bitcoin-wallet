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

/** Notify the user interface that the transaction parser has seen a new
  * Bitcoin amount/address pair.
  * \param text_amount The output amount, as a null-terminated text string
  *                    such as "0.01".
  * \param text_address The output address, as a null-terminated text string
  *                     such as "1RaTTuSEN7jJUDiW1EGogHwtek7g9BiEn".
  * \return 0 if no error occurred, non-zero if there was not enough space to
  *         store the amount/address pair.
  */
uint8_t newOutputSeen(char *text_amount, char *text_address)
{
	return 0;
}

/** Notify the user interface that the transaction parser has seen the
  * transaction fee. If there is no transaction fee, the transaction parser
  * will not call this.
  * \param text_amount The transaction fee, as a null-terminated text string
  *                    such as "0.01".
  */
void setTransactionFee(char *text_amount)
{
}

/** Notify the user interface that the list of Bitcoin amount/address pairs
  * should be cleared. */
void clearOutputsSeen(void)
{
}

/** Ask user if they want to allow some action.
  * \param command The action to ask the user about. See #AskUserCommandEnum.
  * \return 0 if the user accepted, non-zero if the user denied.
  */
uint8_t askUser(AskUserCommand command)
{
	return 0;
}

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

/** Write backup seed to some output device. The choice of output device and
  * seed representation is up to the platform-dependent code. But a typical
  * example would be displaying the seed as a hexadecimal string on a LCD.
  * \param seed A byte array of length #SEED_LENGTH bytes which contains the
  *             backup seed.
  * \param is_encrypted Specifies whether the seed has been encrypted
  *                     (non-zero) or not (zero).
  * \param destination_device Specifies which (platform-dependent) device the
  *                           backup seed should be sent to.
  * \return 0 on success, or non-zero if the backup seed could not be written
  *         to the destination device.
  */
uint8_t writeBackupSeed(uint8_t *seed, uint8_t is_encrypted, uint8_t destination_device)
{
	return 0;
}

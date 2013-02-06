/** \file eeprom.c
  *
  * \brief Reads and writes to the LPC11Uxx's EEPROM.
  *
  * This contains functions which implement non-volatile storage using the
  * LPC11Uxx's EEPROM. The in application programming (IAP) interface is
  * used to access the EEPROM.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "../common.h"
#include "../hwinterface.h"

/** In application programming entry point. The 0th bit is set to force
  * the instruction mode to Thumb mode. */
#define IAP_LOCATION 0x1fff1ff1;

/** The type of the in application programming entry function. */
typedef void (*IAPFunctionType)(uint32_t *, uint32_t *);

/** The in application programming entry point. */
IAPFunctionType iapEntry = (IAPFunctionType)IAP_LOCATION;

/** Storage for in application programming command buffer. */
static uint32_t iap_command[5];
/** Storage for in application programming result buffer. */
static uint32_t iap_result[5];

/** Size of EEPROM, in number of bytes. This isn't 4096 because, according to
  * the LPC11Uxx user manual, the last 64 bytes must not be written to.
  * \warning This is set for LPC11Uxx microcontrollers with 4K of
  *          EEPROM. This will need to be adjusted if that's not the case.
  */
#define EEPROM_SIZE		4032

/** Write to non-volatile storage.
  * \param data A pointer to the data to be written.
  * \param address Byte offset specifying where in non-volatile storage to
  *                start writing to.
  * \param length The number of bytes to write.
  * \return See #NonVolatileReturnEnum for return values.
  * \warning Writes may be buffered; use nonVolatileFlush() to be sure that
  *          data is actually written to non-volatile storage.
  */
NonVolatileReturn nonVolatileWrite(uint8_t *data, uint32_t address, uint8_t length)
{
	// Since EEPROM_SIZE is much smaller than 2 ^ 32, address + length cannot
	// overflow.
	if ((address > EEPROM_SIZE)
		|| ((address + length) > EEPROM_SIZE))
	{
		return NV_INVALID_ADDRESS;
	}
	iap_command[0] = 61; // IAP command code for "Write EEPROM"
	iap_command[1] = address; // EEPROM address
	iap_command[2] = (uint32_t)data; // RAM address
	iap_command[3] = length; // number of bytes to be written
	iap_command[4] = 48000; // system clock frequency in kHz
	iapEntry(iap_command, iap_result);
	if (iap_result[0] == 0)
	{
		return NV_NO_ERROR;
	}
	else
	{
		return NV_IO_ERROR;
	}
}

/** Read from non-volatile storage.
  * \param data A pointer to the buffer which will receive the data.
  * \param address Byte offset specifying where in non-volatile storage to
  *                start reading from.
  * \param length The number of bytes to read.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn nonVolatileRead(uint8_t *data, uint32_t address, uint8_t length)
{
	// Since EEPROM_SIZE is much smaller than 2 ^ 32, address + length cannot
	// overflow.
	if ((address > EEPROM_SIZE)
		|| ((address + length) > EEPROM_SIZE))
	{
		return NV_INVALID_ADDRESS;
	}
	iap_command[0] = 62; // IAP command code for "Read EEPROM"
	iap_command[1] = address; // EEPROM address
	iap_command[2] = (uint32_t)data; // RAM address
	iap_command[3] = length; // number of bytes to be read
	iap_command[4] = 48000; // system clock frequency in kHz
	iapEntry(iap_command, iap_result);
	if (iap_result[0] == 0)
	{
		return NV_NO_ERROR;
	}
	else
	{
		return NV_IO_ERROR;
	}
}

/** Ensure that all buffered writes are committed to non-volatile storage.
  * \return See #NonVolatileReturnEnum for return values.
  */
NonVolatileReturn nonVolatileFlush(void)
{
	// Nothing to do; writes are never buffered.
	return NV_NO_ERROR;
}

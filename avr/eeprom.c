// ***********************************************************************
// eeprom.c
// ***********************************************************************
//
// Containes functions which implement non-volatile storage using the AVR's
// EEPROM. It's not much (only 1024 bytes on the ATmega328), but it's enough
// to test with.
//
// This file is licensed as described by the file LICENCE.

#include <avr/eeprom.h>

#include "../common.h"
#include "../hwinterface.h"

// Size of EEPROM.
#define EEPROM_SIZE		1024

// Write to non-volatile storage. address is a byte offset specifying where
// in non-volatile storage to start writing to. data is a pointer to the
// data to be written and length is the number of bytes to write. See
// nonvolatile_return for return values.
nonvolatile_return nonvolatile_write(u32 address, u8 *data, u8 length)
{
	if ((address > EEPROM_SIZE)
		|| ((address + (u32)length) > EEPROM_SIZE))
	{
		return NV_INVALID_ADDRESS;
	}
	eeprom_busy_wait();
	// The (void *)(int) is there because pointers on AVR are 16-bit, so
	// just doing (void *) would result in a "cast to pointer from integer
	// of different size" warning.
	eeprom_write_block(data, (void *)(int)address, length);
	return NV_NO_ERROR;
}

// Read from non-volatile storage. address is a byte offset specifying where
// in non-volatile storage to start reading from. data is a pointer to the
// buffer which will receive the data and length is the number of bytes to
// read. See nonvolatile_return for return values.
nonvolatile_return nonvolatile_read(u32 address, u8 *data, u8 length)
{
	if ((address > EEPROM_SIZE)
		|| ((address + (u32)length) > EEPROM_SIZE))
	{
		return NV_INVALID_ADDRESS;
	}
	eeprom_busy_wait();
	// The (void *)(int) is there because pointers on AVR are 16-bit, so
	// just doing (void *) would result in a "cast to pointer from integer
	// of different size" warning.
	eeprom_read_block(data, (void *)(int)address, length);
	return NV_NO_ERROR;
}

// Ensure that all buffered writes are committed to non-volatile storage.
void nonvolatile_flush(void)
{
	// Nothing to do.
}


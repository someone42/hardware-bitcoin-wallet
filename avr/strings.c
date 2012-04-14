// ***********************************************************************
// strings.c
// ***********************************************************************
//
// Containes functions which retrieve device-specific strings. It's
// important that these strings are stored in program memory (flash),
// otherwise they eat up valuable RAM.
//
// This file is licensed as described by the file LICENCE.

#include <avr/io.h>
#include <avr/pgmspace.h>

#include "../common.h"
#include "../hwinterface.h"

static const char str_MISCSTR_VERSION[] PROGMEM = "Hardware Bitcoin Wallet for AVR v0.2";
static const char str_MISCSTR_PERMISSION_DENIED[] PROGMEM = "Permission denied by user";
static const char str_MISCSTR_INVALID_PACKET[] PROGMEM = "Unrecognised command";
static const char str_WALLET_FULL[] PROGMEM = "Wallet has run out of space";
static const char str_WALLET_EMPTY[] PROGMEM = "Wallet has nothing in it";
static const char str_WALLET_READ_ERROR[] PROGMEM = "EEPROM Read error";
static const char str_WALLET_WRITE_ERROR[] PROGMEM = "EEPROM Write error";
static const char str_WALLET_ADDRESS_NOT_FOUND[] PROGMEM = "Address not in wallet";
static const char str_WALLET_NOT_THERE[] PROGMEM = "Wallet doesn't exist";
static const char str_WALLET_END_OF_LIST[] PROGMEM = "End of address list";
static const char str_WALLET_INVALID_HANDLE[] PROGMEM = "Invalid address handle";
static const char str_TRANSACTION_INVALID_FORMAT[] PROGMEM = "Format of transaction is unknown or invalid";
static const char str_TRANSACTION_TOO_MANY_INPUTS[] PROGMEM = "Too many inputs in transaction";
static const char str_TRANSACTION_TOO_MANY_OUTPUTS[] PROGMEM = "Too many outputs in transaction";
static const char str_TRANSACTION_TOO_LARGE[] PROGMEM = "Transaction's size is too large";
static const char str_TRANSACTION_NON_STANDARD[] PROGMEM = "Transaction is non-standard";
static const char str_TRANSACTION_READ_ERROR[] PROGMEM = "Stream read error";
static const char str_UNKNOWN[] PROGMEM = "Unknown error";


// Obtain one character from one of the device's strings. pos = 0 specifies
// the first character, pos = 1 the second etc. spec specifies which string
// to get the character from. set specifies which set of strings to use.
// The interpretation of spec depends on set; see the comments near StringSet
// for clarification.
char getString(StringSet set, uint8_t spec, uint16_t pos)
{
	if (set == STRINGSET_MISC)
	{
		switch (spec)
		{
		case MISCSTR_VERSION:
			return (char)pgm_read_byte(&(str_MISCSTR_VERSION[pos]));
			break;
		case MISCSTR_PERMISSION_DENIED:
			return (char)pgm_read_byte(&(str_MISCSTR_PERMISSION_DENIED[pos]));
			break;
		case MISCSTR_INVALID_PACKET:
			return (char)pgm_read_byte(&(str_MISCSTR_INVALID_PACKET[pos]));
			break;
		default:
			return (char)pgm_read_byte(&(str_UNKNOWN[pos]));
			break;
		}
	}
	else if (set == STRINGSET_WALLET)
	{
		switch (spec)
		{
		case WALLET_FULL:
			return (char)pgm_read_byte(&(str_WALLET_FULL[pos]));
			break;
		case WALLET_EMPTY:
			return (char)pgm_read_byte(&(str_WALLET_EMPTY[pos]));
			break;
		case WALLET_READ_ERROR:
			return (char)pgm_read_byte(&(str_WALLET_READ_ERROR[pos]));
			break;
		case WALLET_WRITE_ERROR:
			return (char)pgm_read_byte(&(str_WALLET_WRITE_ERROR[pos]));
			break;
		case WALLET_ADDRESS_NOT_FOUND:
			return (char)pgm_read_byte(&(str_WALLET_ADDRESS_NOT_FOUND[pos]));
			break;
		case WALLET_NOT_THERE:
			return (char)pgm_read_byte(&(str_WALLET_NOT_THERE[pos]));
			break;
		case WALLET_END_OF_LIST:
			return (char)pgm_read_byte(&(str_WALLET_END_OF_LIST[pos]));
			break;
		case WALLET_INVALID_HANDLE:
			return (char)pgm_read_byte(&(str_WALLET_INVALID_HANDLE[pos]));
			break;
		default:
			return (char)pgm_read_byte(&(str_UNKNOWN[pos]));
			break;
		}
	}
	else if (set == STRINGSET_TRANSACTION)
	{
		switch (spec)
		{
		case TRANSACTION_INVALID_FORMAT:
			return (char)pgm_read_byte(&(str_TRANSACTION_INVALID_FORMAT[pos]));
			break;
		case TRANSACTION_TOO_MANY_INPUTS:
			return (char)pgm_read_byte(&(str_TRANSACTION_TOO_MANY_INPUTS[pos]));
			break;
		case TRANSACTION_TOO_MANY_OUTPUTS:
			return (char)pgm_read_byte(&(str_TRANSACTION_TOO_MANY_OUTPUTS[pos]));
			break;
		case TRANSACTION_TOO_LARGE:
			return (char)pgm_read_byte(&(str_TRANSACTION_TOO_LARGE[pos]));
			break;
		case TRANSACTION_NON_STANDARD:
			return (char)pgm_read_byte(&(str_TRANSACTION_NON_STANDARD[pos]));
			break;
		case TRANSACTION_READ_ERROR:
			return (char)pgm_read_byte(&(str_TRANSACTION_READ_ERROR[pos]));
			break;
		default:
			return (char)pgm_read_byte(&(str_UNKNOWN[pos]));
			break;
		}
	}
	else
	{
		return (char)pgm_read_byte(&(str_UNKNOWN[pos]));
	}
}

// Get the length of one of the device's strings. See getString() for what
// set and spec refer to.
uint16_t getStringLength(StringSet set, uint8_t spec)
{
	if (set == STRINGSET_MISC)
	{
		switch (spec)
		{
		case MISCSTR_VERSION:
			return (uint16_t)(sizeof(str_MISCSTR_VERSION) - 1);
			break;
		case MISCSTR_PERMISSION_DENIED:
			return (uint16_t)(sizeof(str_MISCSTR_PERMISSION_DENIED) - 1);
			break;
		case MISCSTR_INVALID_PACKET:
			return (uint16_t)(sizeof(str_MISCSTR_INVALID_PACKET) - 1);
			break;
		default:
			return (uint16_t)(sizeof(str_UNKNOWN) - 1);
			break;
		}
	}
	else if (set == STRINGSET_WALLET)
	{
		switch (spec)
		{
		case WALLET_FULL:
			return (uint16_t)(sizeof(str_WALLET_FULL) - 1);
			break;
		case WALLET_EMPTY:
			return (uint16_t)(sizeof(str_WALLET_EMPTY) - 1);
			break;
		case WALLET_READ_ERROR:
			return (uint16_t)(sizeof(str_WALLET_READ_ERROR) - 1);
			break;
		case WALLET_WRITE_ERROR:
			return (uint16_t)(sizeof(str_WALLET_WRITE_ERROR) - 1);
			break;
		case WALLET_ADDRESS_NOT_FOUND:
			return (uint16_t)(sizeof(str_WALLET_ADDRESS_NOT_FOUND) - 1);
			break;
		case WALLET_NOT_THERE:
			return (uint16_t)(sizeof(str_WALLET_NOT_THERE) - 1);
			break;
		case WALLET_END_OF_LIST:
			return (uint16_t)(sizeof(str_WALLET_END_OF_LIST) - 1);
			break;
		case WALLET_INVALID_HANDLE:
			return (uint16_t)(sizeof(str_WALLET_INVALID_HANDLE) - 1);
			break;
		default:
			return (uint16_t)(sizeof(str_UNKNOWN) - 1);
			break;
		}
	}
	else if (set == STRINGSET_TRANSACTION)
	{
		switch (spec)
		{
		case TRANSACTION_INVALID_FORMAT:
			return (uint16_t)(sizeof(str_TRANSACTION_INVALID_FORMAT) - 1);
			break;
		case TRANSACTION_TOO_MANY_INPUTS:
			return (uint16_t)(sizeof(str_TRANSACTION_TOO_MANY_INPUTS) - 1);
			break;
		case TRANSACTION_TOO_MANY_OUTPUTS:
			return (uint16_t)(sizeof(str_TRANSACTION_TOO_MANY_OUTPUTS) - 1);
			break;
		case TRANSACTION_TOO_LARGE:
			return (uint16_t)(sizeof(str_TRANSACTION_TOO_LARGE) - 1);
			break;
		case TRANSACTION_NON_STANDARD:
			return (uint16_t)(sizeof(str_TRANSACTION_NON_STANDARD) - 1);
			break;
		case TRANSACTION_READ_ERROR:
			return (uint16_t)(sizeof(str_TRANSACTION_READ_ERROR) - 1);
			break;
		default:
			return (uint16_t)(sizeof(str_UNKNOWN) - 1);
			break;
		}
	}
	else
	{
		return (uint16_t)(sizeof(str_UNKNOWN) - 1);
	}
}


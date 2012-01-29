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

static const char str_MISCSTR_VERSION[] PROGMEM = "Hardware Bitcoin Wallet for AVR v0.1";
static const char str_MISCSTR_PERMISSION_DENIED[] PROGMEM = "Permission denied by user";
static const char str_MISCSTR_INVALID_PACKET[] PROGMEM = "Unrecognised command";
static const char str_WALLET_FULL[] PROGMEM = "Wallet has run out of space";
static const char str_WALLET_EMPTY[] PROGMEM = "Wallet has nothing in it";
static const char str_WALLET_READ_ERROR[] PROGMEM = "Read error";
static const char str_WALLET_WRITE_ERROR[] PROGMEM = "Write error";
static const char str_WALLET_ADDRESS_NOT_FOUND[] PROGMEM = "Address not in wallet";
static const char str_WALLET_NOT_THERE[] PROGMEM = "Wallet doesn't exist";
static const char str_WALLET_END_OF_LIST[] PROGMEM = "End of address list";
static const char str_WALLET_INVALID_HANDLE[] PROGMEM = "Invalid address handle";
static const char str_TX_INVALID_FORMAT[] PROGMEM = "Format of transaction is unknown or invalid";
static const char str_TX_TOO_MANY_INPUTS[] PROGMEM = "Too many inputs in transaction";
static const char str_TX_TOO_MANY_OUTPUTS[] PROGMEM = "Too many outputs in transaction";
static const char str_TX_TOO_LARGE[] PROGMEM = "Transaction's size is too large";
static const char str_TX_NONSTANDARD[] PROGMEM = "Transaction is non-standard";
static const char str_UNKNOWN[] PROGMEM = "Unknown error";


// Obtain one character from one of the device's strings. pos = 0 specifies
// the first character, pos = 1 the second etc. spec specifies which string
// to get the character from. set specifies which set of strings to use.
// The interpretation of spec depends on set; see the comments near string_set
// for clarification.
char get_string(string_set set, u8 spec, u16 pos)
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
		case TX_INVALID_FORMAT:
			return (char)pgm_read_byte(&(str_TX_INVALID_FORMAT[pos]));
			break;
		case TX_TOO_MANY_INPUTS:
			return (char)pgm_read_byte(&(str_TX_TOO_MANY_INPUTS[pos]));
			break;
		case TX_TOO_MANY_OUTPUTS:
			return (char)pgm_read_byte(&(str_TX_TOO_MANY_OUTPUTS[pos]));
			break;
		case TX_TOO_LARGE:
			return (char)pgm_read_byte(&(str_TX_TOO_LARGE[pos]));
			break;
		case TX_NONSTANDARD:
			return (char)pgm_read_byte(&(str_TX_NONSTANDARD[pos]));
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

// Get the length of one of the device's strings. See get_string() for what
// set and spec refer to.
u16 get_string_length(string_set set, u8 spec)
{
	if (set == STRINGSET_MISC)
	{
		switch (spec)
		{
		case MISCSTR_VERSION:
			return (u16)(sizeof(str_MISCSTR_VERSION) - 1);
			break;
		case MISCSTR_PERMISSION_DENIED:
			return (u16)(sizeof(str_MISCSTR_PERMISSION_DENIED) - 1);
			break;
		case MISCSTR_INVALID_PACKET:
			return (u16)(sizeof(str_MISCSTR_INVALID_PACKET) - 1);
			break;
		default:
			return (u16)(sizeof(str_UNKNOWN) - 1);
			break;
		}
	}
	else if (set == STRINGSET_WALLET)
	{
		switch (spec)
		{
		case WALLET_FULL:
			return (u16)(sizeof(str_WALLET_FULL) - 1);
			break;
		case WALLET_EMPTY:
			return (u16)(sizeof(str_WALLET_EMPTY) - 1);
			break;
		case WALLET_READ_ERROR:
			return (u16)(sizeof(str_WALLET_READ_ERROR) - 1);
			break;
		case WALLET_WRITE_ERROR:
			return (u16)(sizeof(str_WALLET_WRITE_ERROR) - 1);
			break;
		case WALLET_ADDRESS_NOT_FOUND:
			return (u16)(sizeof(str_WALLET_ADDRESS_NOT_FOUND) - 1);
			break;
		case WALLET_NOT_THERE:
			return (u16)(sizeof(str_WALLET_NOT_THERE) - 1);
			break;
		case WALLET_END_OF_LIST:
			return (u16)(sizeof(str_WALLET_END_OF_LIST) - 1);
			break;
		case WALLET_INVALID_HANDLE:
			return (u16)(sizeof(str_WALLET_INVALID_HANDLE) - 1);
			break;
		default:
			return (u16)(sizeof(str_UNKNOWN) - 1);
			break;
		}
	}
	else if (set == STRINGSET_TRANSACTION)
	{
		switch (spec)
		{
		case TX_INVALID_FORMAT:
			return (u16)(sizeof(str_TX_INVALID_FORMAT) - 1);
			break;
		case TX_TOO_MANY_INPUTS:
			return (u16)(sizeof(str_TX_TOO_MANY_INPUTS) - 1);
			break;
		case TX_TOO_MANY_OUTPUTS:
			return (u16)(sizeof(str_TX_TOO_MANY_OUTPUTS) - 1);
			break;
		case TX_TOO_LARGE:
			return (u16)(sizeof(str_TX_TOO_LARGE) - 1);
			break;
		case TX_NONSTANDARD:
			return (u16)(sizeof(str_TX_NONSTANDARD) - 1);
			break;
		default:
			return (u16)(sizeof(str_UNKNOWN) - 1);
			break;
		}
	}
	else
	{
		return (u16)(sizeof(str_UNKNOWN) - 1);
	}
}


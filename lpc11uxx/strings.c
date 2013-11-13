/** \file strings.c
  *
  * \brief Defines and retrieves device-specific strings.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "../common.h"
#include "../hwinterface.h"

/**
 * \defgroup DeviceStrings Device-specific strings.
 *
 * @{
 */
/** Version string. */
static const char str_MISCSTR_VERSION[] = "Hardware Bitcoin Wallet for LPC11Uxx v0.4";
/** Permission denied (user pressed cancel button) string. */
static const char str_MISCSTR_PERMISSION_DENIED_USER[] = "Permission denied by user";
/** String specifying that processPacket() didn't like the format or
  * contents of a packet. */
static const char str_MISCSTR_INVALID_PACKET[] = "Invalid packet";
/** String specifying that a parameter was unacceptably large. */
static const char str_MISCSTR_PARAM_TOO_LARGE[] = "Parameter too large";
/** Permission denied (host cancelled action) string. */
static const char str_MISCSTR_PERMISSION_DENIED_HOST[] = "Host cancelled action";
/** String specifying that an unexpected message was received. */
static const char str_MISCSTR_UNEXPECTED_PACKET[] = "Unexpected packet";
/** String specifying that the submitted one-time password (OTP) did not match
  * the generated OTP. */
static const char str_MISCSTR_OTP_MISMATCH[] = "OTP mismatch";
/** String for #WALLET_FULL wallet error. */
static const char str_WALLET_FULL[] = "Wallet has run out of space";
/** String for #WALLET_EMPTY wallet error. */
static const char str_WALLET_EMPTY[] = "Wallet has nothing in it";
/** String for #WALLET_READ_ERROR wallet error. */
static const char str_WALLET_READ_ERROR[] = "EEPROM Read error";
/** String for #WALLET_WRITE_ERROR error. */
static const char str_WALLET_WRITE_ERROR[] = "EEPROM Write error";
/** String for #WALLET_ADDRESS_NOT_FOUND wallet error. */
static const char str_WALLET_ADDRESS_NOT_FOUND[] = "Address not in wallet";
/** String for #WALLET_NOT_THERE wallet error. */
static const char str_WALLET_NOT_THERE[] = "Wallet doesn't exist";
/** String for #WALLET_NOT_LOADED wallet error. */
static const char str_WALLET_NOT_LOADED[] = "Wallet not loaded";
/** String for #WALLET_INVALID_HANDLE wallet error. */
static const char str_WALLET_INVALID_HANDLE[] = "Invalid address handle";
/** String for #WALLET_BACKUP_ERROR wallet error. */
static const char str_WALLET_BACKUP_ERROR[] = "Seed could not be written to specified device";
/** String for #WALLET_RNG_FAILURE wallet error. */
static const char str_WALLET_RNG_FAILURE[] = "Failure in random number generation system";
/** String for #WALLET_INVALID_WALLET_NUM wallet error. */
static const char str_WALLET_INVALID_WALLET_NUM[] = "Invalid wallet number";
/** String for #WALLET_INVALID_OPERATION wallet error. */
static const char str_WALLET_INVALID_OPERATION[] = "Operation not allowed";
/** String for #TRANSACTION_INVALID_FORMAT transaction parser error. */
static const char str_TRANSACTION_INVALID_FORMAT[] = "Format of transaction is unknown or invalid";
/** String for #TRANSACTION_TOO_MANY_INPUTS transaction parser error. */
static const char str_TRANSACTION_TOO_MANY_INPUTS[] = "Too many inputs in transaction";
/** String for #TRANSACTION_TOO_MANY_OUTPUTS transaction parser error. */
static const char str_TRANSACTION_TOO_MANY_OUTPUTS[] = "Too many outputs in transaction";
/** String for #TRANSACTION_TOO_LARGE transaction parser error. */
static const char str_TRANSACTION_TOO_LARGE[] = "Transaction's size is too large";
/** String for #TRANSACTION_NON_STANDARD transaction parser error. */
static const char str_TRANSACTION_NON_STANDARD[] = "Transaction is non-standard";
/** String for #TRANSACTION_INVALID_AMOUNT transaction parser error. */
static const char str_TRANSACTION_INVALID_AMOUNT[] = "Invalid output amount in transaction";
/** String for #TRANSACTION_INVALID_REFERENCE transaction parser error. */
static const char str_TRANSACTION_INVALID_REFERENCE[] = "Invalid transaction reference";
/** String for unknown error. */
static const char str_UNKNOWN[] = "Unknown error";
/**@}*/

/** Obtain one character from one of the device's strings.
  * \param set Specifies which set of strings to use; should be
  *            one of #StringSetEnum.
  * \param spec Specifies which string to get the character from. The
  *             interpretation of this depends on the value of set;
  *             see #StringSetEnum for clarification.
  * \param pos The position of the character within the string; 0 means first,
  *            1 means second etc.
  * \return The character from the specified string.
  */
char getString(StringSet set, uint8_t spec, uint16_t pos)
{
	const char *str;

	if (pos >= getStringLength(set, spec))
	{
		// Attempting to read beyond end of string.
		return 0;
	}
	if (set == STRINGSET_MISC)
	{
		switch (spec)
		{
		case MISCSTR_VERSION:
			str = str_MISCSTR_VERSION;
			break;
		case MISCSTR_PERMISSION_DENIED_USER:
			str = str_MISCSTR_PERMISSION_DENIED_USER;
			break;
		case MISCSTR_INVALID_PACKET:
			str = str_MISCSTR_INVALID_PACKET;
			break;
		case MISCSTR_PARAM_TOO_LARGE:
			str = str_MISCSTR_PARAM_TOO_LARGE;
			break;
		case MISCSTR_PERMISSION_DENIED_HOST:
			str = str_MISCSTR_PERMISSION_DENIED_HOST;
			break;
		case MISCSTR_UNEXPECTED_PACKET:
			str = str_MISCSTR_UNEXPECTED_PACKET;
			break;
		case MISCSTR_OTP_MISMATCH:
			str = str_MISCSTR_OTP_MISMATCH;
			break;
		default:
			str = str_UNKNOWN;
			break;
		}
	}
	else if (set == STRINGSET_WALLET)
	{
		switch (spec)
		{
		case WALLET_FULL:
			str = str_WALLET_FULL;
			break;
		case WALLET_EMPTY:
			str = str_WALLET_EMPTY;
			break;
		case WALLET_READ_ERROR:
			str = str_WALLET_READ_ERROR;
			break;
		case WALLET_WRITE_ERROR:
			str = str_WALLET_WRITE_ERROR;
			break;
		case WALLET_ADDRESS_NOT_FOUND:
			str = str_WALLET_ADDRESS_NOT_FOUND;
			break;
		case WALLET_NOT_THERE:
			str = str_WALLET_NOT_THERE;
			break;
		case WALLET_NOT_LOADED:
			str = str_WALLET_NOT_LOADED;
			break;
		case WALLET_INVALID_HANDLE:
			str = str_WALLET_INVALID_HANDLE;
			break;
		case WALLET_BACKUP_ERROR:
			str = str_WALLET_BACKUP_ERROR;
			break;
		case WALLET_RNG_FAILURE:
			str = str_WALLET_RNG_FAILURE;
			break;
		case WALLET_INVALID_WALLET_NUM:
			str = str_WALLET_INVALID_WALLET_NUM;
			break;
		case WALLET_INVALID_OPERATION:
			str = str_WALLET_INVALID_OPERATION;
			break;
		default:
			str = str_UNKNOWN;
			break;
		}
	}
	else if (set == STRINGSET_TRANSACTION)
	{
		switch (spec)
		{
		case TRANSACTION_INVALID_FORMAT:
			str = str_TRANSACTION_INVALID_FORMAT;
			break;
		case TRANSACTION_TOO_MANY_INPUTS:
			str = str_TRANSACTION_TOO_MANY_INPUTS;
			break;
		case TRANSACTION_TOO_MANY_OUTPUTS:
			str = str_TRANSACTION_TOO_MANY_OUTPUTS;
			break;
		case TRANSACTION_TOO_LARGE:
			str = str_TRANSACTION_TOO_LARGE;
			break;
		case TRANSACTION_NON_STANDARD:
			str = str_TRANSACTION_NON_STANDARD;
			break;
		case TRANSACTION_INVALID_AMOUNT:
			str = str_TRANSACTION_INVALID_AMOUNT;
			break;
		case TRANSACTION_INVALID_REFERENCE:
			str = str_TRANSACTION_INVALID_REFERENCE;
			break;
		default:
			str = str_UNKNOWN;
			break;
		}
	}
	else
	{
		str = str_UNKNOWN;
	}
	return str[pos];
}

/** Get the length of one of the device's strings.
  * \param set Specifies which set of strings to use; should be
  *            one of #StringSetEnum.
  * \param spec Specifies which string to get the character from. The
  *             interpretation of this depends on the value of set;
  *             see #StringSetEnum for clarification.
  * \return The length of the string, in number of characters.
  */
uint16_t getStringLength(StringSet set, uint8_t spec)
{
	if (set == STRINGSET_MISC)
	{
		switch (spec)
		{
		case MISCSTR_VERSION:
			return (uint16_t)(sizeof(str_MISCSTR_VERSION) - 1);
			break;
		case MISCSTR_PERMISSION_DENIED_USER:
			return (uint16_t)(sizeof(str_MISCSTR_PERMISSION_DENIED_USER) - 1);
			break;
		case MISCSTR_INVALID_PACKET:
			return (uint16_t)(sizeof(str_MISCSTR_INVALID_PACKET) - 1);
			break;
		case MISCSTR_PARAM_TOO_LARGE:
			return (uint16_t)(sizeof(str_MISCSTR_PARAM_TOO_LARGE) - 1);
			break;
		case MISCSTR_PERMISSION_DENIED_HOST:
			return (uint16_t)(sizeof(str_MISCSTR_PERMISSION_DENIED_HOST) - 1);
			break;
		case MISCSTR_UNEXPECTED_PACKET:
			return (uint16_t)(sizeof(str_MISCSTR_UNEXPECTED_PACKET) - 1);
			break;
		case MISCSTR_OTP_MISMATCH:
			return (uint16_t)(sizeof(str_MISCSTR_OTP_MISMATCH) - 1);
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
		case WALLET_NOT_LOADED:
			return (uint16_t)(sizeof(str_WALLET_NOT_LOADED) - 1);
			break;
		case WALLET_INVALID_HANDLE:
			return (uint16_t)(sizeof(str_WALLET_INVALID_HANDLE) - 1);
			break;
		case WALLET_BACKUP_ERROR:
			return (uint16_t)(sizeof(str_WALLET_BACKUP_ERROR) - 1);
			break;
		case WALLET_RNG_FAILURE:
			return (uint16_t)(sizeof(str_WALLET_RNG_FAILURE) - 1);
			break;
		case WALLET_INVALID_WALLET_NUM:
			return (uint16_t)(sizeof(str_WALLET_INVALID_WALLET_NUM) - 1);
			break;
		case WALLET_INVALID_OPERATION:
			return (uint16_t)(sizeof(str_WALLET_INVALID_OPERATION) - 1);
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
		case TRANSACTION_INVALID_AMOUNT:
			return (uint16_t)(sizeof(str_TRANSACTION_INVALID_AMOUNT) - 1);
			break;
		case TRANSACTION_INVALID_REFERENCE:
			return (uint16_t)(sizeof(str_TRANSACTION_INVALID_REFERENCE) - 1);
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


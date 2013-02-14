/** \file user_interface.c
  *
  * \brief Implements the user interface.
  *
  * This file should contain user interface components which are not specific
  * to any display controller. For example, things like the contents and
  * formatting of each text prompt.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <string.h>
#include "../common.h"
#include "../hwinterface.h"
#include "../baseconv.h"
#include "../prandom.h"
#include "ssd1306.h"
#include "pushbuttons.h"

/** Maximum number of address/amount pairs that can be stored in RAM waiting
  * for approval from the user. This incidentally sets the maximum
  * number of outputs per transaction that parseTransaction() can deal with.
  */
#define MAX_OUTPUTS		16

/** Storage for the text of transaction output amounts. */
static char list_amount[MAX_OUTPUTS][TEXT_AMOUNT_LENGTH];
/** Storage for the text of transaction output addresses. */
static char list_address[MAX_OUTPUTS][TEXT_ADDRESS_LENGTH];
/** Index into #list_amount and #list_address which specifies where the next
  * output amount/address will be copied into. */
static uint32_t list_index;
/** Whether the transaction fee has been set (non-zero) or not (zero). If
  * the transaction fee still hasn't been set after parsing, then the
  * transaction is free. */
static int transaction_fee_set;
/** Storage for transaction fee amount. This is only valid
  * if #transaction_fee_set is non-zero. */
static char transaction_fee_amount[TEXT_AMOUNT_LENGTH];

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
	char *amount_dest;
	char *address_dest;

	if (list_index >= MAX_OUTPUTS)
	{
		return 1; // not enough space to store the amount/address pair
	}
	amount_dest = list_amount[list_index];
	address_dest = list_address[list_index];
	strncpy(amount_dest, text_amount, TEXT_AMOUNT_LENGTH);
	strncpy(address_dest, text_address, TEXT_ADDRESS_LENGTH);
	amount_dest[TEXT_AMOUNT_LENGTH - 1] = '\0';
	address_dest[TEXT_ADDRESS_LENGTH - 1] = '\0';
	list_index++;
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
	strncpy(transaction_fee_amount, text_amount, TEXT_AMOUNT_LENGTH);
	transaction_fee_amount[TEXT_AMOUNT_LENGTH - 1] = '\0';
	transaction_fee_set = 1;
}

/** Notify the user interface that the list of Bitcoin amount/address pairs
  * should be cleared. */
void clearOutputsSeen(void)
{
	list_index = 0;
	transaction_fee_set = 0;
}

/** Ask user if they want to allow some action.
  * \param command The action to ask the user about. See #AskUserCommandEnum.
  * \return 0 if the user accepted, non-zero if the user denied.
  */
uint8_t askUser(AskUserCommand command)
{
	uint8_t i;
	uint8_t r; // what will be returned

	clearDisplay();
	displayOn();

	if (command == ASKUSER_NUKE_WALLET)
	{
		waitForNoButtonPress();
		writeStringToDisplayWordWrap("Delete current wallet and create new one?");
		r = waitForButtonPress();
	}
	else if (command == ASKUSER_NEW_ADDRESS)
	{
		waitForNoButtonPress();
		writeStringToDisplayWordWrap("Create new address?");
		r = waitForButtonPress();
	}
	else if (command == ASKUSER_SIGN_TRANSACTION)
	{
		// writeStringToDisplayWordWrap() isn't used here because word
		// wrapping wastes too much display space.
		for (i = 0; i < list_index; i++)
		{
			clearDisplay();
			waitForNoButtonPress();
			writeStringToDisplay("Send ");
			writeStringToDisplay(list_amount[i]);
			writeStringToDisplay(" BTC to ");
			writeStringToDisplay(list_address[i]);
			writeStringToDisplay("?");
			r = waitForButtonPress();
			if (r)
			{
				// All outputs must be approved in order for a transaction
				// to be signed. Thus if the user denies spending to one
				// output, the entire transaction is forfeit.
				break;
			}
		}
		if (!r && transaction_fee_set)
		{
			clearDisplay();
			waitForNoButtonPress();
			writeStringToDisplay("Transaction fee:");
			nextLine();
			writeStringToDisplay(transaction_fee_amount);
			writeStringToDisplay(" BTC.");
			nextLine();
			writeStringToDisplay("Is this okay?");
			r = waitForButtonPress();
		}
	}
	else if (command == ASKUSER_FORMAT)
	{
		waitForNoButtonPress();
		writeStringToDisplayWordWrap("Format storage? This will delete everything!");
		r = waitForButtonPress();
		if (!r)
		{
			clearDisplay();
			waitForNoButtonPress();
			writeStringToDisplayWordWrap("Are you sure you you want to nuke all wallets?");
			r = waitForButtonPress();
			if (!r)
			{
				clearDisplay();
				waitForNoButtonPress();
				writeStringToDisplayWordWrap("Are you really really sure?");
				r = waitForButtonPress();
			}
		}
	}
	else if (command == ASKUSER_CHANGE_NAME)
	{
		waitForNoButtonPress();
		writeStringToDisplayWordWrap("Change the name of the current wallet?");
		r = waitForButtonPress();
	}
	else if (command == ASKUSER_BACKUP_WALLET)
	{
		waitForNoButtonPress();
		writeStringToDisplayWordWrap("Do you want to backup the current wallet?");
		r = waitForButtonPress();
	}
	else if (command == ASKUSER_RESTORE_WALLET)
	{
		waitForNoButtonPress();
		writeStringToDisplayWordWrap("Delete current wallet and restore from a backup?");
		r = waitForButtonPress();
	}
	else if (command == ASKUSER_CHANGE_KEY)
	{
		waitForNoButtonPress();
		writeStringToDisplayWordWrap("Change the encryption key of the current wallet?");
		r = waitForButtonPress();
	}
	else if (command == ASKUSER_GET_MASTER_KEY)
	{
		waitForNoButtonPress();
		writeStringToDisplayWordWrap("Reveal master public key to host?");
		r = waitForButtonPress();
	}
	else
	{
		waitForNoButtonPress();
		writeStringToDisplayWordWrap("Unknown command in askUser(). Press any button to continue...");
		waitForButtonPress();
		r = 1; // unconditionally deny
	}

	clearDisplay();
	displayOff();
	return r;
}

/** Convert 4 bit number into corresponding hexadecimal character. For
  * example, 0 is converted into '0' and 15 is converted into 'f'.
  * \param nibble The 4 bit number to look at. Only the least significant
  *               4 bits are considered.
  * \return The hexadecimal character.
  */
static char nibbleToHex(uint8_t nibble)
{
	uint8_t temp;
	temp = (uint8_t)(nibble & 0xf);
	if (temp < 10)
	{
		return (char)('0' + temp);
	}
	else
	{
		return (char)('a' + (temp - 10));
	}
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
	uint8_t i;
	uint8_t one_byte; // current byte of seed
	uint8_t byte_counter; // current byte on line, 0 = first, 1 = second etc.
	uint8_t line_number;
	uint8_t r;
	char str[3];
	char leader[3];

	if (destination_device != 0)
	{
		return 1;
	}

	// Tell user whether seed is encrypted or not.
	clearDisplay();
	displayOn();
	waitForNoButtonPress();
	if (is_encrypted)
	{
		writeStringToDisplayWordWrap("Backup is encrypted.");
	}
	else
	{
		writeStringToDisplayWordWrap("Backup is not encrypted.");
	}
	r = waitForButtonPress();
	clearDisplay();
	if (r)
	{
		displayOff();
		return 2;
	}
	waitForNoButtonPress();

	// Output seed to display.
	// str is "xx", where xx are hexadecimal digits.
	// leader is "x:", where x is a hexadecimal digit.
	str[2] = '\0';
	leader[1] = ':';
	leader[2] = '\0';
	byte_counter = 0;
	line_number = 0;
	for (i = 0; i < SEED_LENGTH; i++)
	{
		one_byte = seed[i];
		str[0] = nibbleToHex((uint8_t)(one_byte >> 4));
		str[1] = nibbleToHex(one_byte);
		// The following code will output the seed in the format:
		// " xxxx xxxx xxxx" (for each line)
		if (byte_counter == 0)
		{
			leader[0] = nibbleToHex(line_number);
			writeStringToDisplay(leader);
		}
		else if ((byte_counter & 1) == 0)
		{
			writeStringToDisplay(" ");
		}
		writeStringToDisplay(str);
		byte_counter++;
		if (byte_counter == 6)
		{
			// Move to next line.
			byte_counter = 0;
			line_number++;
		}
		if (displayCursorAtEnd())
		{
			waitForNoButtonPress();
			r = waitForButtonPress();
			clearDisplay();
			if (r)
			{
				displayOff();
				return 2;
			}
			byte_counter = 0;
		}
	}
	waitForNoButtonPress();
	r = waitForButtonPress();
	clearDisplay();
	displayOff();
	if (r)
	{
		return 2;
	}
	return 0;
}

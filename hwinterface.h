/** \file hwinterface.h
  *
  * \brief Defines the platform-dependent interface.
  *
  * All the platform-independent code makes reference to some functions
  * which are strongly platform-dependent. This file describes all the
  * functions which must be implemented on the platform-dependent side.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef HWINTERFACE_H_INCLUDED
#define HWINTERFACE_H_INCLUDED

#include "common.h"
#include "wallet.h"
#include "transaction.h"

/** Return values for non-volatile storage I/O functions. */
typedef enum NonVolatileReturnEnum
{
	/** No error actually occurred. */
	NV_NO_ERROR					=	0,
	/** Invalid address supplied (or, I/O would go beyond end of storage
	  * space). */
	NV_INVALID_ADDRESS			=	1,
	/** Catch-all for all other read/write errors. */
	NV_IO_ERROR					=	2,
} NonVolatileReturn;

/** Values for askUser() function which specify what to ask the user about. */
typedef enum AskUserCommandEnum
{
	/** Do you want to nuke the current wallet and start afresh? */
	ASKUSER_NUKE_WALLET			=	1,
	/** Do you want to create a new address in this wallet? */
	ASKUSER_NEW_ADDRESS			=	2,
	/** Do you want to do this transaction? */
	ASKUSER_SIGN_TRANSACTION	=	3,
	/** Do you want to delete everything? */
	ASKUSER_FORMAT				=	4,
	/** Do you want to change the name of a wallet? */
	ASKUSER_CHANGE_NAME			=	5,
	/** Do wallet backup? */
	ASKUSER_BACKUP_WALLET		=	6,
	/** Restore wallet from backup? */
	ASKUSER_RESTORE_WALLET		=	7,
	/** Do you want to change the encryption key of a wallet? */
	ASKUSER_CHANGE_KEY			=	8,
	/** Do you want to give the host access to the master public key? */
	ASKUSER_GET_MASTER_KEY		=	9
} AskUserCommand;

/** Values for getString() function which specify which set of strings
  * the "spec" parameter selects from. */
typedef enum StringSetEnum
{
	/** "spec" refers to one of the values in #MiscStringsEnum.
	  * See #MiscStringsEnum for what each value should correspond to. */
	STRINGSET_MISC				=	1,
	/** "spec" refers to one of the values in #WalletErrors. The corresponding
	  * string should be a textual representation of the wallet error
	  * (eg. #WALLET_FULL should correspond to something like "Wallet has run
	  * out of space"). */
	STRINGSET_WALLET			=	2,
	/** "spec" refers to one of the values in #TransactionErrors. The
	  * corresponding string should be a textual representation of the
	  * transaction error (eg. #TRANSACTION_TOO_MANY_INPUTS should correspond
	  * to something like "Transaction has too many inputs"). */
	STRINGSET_TRANSACTION		=	3
} StringSet;

/** The miscellaneous strings that can be output. */
typedef enum MiscStringsEnum
{
	/** The device's version string. */
	MISCSTR_VERSION				=	1,
	/** Text explaining that the operation was denied by the user. */
	MISCSTR_PERMISSION_DENIED	=	2,
	/** Text explaining that a packet was malformed or unrecognised. */
	MISCSTR_INVALID_PACKET		=	3,
} MiscStrings;

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
extern char getString(StringSet set, uint8_t spec, uint16_t pos);
/** Get the length of one of the device's strings.
  * \param set Specifies which set of strings to use; should be
  *            one of #StringSetEnum.
  * \param spec Specifies which string to get the character from. The
  *             interpretation of this depends on the value of set;
  *             see #StringSetEnum for clarification.
  * \return The length of the string, in number of characters.
  */
extern uint16_t getStringLength(StringSet set, uint8_t spec);

/** Grab one byte from the communication stream. There is no way for this
  * function to indicate a read error. This is intentional; it
  * makes program flow simpler (no need to put checks everywhere). As a
  * consequence, this function should only return if the received byte is
  * free of read errors.
  *
  * Previously, if a read or write error occurred, processPacket() would
  * return, an error message would be displayed and execution would halt.
  * There is no reason why this couldn't be done inside streamGetOneByte()
  * or streamPutOneByte(). So nothing was lost by omitting the ability to
  * indicate read or write errors.
  *
  * Perhaps the argument can be made that if this function indicated read
  * errors, the caller could attempt some sort of recovery. Perhaps
  * processPacket() could send something to request the retransmission of
  * a packet. But retransmission requests are something which can be dealt
  * with by the implementation of the stream. Thus a caller of
  * streamGetOneByte() will assume that the implementation handles things
  * like automatic repeat request, flow control and error detection and that
  * if a true "stream read error" occurs, the communication link is shot to
  * bits and nothing the caller can do will fix that.
  * \return The received byte.
  */
extern uint8_t streamGetOneByte(void);
/** Send one byte to the communication stream. There is no way for this
  * function to indicate a write error. This is intentional; it
  * makes program flow simpler (no need to put checks everywhere). As a
  * consequence, this function should only return if the byte was sent
  * free of write errors.
  *
  * See streamGetOneByte() for some justification about why write errors
  * aren't indicated by a return value.
  * \param one_byte The byte to send.
  */
extern void streamPutOneByte(uint8_t one_byte);

/** Notify the user interface that the transaction parser has seen a new
  * Bitcoin amount/address pair.
  * \param text_amount The output amount, as a null-terminated text string
  *                    such as "0.01".
  * \param text_address The output address, as a null-terminated text string
  *                     such as "1RaTTuSEN7jJUDiW1EGogHwtek7g9BiEn".
  * \return 0 if no error occurred, non-zero if there was not enough space to
  *         store the amount/address pair.
  */
extern uint8_t newOutputSeen(char *text_amount, char *text_address);
/** Notify the user interface that the transaction parser has seen the
  * transaction fee. If there is no transaction fee, the transaction parser
  * will not call this.
  * \param text_amount The transaction fee, as a null-terminated text string
  *                    such as "0.01".
  */
extern void setTransactionFee(char *text_amount);
/** Notify the user interface that the list of Bitcoin amount/address pairs
  * should be cleared. */
extern void clearOutputsSeen(void);
/** Inform the user that an address has been generated.
  * \param address The output address, as a null-terminated text string
  *                such as "1RaTTuSEN7jJUDiW1EGogHwtek7g9BiEn".
  * \param num_sigs The number of required signatures to redeem Bitcoins from
  *                 the address. For a non-multi-signature address, this
  *                 should be 1.
  * \param num_pubkeys The number of public keys involved in the address. For
  *                    a non-multi-signature address, this should be 1.
  */
extern void displayAddress(char *address, uint8_t num_sigs, uint8_t num_pubkeys);
/** Ask user if they want to allow some action.
  * \param command The action to ask the user about. See #AskUserCommandEnum.
  * \return 0 if the user accepted, non-zero if the user denied.
  */
extern uint8_t askUser(AskUserCommand command);

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
extern int hardwareRandom32Bytes(uint8_t *buffer);

/** Write to non-volatile storage.
  * \param data A pointer to the data to be written.
  * \param address Byte offset specifying where in non-volatile storage to
  *                start writing to.
  * \param length The number of bytes to write.
  * \return See #NonVolatileReturnEnum for return values.
  * \warning Writes may be buffered; use nonVolatileFlush() to be sure that
  *          data is actually written to non-volatile storage.
  */
extern NonVolatileReturn nonVolatileWrite(uint8_t *data, uint32_t address, uint32_t length);
/** Read from non-volatile storage.
  * \param data A pointer to the buffer which will receive the data.
  * \param address Byte offset specifying where in non-volatile storage to
  *                start reading from.
  * \param length The number of bytes to read.
  * \return See #NonVolatileReturnEnum for return values.
  */
extern NonVolatileReturn nonVolatileRead(uint8_t *data, uint32_t address, uint32_t length);
/** Ensure that all buffered writes are committed to non-volatile storage.
  * \return See #NonVolatileReturnEnum for return values.
  */
extern NonVolatileReturn nonVolatileFlush(void);

/** Overwrite anything in RAM which could contain sensitive data. "Sensitive
  * data" includes secret things like encryption keys and wallet private keys.
  * It also includes derived things like expanded keys and intermediate
  * results from elliptic curve calculations. Even past transaction data,
  * addresses and intermediate results from hash calculations could be 
  * considered sensitive and should be overwritten.
  */
extern void sanitiseRam(void);

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
extern uint8_t writeBackupSeed(uint8_t *seed, uint8_t is_encrypted, uint8_t destination_device);

#endif // #ifndef HWINTERFACE_H_INCLUDED

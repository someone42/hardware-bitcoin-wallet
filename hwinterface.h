// ***********************************************************************
// hwinterface.h
// ***********************************************************************
//
// All the platform-independent code makes reference to some functions
// which are strongly platform-dependent. This file describes all the
// functions which must be implemented on the platform-dependent side.
//
// This file is licensed as described by the file LICENCE.

#ifndef HWINTERFACE_H_INCLUDED
#define HWINTERFACE_H_INCLUDED

#include "common.h"
#include "wallet.h"
#include "transaction.h"

// Return values for non-volatile storage I/O functions
typedef enum nonvolatile_return_type
{
	// No error actually occurred.
	NV_NO_ERROR					=	0,
	// Invalid address supplied (or, I/O would go beyond end of storage
	// space).
	NV_INVALID_ADDRESS			=	1,
	// Catch-all for all other read/write errors.
	NV_IO_ERROR					=	2,
} nonvolatile_return;

// Values for ask_user() function which specify what to ask the user about
typedef enum askuser_command_type
{
	// Do you want to nuke the current wallet and start afresh?
	ASKUSER_NUKE_WALLET			=	1,
	// Do you want to create a new address in this wallet?
	ASKUSER_NEW_ADDRESS			=	2,
	// Do you want to do this transaction?
	ASKUSER_SIGN_TRANSACTION	=	3,
	// Do you want to delete everything?
	ASKUSER_FORMAT				=	4,
	// Do you want to change the name of a wallet?
	ASKUSER_CHANGE_NAME			=	5
} askuser_command;

// Values for get_string() function which specify which set of strings
// the "spec" parameter selects from.
typedef enum string_set_type
{
	// "spec" refers to one of the values in misc_strings. See misc_strings
	// for what each value should correspond to.
	STRINGSET_MISC				=	1,
	// "spec" refers to one of the values in wallet_errors. The corresponding
	// string should be a textual representation of the wallet error
	// (eg. WALLET_FULL should correspond to something like "Wallet has run
	// out of space").
	STRINGSET_WALLET			=	2,
	// "spec" refers to one of the values in tx_errors. The corresponding
	// string should be a textual representation of the transaction error
	// (eg. TX_TOO_MANY_INPUTS should correspond to something like
	// "Transaction has too many inputs").
	STRINGSET_TRANSACTION		=	3
} string_set;

typedef enum misc_strings_type
{
	// The device's version string.
	MISCSTR_VERSION				=	1,
	// Text explaining that the operation was denied by the user.
	MISCSTR_PERMISSION_DENIED	=	2,
	// Text explaining that a packet was malformed or unrecognised.
	MISCSTR_INVALID_PACKET		=	3,
} misc_strings;

// Obtain one character from one of the device's strings. pos = 0 specifies
// the first character, pos = 1 the second etc. spec specifies which string
// to get the character from. set specifies which set of strings to use.
// The interpretation of spec depends on set; see the comments near string_set
// for clarification.
extern char get_string(string_set set, u8 spec, u16 pos);
// Get the length of one of the device's strings. See get_string() for what
// set and spec refer to.
extern u16 get_string_length(string_set set, u8 spec);

// Grab one byte from the communication stream, placing that byte
// in *onebyte. If no error occurred, return 0, otherwise return a non-zero
// value to indicate a read error.
extern u8 stream_get_one_byte(u8 *onebyte);
// Send one byte to the communication stream.
// If no error occurred, return 0, otherwise return a non-zero value
// to indicate a write error.
extern u8 stream_put_one_byte(u8 onebyte);

// Notify the user interface that the transaction parser has seen a new
// BitCoin amount/address pair. Both the amount and address are
// null-terminated text strings such as "0.01" and
// "1RaTTuSEN7jJUDiW1EGogHwtek7g9BiEn" respectively. If no error occurred,
// return 0. If there was not enough space to store the amount/address pair,
// then return some non-zero value.
extern u8 new_output_seen(char *textamount, char *textaddress);
// Notify the user interface that the list of BitCoin amount/address pairs
// should be cleared.
extern void clear_outputs_seen(void);
// Ask user if they want to allow some action. Returns 0 if the user
// accepted, non-zero if the user denied.
extern u8 ask_user(askuser_command command);

// Fill buffer with n random bytes. Return an estimate of the total number
// of bits (not bytes) of entropy in the buffer. Do not use pseudo-random
// number generators to fill the buffer, except for testing.
extern u16 hardware_random_bytes(u8 *buffer, u8 n);

// Non-volatile storage must have a size which is a multiple of 128 bytes.
// If the size of the storage area is not a multiple of 128 bytes, then the
// area should be truncated (in software) to the largest multiple of 128
// bytes.

// Write to non-volatile storage. address is a byte offset specifying where
// in non-volatile storage to start writing to. data is a pointer to the
// data to be written and length is the number of bytes to write. See
// nonvolatile_return for return values.
// Warning: writes may be buffered; use nonvolatile_flush() to be sure that
// data is actually written to non-volatile storage.
extern nonvolatile_return nonvolatile_write(u8 *data, u32 address, u8 length);
// Read from non-volatile storage. address is a byte offset specifying where
// in non-volatile storage to start reading from. data is a pointer to the
// buffer which will receive the data and length is the number of bytes to
// read. See nonvolatile_return for return values.
extern nonvolatile_return nonvolatile_read(u8 *data, u32 address, u8 length);
// Ensure that all buffered writes are committed to non-volatile storage.
extern void nonvolatile_flush(void);

// Overwrite anything in RAM which could contain sensitive data. "Sensitive
// data" includes secret things like encryption keys and wallet private keys.
// It also includes derived things like expanded keys and intermediate results
// from elliptic curve calculations. Even past transaction data, addresses
// and intermediate results from hash calculations could be considered
// sensitive and should be overwritten.
extern void sanitise_ram(void);

#endif // #ifndef HWINTERFACE_H_INCLUDED

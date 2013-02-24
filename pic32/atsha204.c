/** \file atsha204.c
  *
  * \brief Driver for Atmel CryptoAuthentication (ATSHA204) chip.
  *
  * The ATSHA204 is a security device which features, among other things, an
  * internal hardware random number generator and the ability to calculate
  * hashes of various chunks of data. Because it is hardened against physical
  * attack, the ATSHA204 can be used to increase the physical security of a
  * hardware Bitcoin wallet. The ATSHA204's internal hardware random number
  * generator can also be used as a source of entropy.
  *
  * The functions in this file provide a software interface to a subset of
  * the ATSHA204's capabilities. For hardware interfacing requirements, see
  * initATSHA204(). To use the functions in this file, first call
  * initATSHA204() once. After that, all the other functions may be used. Note
  * that as described in section 8.1.6 of the ATSHA204 datasheet, the ATSHA204
  * features a watchdog timer which puts the device to sleep periodically.
  * Thus the recommended sequence of calls is: atsha204Wake(), do actual stuff
  * atsha204Sleep().
  *
  * All references to the "ATSHA204 datasheet" refer to document revision
  * 8740D, obtained from http://www.atmel.com/images/doc8740.pdf on
  * 17 November 2012.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
#include <p32xxxx.h>
#include "../common.h"
#include "pic32_system.h"
#include "atsha204.h"

/** Token which represents a one bit. It is sent least-significant bit
  * first. */
#define SEND_TOKEN_ONE				0x1fe
/** Token which represents a zero bit. It is sent least-significant bit
  * first. */
#define SEND_TOKEN_ZERO				0x1fa
/** Number of bits in each token. */
#define SEND_TOKEN_SIZE				9

/** Timeout for waiting for an entire token from the ATSHA204. This is given
  * in the number of search loop iterations of atsha204LookForBit().
  * The value here is:
  * (t_BIT maximum + t_TURNAROUND) * 1.5 / 0.167, rounded up.
  * t_BIT and t_TURNAROUND are from Table 7-3 of the ATSHA204 datasheet
  * (measured in microsecond). 1.5 is a safety factor. 0.167 is the time taken
  * (in microsecond) for a single search loop iteration (assumes CPU clock is
  * at 72 MHz).
  */
#define TOKEN_TIMEOUT_ITERATIONS	1554
/** Timeout for waiting for a single zero pulse within a token from the
  * ATSHA204. This is given in the number of search loop iterations of
  * atsha204LookForBit(). The value here is:
  * t_ZLO maximum * 1.5 / 0.167, rounded up.
  * t_ZLO is from Table 7-3 of the ATSHA204 datasheet (measured in
  * microsecond). 1.5 is a safety factor. 0.167 is the time taken (in
  * microsecond) for a single search loop iteration (assumes CPU clock is
  * at 72 MHz).
  */
#define PULSE_TIMEOUT_ITERATIONS	78

/** Possible return values for receiveToken(). */
typedef enum ATSHA204ReceivedTokenEnum
{
	/** Return value for receiveToken() which indicates that a token
	  * representing a single "0" bit was received. */
	RECEIVED_TOKEN_ZERO		= 130,
	/** Return value for receiveToken() which indicates that a token
	  * representing a single "1" bit was received. */
	RECEIVED_TOKEN_ONE		= 146,
	/** Return value for receiveToken() which indicates that no token
	  * was received; a timeout occurred. */
	RECEIVED_TOKEN_TIMEOUT	= 154
} ATSHA204ReceivedToken;

/** ATSHA204 I/O flags: an 8 bit flag which tells the ATSHA204 what the
  * subsequent operation is going to be. The values here were transcribed from
  * Table 5-1 of the ATSHA204 datasheet. */
typedef enum ATSHA204IOFlagsEnum
{
	/** A command block (to be transmitted to the ATSHA204) will follow this
	  * flag. */
	COMMAND_FLAG			= 0x77,
	/** Tells ATSHA204 to transmit its response back to us. */
	TRANSMIT_FLAG			= 0x88,
	/** Tells ATSHA204 to enter idle (low power) mode. */
	IDLE_FLAG				= 0xbb,
	/** Tells ATSHA204 to enter sleep (very low power) mode. */
	SLEEP_FLAG				= 0xcc
} ATSHA204IOFlags;

/** ATSHA204 command operation codes. Each command block has one of these to
  * tell the ATSHA204 which operation to perform. The values here were
  * transcribed from Table 8-4 of the ATSHA204 datasheet. */
typedef enum ATSHA205OpCodesEnum
{
	/** Derive a key from another key. */
	OPCODE_DERIVEKEY		= 0x1c,
	/** Get device revision. */
	OPCODE_DEVREV			= 0x30,
	/** Generate data protection digest. */
	OPCODE_GENDIG			= 0x15,
	/** Generate HMAC-SHA256 hash of some data. */
	OPCODE_HMAC				= 0x11,
	/** Verify SHA256 hash generated on another ATSHA204 device. */
	OPCODE_CHECKMAC			= 0x28,
	/** Prevent a zone of non-volatile memory from being further modified. */
	OPCODE_LOCK				= 0x17,
	/** Generate SHA256 hash of some data. */
	OPCODE_MAC				= 0x08,
	/** Use internal random number generator to generate a nonce. */
	OPCODE_NONCE			= 0x16,
	/** Selectively place ATSHA204 devices sharing the bus into idle state. */
	OPCODE_PAUSE			= 0x01,
	/** Get output of internal random number generator. */
	OPCODE_RANDOM			= 0x1b,
	/** Read from non-volatile memory. */
	OPCODE_READ				= 0x02,
	/** Update two special "extra" bytes within configuration zone. */
	OPCODE_UPDATEEXTRA		= 0x20,
	/** Write to non-volatile memory. */
	OPCODE_WRITE			= 0x12
} ATSHA205OpCodes;

/** Status/error codes which are sometimes returned by the ATSHA204. The
  * values here were transcribed from Table 8-3 of the ATSHA204 datasheet. */
typedef enum ATSHA205StatusCodesEnum
{
	/** Command succeeded. */
	STATUS_SUCCESS			= 0x00,
	/** CheckMac (see #OPCODE_CHECKMAC) command successfully completed, but
	  * the actual result did not match the expected result. */
	STATUS_MISCOMPARE		= 0x01,
	/** Invalid command block format or unrecognised command. */
	STATUS_PARSE_ERROR		= 0x03,
	/** The ATSHA204 cannot complete the specified command. */
	STATUS_EXECUTION_ERROR	= 0x0f,
	/** The ATSHA204 has successfully received a wake token. */
	STATUS_WAKE				= 0x11,
	/** A command was not properly received by the ATSHA204. */
	STATUS_CRC_ERROR		= 0xff
} ATSHA205StatusCodes;

/** See atsha204_bitbang.S. */
extern void atsha204SendToken(volatile uint32_t *port, uint32_t token, uint32_t size);
/** See atsha204_bitbang.S. */
extern uint32_t atsha204LookForBit(volatile uint32_t *port, uint32_t desired_bit, uint32_t timeout_counter);

/** Send a series of bytes to the ATSHA204 by forming a bunch of tokens and
  * transmitting them.
  * \param buffer The bytes to send to the ATSHA204.
  * \param length The number of bytes to send.
  */
static void sendBytes(const uint8_t *buffer, const unsigned int length)
{
	unsigned int i;
	unsigned int j;
	unsigned int one_byte;
	uint32_t token;
	uint32_t status;

	status = disableInterrupts();
	for (i = 0; i < length; i++)
	{
		one_byte = buffer[i];
		for (j = 0; j < 8; j++)
		{
			if ((one_byte & 1) != 0)
			{
				token = SEND_TOKEN_ONE;
			}
			else
			{
				token = SEND_TOKEN_ZERO;
			}
			atsha204SendToken(&PORTF, token, SEND_TOKEN_SIZE);
			one_byte >>= 1;
		}
	}
	restoreInterrupts(status);
}

/** Wait for and receive a single token from the ATSHA204. If this does
  * receive a token, it will return well before the end of that token, allowing
  * the caller to do some processing before the next token begins.
  * \return See #ATSHA204ReceivedToken.
  * \warning This assumes interrupts are disabled and RF0 is in an input state.
  */
static ATSHA204ReceivedToken receiveToken(void)
{
	// The code for this function was heavily inspired by
	// SHA204LibraryDistributable/SHA204_90USB1287/src/bitbang_phys.c within
	// http://www.atmel.com/Images/SHA204LibraryDistributable_1.3.0.zip,
	// obtained on 16 January 2013.

	// See section 7.3.1 of the ATSHA204 datasheet for the format of tokens.
	// One neat thing about the token format is that it is possible to
	// distinguish between a "0" token and a "1" token well before the end of
	// that token. Thus some processing can be done without fear of missing
	// received tokens.
	// Look for falling edge of start bit.
	if (atsha204LookForBit(&PORTF, 0, TOKEN_TIMEOUT_ITERATIONS) == 0)
	{
		return RECEIVED_TOKEN_TIMEOUT;
	}
	// Look for rising edge of start bit.
	if (atsha204LookForBit(&PORTF, 1, TOKEN_TIMEOUT_ITERATIONS) == 0)
	{
		return RECEIVED_TOKEN_TIMEOUT;
	}
	// Having seen the start bit, the token represents either a zero (if there
	// is an additional low pulse) or a one (if there is no additional low
	// pulse).
	// PULSE_TIMEOUT_ITERATIONS is used as a timeout instead of
	// TOKEN_TIMEOUT_ITERATIONS to distinguish between a possible low pulse of
	// the current token and the start bit of the next token.
	if (atsha204LookForBit(&PORTF, 0, PULSE_TIMEOUT_ITERATIONS) == 0)
	{
		// Timeout occurred; there is no additional low pulse, so the token
		// represents a 1.
		return RECEIVED_TOKEN_ONE;
	}
	else
	{
		// Look for the high transition. This is so that the current low
		// pulse isn't mistaken for the next start bit.
		if (atsha204LookForBit(&PORTF, 1, PULSE_TIMEOUT_ITERATIONS) == 0)
		{
			// Weird; the low pulse stayed low for too long.
			return RECEIVED_TOKEN_TIMEOUT;
		}
		else
		{
			return RECEIVED_TOKEN_ZERO;
		}
	}
}

/** Receive a series of bytes from the ATSHA204. This function will stop
  * receiving if a timeout occurs or if the supplied buffer becomes full.
  * \param buffer An array of bytes which will be filled up with the received
  *               bytes.
  * \param length The size of buffer, in number of bytes.
  * \return The actual number of received bytes, which may not necessarily be
  *         equal to length.
  */
static uint32_t receiveBytes(uint8_t *buffer, uint32_t length)
{
	ATSHA204ReceivedToken token;
	unsigned int i;
	unsigned int j;
	unsigned int bits_received;
	int timeout_seen;
	uint8_t current_byte;
	uint8_t current_bit;
	uint32_t actual_length;
	uint32_t status;

	status = disableInterrupts();
	TRISFbits.TRISF0 = 1;

	timeout_seen = 0;
	actual_length = 0;
	for (i = 0; i < length; i++)
	{
		current_byte = 0;
		current_bit = 1;
		bits_received = 0;
		for (j = 0; j < 8; j++)
		{
			token = receiveToken();
			if (token == RECEIVED_TOKEN_TIMEOUT)
			{
				timeout_seen = 1;
				break;
			}
			else
			{
				bits_received++;
				if (token == RECEIVED_TOKEN_ONE)
				{
					current_byte |= current_bit;
				}
			}
			current_bit <<= 1;
		} // end for (j = 0; j < 8; j++)
		if (bits_received > 0)
		{
			buffer[i] = current_byte;
			actual_length++;
		}
		if (timeout_seen)
		{
			break;
		}
	} // end for (i = 0; i < length; i++)

	TRISFbits.TRISF0 = 0;
	restoreInterrupts(status);
	return actual_length;
}

/** Send wake token to ATSHA204, to take it out of idle or sleep mode. */
static void sendWakeToken(void)
{
	PORTFbits.RF0 = 0;
	delayCycles(80 * CYCLES_PER_MICROSECOND); // 80 us
	PORTFbits.RF0 = 1;
	delayCycles(3 * CYCLES_PER_MILLISECOND); // 3 ms
}

/** Calculate the CRC16 of a stream of bits, using the generator polynomial
  * 0x8005 (as the ATSHA204 does).
  * \param buffer Array of bytes containing the bits to calculate the CRC16 of.
  *               The bits will be read least-significant bit first.
  * \param length_bits The length, in bytes, of the stream.
  * \return The CRC16 of the stream of bits.
  */
static uint16_t calculateCRC16(uint8_t *buffer, uint32_t length)
{
	uint32_t i;
	uint16_t remainder;
	unsigned int bit_counter;
	uint8_t one_byte;
	unsigned int one_bit;

	remainder = 0;
	bit_counter = 0;
	one_byte = 0;
	for (i = 0; i < (length * 8); i++)
	{
		if (bit_counter == 0)
		{
			one_byte = *buffer;
			buffer++;
		}
		bit_counter = (bit_counter + 1) & 7;
		one_bit = ((remainder >> 15) ^ one_byte) & 1;
		remainder <<= 1;
		if (one_bit == 1)
		{
			remainder ^= 0x8005; // generator polynomial
		}
		one_byte >>= 1;
	}
	return remainder;
}

/** Calculate the CRC16 of a byte array and append that CRC16 to the array.
  * \param buffer Array of bytes containing the data to calculate the CRC16
  *               of. The CRC16 will be appended to the end of the array, hence
  *               the array must be of size length + 2.
  * \param length The length, in bytes, of the data to calculate the CRC16 of.
  * \warning This will overwrite the contents of buffer[length] and
  *          buffer[length + 1].
  */
static void appendCRC16(uint8_t *buffer, uint32_t length)
{
	uint16_t crc16;

	crc16 = calculateCRC16(buffer, length);
	buffer[length] = (uint8_t)crc16;
	buffer[length + 1] = (uint8_t)(crc16 >> 8);
}

/** Check whether an I/O block received from the ATSHA204 is valid.
  * \return 0 if the block is not valid, non-zero if it is valid.
  */
static int isBlockValid(uint8_t *buffer, uint32_t length)
{
	uint16_t received_crc16;
	uint16_t calculated_crc16;

	if (length < 3)
	{
		return 0; // block is too small
	}
	if (buffer[0] != length)
	{
		return 0; // block length doesn't match received length
	}
	received_crc16 = (uint16_t)(((uint16_t)buffer[length - 2])
			| (((uint16_t)buffer[length - 1]) << 8));
	calculated_crc16 = calculateCRC16(buffer, length - 2);
	if (received_crc16 != calculated_crc16)
	{
		return 0; // bad CRC
	}
	return 1;
}

/** Convenience function that combines the sendBytes() and receiveBytes()
  * calls. This will send  immediately before receiving.
  * \param buffer An array containing bytes to send to the ATSHA204. Any
  *               received bytes will also be placed here.
  * \param transmit_length Number of bytes to send.
  * \param buffer_length The size of buffer, in number of bytes.
  * \return The actual number of received bytes, which may not necessarily be
  *         equal to buffer_length.
  */
static uint32_t sendAndReceiveBytes(uint8_t *buffer, const unsigned int transmit_length, uint32_t buffer_length)
{
	uint32_t status;
	uint32_t r;

	// Interrupts are disabled for the entire sequence so that the receive
	// loop doesn't miss any response.
	status = disableInterrupts();
	sendBytes(buffer, transmit_length);
	r = receiveBytes(buffer, buffer_length);
	restoreInterrupts(status);
	return r;
}

/** Initialise PIC32 peripherals to interface with the ATSHA204. The ATSHA204
  * should be connected as follows: SDA should be connected to RF0, with a
  * pull-up resistor to Vcc. The ATSHA204 should be configured to use the
  * single-wire interface described in section 5 of the ATSHA204 datasheet.
  *
  * Note that the ATSHA204 does not power on into an active state; an
  * additional call to atsha204Wake() is needed to wake the device up.
  */
void initATSHA204(void)
{
	TRISFbits.TRISF0 = 0;
}

/** Attempt to wake the ATSHA204; this brings it out of idle or sleep mode.
  * Waking is necessary because the ATSHA204 features a watchdog timer which
  * will cause the ATSHA204 to sleep if there is no bus activity.
  * This function will also check if the wake was successful.
  * \return 0 on success, non-zero if the wake failed for any reason.
  */
int atsha204Wake(void)
{
	uint32_t received_length;
	uint8_t buffer[8];

	sendWakeToken();
	buffer[0] = TRANSMIT_FLAG;
	received_length = sendAndReceiveBytes(buffer, 1, sizeof(buffer));
	if(!isBlockValid(buffer, received_length))
	{
		return 1; // invalid block received
	}
	if (received_length != 4)
	{
		return 1; // just after wake, the ATSHA204 should return a 4 byte block
	}
	if (buffer[1] != STATUS_WAKE)
	{
		return 1; // ATSHA204 returned unexpected error/status
	}
	return 0; // success
}

/** Send the ATSHA204 to sleep, so it consumes very little power and ignores
  * everything except for wake tokens. */
void atsha204Sleep(void)
{
	uint8_t buffer[4];

	buffer[0] = SLEEP_FLAG;
	sendBytes(buffer, 1);
}

/** Get the output of the ATSHA204's internal hardware random number
  * generator.
  * \param random_bytes Byte array which, on success, will be written with
  *                     32 random bytes.
  * \return 0 on success, non-zero on failure.
  */
int atsha204Random(uint8_t *random_bytes)
{
	uint32_t received_length;
	uint8_t buffer[64];
	unsigned int timeout_counter;

	buffer[0] = COMMAND_FLAG;
	buffer[1] = 7; // length
	buffer[2] = OPCODE_RANDOM;
	buffer[3] = 0; // mode = 0: automatically update EEPROM seed
	buffer[4] = 0; // reserved; must be 0
	buffer[5] = 0; // reserved; must be 0
	appendCRC16(&(buffer[1]), 5);
	sendBytes(buffer, 8);
	timeout_counter = 0;
	do
	{
		// The token receive timeout (#TOKEN_TIMEOUT_ITERATIONS) equates to
		// about 250 microsecond. The idea here is to delay enough to make
		// each iteration of this do loop about 1 millisecond.
		delayCycles(750 * CYCLES_PER_MICROSECOND); // 750 microsecond
		buffer[0] = TRANSMIT_FLAG;
		received_length = sendAndReceiveBytes(buffer, 1, sizeof(buffer));
		timeout_counter++;
		// From Table 8-4 of the ATSHA204 datasheet, the maximum execution
		// time of the "Random" command is 50 millisecond. The timeout
		// value of 75 below includes a safety factor of 1.5.
	} while ((received_length == 0) && (timeout_counter < 75));
	if (received_length == 0)
	{
		return 1; // timeout
	}
	if(!isBlockValid(buffer, received_length))
	{
		return 1; // invalid block received
	}
	if (received_length != 35)
	{
		return 1; // unexpected packet size
	}
	memcpy(random_bytes, &(buffer[1]), 32);
	return 0; // success
}

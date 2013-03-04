/** \file usart.c
  *
  * \brief Implements stream I/O using the AVR's USART.
  *
  * This allows the host to communicate with the AVR over a serial link.
  * On some Arduinos, the USART is connected to a USB-to-serial bridge,
  * allowing the host to communicate with the AVR over a USB connection.
  * See initUsart() for serial communication parameters.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <avr/io.h>
#include <avr/interrupt.h>
#include <avr/sleep.h>
#include <util/delay.h>

#include "../common.h"
#include "../endian.h"
#include "../hwinterface.h"
#include "hwinit.h"
#include "lcd_and_input.h"

/** Size of transmit buffer, in number of bytes.
  * \warning This must be a power of 2.
  * \warning This must be >= 16 and must be <= 256.
  */
#define TX_BUFFER_SIZE	32
/** Size of receive buffer, in number of bytes.
  * \warning This must be a power of 2.
  * \warning This must be >= 16 and must be <= 256.
  */
#define RX_BUFFER_SIZE	128

/** Bitwise AND mask for transmit buffer index. */
#define TX_BUFFER_MASK	(TX_BUFFER_SIZE - 1)
/** Bitwise AND mask for receive buffer index. */
#define RX_BUFFER_MASK	(RX_BUFFER_SIZE - 1)

/** Storage for the transmit buffer. */
static volatile uint8_t tx_buffer[TX_BUFFER_SIZE];
/** Storage for the receive buffer. */
static volatile uint8_t rx_buffer[RX_BUFFER_SIZE];
/** Index in the transmit buffer of the first character to send. */
static volatile uint8_t tx_buffer_start;
/** Index in the receive buffer of the first character to get. */
static volatile uint8_t rx_buffer_start;
/** Index + 1 in the transmit buffer of the last character to send. */
static volatile uint8_t tx_buffer_end;
/** Index + 1 in the receive buffer of the last character to get. */
static volatile uint8_t rx_buffer_end;
/** Is transmit buffer is full? */
static volatile bool tx_buffer_full;
/** Is receive buffer is full? */
static volatile bool rx_buffer_full;
/** Has a receive buffer overrun occurred? */
static volatile bool rx_buffer_overrun;

/** Number of bytes which can be received until the next acknowledgement must
  * be sent. */
static uint32_t rx_acknowledge;
/** Number of bytes which can be sent before waiting for the next
  * acknowledgement to be received. */
static uint32_t tx_acknowledge;

/** Initialises USART0 with the parameters:
  * baud rate 57600, 8 data bits, no parity bit, 1 start bit, 0 stop bits.
  * This also clears the transmit/receive buffers.
  */
void initUsart(void)
{
	uint8_t temp;

	cli();
	tx_buffer_start = 0;
	tx_buffer_end = 0;
	tx_buffer_full = false;
	rx_buffer_start = 0;
	rx_buffer_end = 0;
	rx_buffer_full = false;
	rx_buffer_overrun = false;
	rx_acknowledge = 16;
	tx_acknowledge = 16;
#define BAUD 57600
	// util/setbaud.h will set UBRRH_VALUE, UBRRL_VALUE and USE_2X to
	// appropriate values, given some F_CPU and BAUD.
#include <util/setbaud.h>
	UBRR0H = UBRRH_VALUE;
	UBRR0L = UBRRL_VALUE;
	// The datasheet says to set FE0, DOR0 and UPE0 to 0 whenever writing to
	// UCSR0A.
	temp = (uint8_t)(UCSR0A & ~_BV(FE0) & ~_BV(DOR0) & ~_BV(UPE0) & ~_BV(U2X0) & ~_BV(MPCM0));
#if USE_2X
	temp |= _BV(U2X0);
#endif // #if USE_2X
	UCSR0A = temp;
	UCSR0B = _BV(RXCIE0) | _BV(RXEN0) | _BV(TXEN0);
	UCSR0C = _BV(UCSZ01) | _BV(UCSZ00);
	PRR = (uint8_t)(PRR & ~_BV(PRUSART0));
	sei();
}

/** Interrupt service routine which is called whenever the USART receives
  * a byte. */
ISR(USART_RX_vect)
{
	if (rx_buffer_full)
	{
		// Uh oh, no space left in receive buffer. Still need to read UDR0
		// to make USART happy.
		uint8_t temp;
		temp = UDR0;
		rx_buffer_overrun = true;
	}
	else
	{
		rx_buffer[rx_buffer_end] = UDR0;
		rx_buffer_end++;
		rx_buffer_end = (uint8_t)(rx_buffer_end & RX_BUFFER_MASK);
		if (rx_buffer_start == rx_buffer_end)
		{
			rx_buffer_full = true;
		}
	}
}

/** Interrupt service routine for USART Data Register Empty.
  * UDRE0 is used instead of TXC0 (transmit complete) because the ISR only
  * moves one byte into the transmit buffer, not an entire frame (however
  * large that happens to be).
  */
ISR(USART_UDRE_vect)
{
	if ((tx_buffer_start != tx_buffer_end) || tx_buffer_full)
	{
		UDR0 = tx_buffer[tx_buffer_start];
		tx_buffer_start++;
		tx_buffer_start = (uint8_t)(tx_buffer_start & TX_BUFFER_MASK);
		tx_buffer_full = false;
	}
	else
	{
		// Nothing left in transmit buffer; disable UDRE interrupt, otherwise
		// it will continuously fire.
		UCSR0B = (uint8_t)(UCSR0B & ~_BV(UDRIE0));
	}
}

/** Send one byte through USART0. If the transmit buffer is full, this will
  * block until it isn't.
  * \param data The byte to send.
  */
static void usartSend(uint8_t data)
{
	bool send_immediately;

	cli();
	send_immediately = false;
	if (!tx_buffer_full && (tx_buffer_start == tx_buffer_end)
		&& (UCSR0A & _BV(UDRE0)))
	{
		send_immediately = true;
	}
	sei();
	if (send_immediately)
	{
		UDR0 = data;
	}
	else
	{
		// Need to queue it.
		while (tx_buffer_full)
		{
			// do nothing
		}
		cli();
		tx_buffer[tx_buffer_end] = data;
		tx_buffer_end++;
		tx_buffer_end = (uint8_t)(tx_buffer_end & TX_BUFFER_MASK);
		if (tx_buffer_start == tx_buffer_end)
		{
			tx_buffer_full = true;
		}
		UCSR0B |= _BV(UDRIE0);
		sei();
	}
}

/** Receive one byte through USART0. If there isn't a byte in the receive
  * buffer, this will block until there is.
  * \return The byte that was received.
  */
static uint8_t usartReceive(void)
{
	uint8_t r;

	// The check in the loop doesn't need to be atomic, because the worst
	// that can happen is that the loop spins one extra time.
	while ((rx_buffer_start == rx_buffer_end) && !rx_buffer_full)
	{
		// do nothing
	}
	cli();
	r = rx_buffer[rx_buffer_start];
	rx_buffer_start++;
	rx_buffer_start = (uint8_t)(rx_buffer_start & RX_BUFFER_MASK);
	rx_buffer_full = false;
	sei();
	return r;
}

/** This is called if a stream read or write error occurs. It never returns.
  * \warning Only call this if the error is unrecoverable. It halts the CPU.
  */
static void streamReadOrWriteError(void)
{
	streamError();
	cli();
	sleep_mode();
	for (;;)
	{
		// do nothing
	}
}

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
uint8_t streamGetOneByte(void)
{
	uint8_t one_byte;

	one_byte = usartReceive();
	rx_acknowledge--;
	if (rx_acknowledge == 0)
	{
		// Send acknowledgement to other side.
		uint8_t buffer[4];
		uint8_t i;

		rx_acknowledge = RX_BUFFER_SIZE;
		writeU32LittleEndian(buffer, rx_acknowledge);
		usartSend(0xff);
		for (i = 0; i < 4; i++)
		{
			usartSend(buffer[i]);
		}
	}
	if (rx_buffer_overrun)
	{
		streamReadOrWriteError();
	}
	return one_byte;
}

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
void streamPutOneByte(uint8_t one_byte)
{
	usartSend(one_byte);
	tx_acknowledge--;
	if (tx_acknowledge == 0)
	{
		// Need to wait for acknowledgement from other side.
		uint8_t buffer[4];
		uint8_t i;

		do
		{
			// do nothing
		} while (usartReceive() != 0xff);
		for (i = 0; i < 4; i++)
		{
			buffer[i] = usartReceive();
		}
		tx_acknowledge = readU32LittleEndian(buffer);
	}
}

/** Beginning of BSS (zero-initialised) section. */
extern void __bss_start;

/** This is a separate function so that the saved variables in sanitiseRam()
  * won't get mangled. */
static NOINLINE void sanitiseRamInternal(void)
{
	volatile uint16_t i;

	// This is an awful abuse of C's type system.
	// __bss_start is a symbol exported by the linker which conveniently
	// has an address which points to the beginning of the zero-initialised
	// data section. i, being allocated on the stack, has an address which
	// points to the bottom of the stack.
	// Clearing everything in-between ensures that the device is left in a
	// state similar to after a reset, with all variables cleared and no
	// remains of past stack variables sitting in unused memory somewhere.
	// The beginning of non-zero-initialised data (__data_start) is not used
	// because non-zero-initialised data is never used to store sensitive
	// data - it's only used for lookup tables.
	cli();
	for (i = (uint16_t)&__bss_start; i < (uint16_t)&i; i++)
	{
		*((uint8_t *)i) = 0xff; // just to be sure
		*((uint8_t *)i) = 0;
	}
	sei();
}

/** Overwrite anything in RAM which could contain sensitive data.
  *
  * This is here because the easiest way to clear everything that is
  * potentially sensitive is to clear (nearly) everything. The only
  * data that aren't cleared are the serial communication acknowledgement
  * counters, because clearing those would cause them to go out of sync
  * with the host (causing one or the other to stall waiting for
  * acknowledgement).
  */
void sanitiseRam(void)
{
	uint32_t saved_rx_acknowledge;
	uint32_t saved_tx_acknowledge;

	// Wait until transmit buffer is empty.
	while (tx_buffer_full)
	{
		// do nothing
	}
	while (tx_buffer_start != tx_buffer_end)
	{
		// do nothing
	}
	// Receive buffer should be empty. It's probably the case if this function
	// was called as a result of a "unload wallet" packet, since the host
	// isn't supposed to send anything until it receives a response from
	// here.

	saved_rx_acknowledge = rx_acknowledge;
	saved_tx_acknowledge = tx_acknowledge;
	sanitiseRamInternal();
	rx_acknowledge = saved_rx_acknowledge;
	tx_acknowledge = saved_tx_acknowledge;
}

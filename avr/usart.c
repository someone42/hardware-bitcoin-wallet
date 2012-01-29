// ***********************************************************************
// usart.c
// ***********************************************************************
//
// Containes functions which do stream I/O using the AVR's USART. This
// allows a computer to communicate with the AVR over a serial link.
//
// This file is licensed as described by the file LICENCE.

#include <avr/io.h>
#include <avr/interrupt.h>
#include <util/delay.h>

#include "../common.h"
#include "../endian.h"
#include "../hwinterface.h"
#include "hwinit.h"

// Size of transmit and receive buffers. They must be a power of 2 and
// must be <= 256. The receive buffer's size must be >= 16.
#define TX_BUFFER_SIZE	32
#define RX_BUFFER_SIZE	128

// Bitwise AND masks for buffer indices.
#define TX_BUFFER_MASK	(TX_BUFFER_SIZE - 1)
#define RX_BUFFER_MASK	(RX_BUFFER_SIZE - 1)

// The transmit/receive buffer.
static volatile u8 tx_buffer[TX_BUFFER_SIZE];
static volatile u8 rx_buffer[RX_BUFFER_SIZE];
// Index in transmit/receive buffer of first character to send/be received.
static volatile u8 tx_buffer_start;
static volatile u8 rx_buffer_start;
// Index + 1 in transmit/receive buffer of last character to send/be received.
static volatile u8 tx_buffer_end;
static volatile u8 rx_buffer_end;
// Set to non-zero if transmit/receive buffer is full.
static volatile u8 tx_buffer_full;
static volatile u8 rx_buffer_full;
// Set to non-zero if a receive buffer overrun occurs
static volatile u8 rx_buffer_overrun;

// Bytes to receive until sending next acknowledge.
static u32 rx_acknowledge;
// Bytes to send until waiting for acknowledge.
static u32 tx_acknowledge;

// Initialises USART0 with the parameters:
// baud rate 57600, 8 data bits, no parity bit, 1 start bit, 0 stop bits.
// This also clears the transmit/receive buffers.
void init_usart(void)
{
	u8 temp;

	cli();
	tx_buffer_start = 0;
	tx_buffer_end = 0;
	tx_buffer_full = 0;
	rx_buffer_start = 0;
	rx_buffer_end = 0;
	rx_buffer_full = 0;
	rx_buffer_overrun = 0;
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
	temp = (u8)(UCSR0A & ~_BV(FE0) & ~_BV(DOR0) & ~_BV(UPE0) & ~_BV(U2X0) & ~_BV(MPCM0));
#if USE_2X
	temp |= _BV(U2X0);
#endif // #if USE_2X
	UCSR0A = temp;
	UCSR0B = _BV(RXCIE0) | _BV(RXEN0) | _BV(TXEN0);
	UCSR0C = _BV(UCSZ01) | _BV(UCSZ00);
	PRR = (u8)(PRR & ~_BV(PRUSART0));
	sei();
}

ISR(USART_RX_vect)
{
	if (rx_buffer_full)
	{
		// Uh oh, no space left in receive buffer. Still need to read UDR0
		// to make USART happy.
		u8 temp;
		temp = UDR0;
		rx_buffer_overrun = 1;
	}
	else
	{
		rx_buffer[rx_buffer_end] = UDR0;
		rx_buffer_end++;
		rx_buffer_end = (u8)(rx_buffer_end & RX_BUFFER_MASK);
		if (rx_buffer_start == rx_buffer_end)
		{
			rx_buffer_full = 1;
		}
	}
}

// Interrupt service routine for USART Data Register Empty.
// UDRE0 is used instead of TXC0 (transmit complete) because the ISR only
// moves one byte into the transmit buffer, not an entire frame (however large
// that happens to be).
ISR(USART_UDRE_vect)
{
	if ((tx_buffer_start != tx_buffer_end) || tx_buffer_full)
	{
		UDR0 = tx_buffer[tx_buffer_start];
		tx_buffer_start++;
		tx_buffer_start = (u8)(tx_buffer_start & TX_BUFFER_MASK);
		tx_buffer_full = 0;
	}
	else
	{
		// Nothing left in transmit buffer; disable UDRE interrupt, otherwise
		// it will continuously fire.
		UCSR0B = (u8)(UCSR0B & ~_BV(UDRIE0));
	}
}

// Send one byte through USART0. This will block if the transmit buffer is
// full.
static void usart_send(u8 data)
{
	u8 send_immediately;

	cli();
	send_immediately = 0;
	if (!tx_buffer_full && (tx_buffer_start == tx_buffer_end)
		&& (UCSR0A & _BV(UDRE0)))
	{
		send_immediately = 1;
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
		tx_buffer_end = (u8)(tx_buffer_end & TX_BUFFER_MASK);
		if (tx_buffer_start == tx_buffer_end)
		{
			tx_buffer_full = 1;
		}
		UCSR0B |= _BV(UDRIE0);
		sei();
	}
}

// Receive one byte through USART0. If there isn't a byte in the receive
// buffer, this will block until there is.
static u8 usart_receive(void)
{
	u8 r;

	// The check in the loop doesn't need to be atomic, because the worst
	// that can happen is that the loop spins one extra time.
	while ((rx_buffer_start == rx_buffer_end) && !rx_buffer_full)
	{
		// do nothing
	}
	cli();
	r = rx_buffer[rx_buffer_start];
	rx_buffer_start++;
	rx_buffer_start = (u8)(rx_buffer_start & RX_BUFFER_MASK);
	rx_buffer_full = 0;
	sei();
	return r;
}

// Grab one byte from the communication stream, placing that byte
// in *onebyte. If no error occurred, return 0, otherwise return a non-zero
// value to indicate a read error.
u8 stream_get_one_byte(u8 *onebyte)
{
	*onebyte = usart_receive();
	rx_acknowledge--;
	if (rx_acknowledge == 0)
	{
		// Send acknowledgement to other side.
		u8 buffer[4];
		u8 i;

		rx_acknowledge = RX_BUFFER_SIZE;
		write_u32_littleendian(buffer, rx_acknowledge);
		usart_send(0xff);
		for (i = 0; i < 4; i++)
		{
			usart_send(buffer[i]);
		}
	}
	if (rx_buffer_overrun)
	{
		rx_buffer_overrun = 0;
		return 1;
	}
	return 0;
}

// Send one byte to the communication stream.
// If no error occurred, return 0, otherwise return a non-zero value
// to indicate a write error.
u8 stream_put_one_byte(u8 onebyte)
{
	usart_send(onebyte);
	tx_acknowledge--;
	if (tx_acknowledge == 0)
	{
		// Need to wait for acknowledgement from other side.
		u8 buffer[4];
		u8 i;

		do
		{
			// do nothing
		} while (usart_receive() != 0xff);
		for (i = 0; i < 4; i++)
		{
			buffer[i] = usart_receive();
		}
		tx_acknowledge = read_u32_littleendian(buffer);
	}
	return 0;
}

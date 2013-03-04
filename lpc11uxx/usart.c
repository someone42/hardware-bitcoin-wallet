/** \file usart.c
  *
  * \brief Interfaces circular buffers to LPC11Uxx's USART.
  *
  * This allows the host to communicate with the wallet via. a serial link.
  * On some development boards (eg. the mbed LPC11U24), the USART is
  * connected to a USB-to-serial bridge, allowing the host to communicate
  * with the wallet over a USB connection.
  * See initUsart() for serial communication parameters.
  *
  * This file is only intended to be used for early development. Later
  * versions will probably use LPC11Uxx's USB controller for communication
  * with the host.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "LPC11Uxx.h"
#include "../common.h"
#include "usart.h"
#include "serial_fifo.h"

/** Initialise USART at 57600 baud, 8 data bits, no parity and 1 stop bit. */
void initUsart(void)
{
	LPC_SYSCON->SYSAHBCLKCTRL |= 0x11000; // enable clock to IOCON and USART
	LPC_IOCON->PIO0_18 = 0x91; // set RXD pin, pull-up enabled
	LPC_IOCON->PIO0_19 = 0x91; // set TXD pin, pull-up enabled
	LPC_SYSCON->UARTCLKDIV = 1; // UART_CLK divider = 1

	// Set baud rate to 57600. The divisors were found by exhaustive search.
	// The resulting baud rate is 48000000 / (16 * 27 * (1 + 13 / 14)),
	// which differs from 57600 by 0.02%.
	LPC_USART->LCR |= 0x80; // enable access to divisor latches
	LPC_USART->FDR = 0xed; // fractional divider = 1 + 13 / 14
	LPC_USART->DLL = 27; // set least significant 8 bits of divisor latch to 27
	LPC_USART->DLM = 0; // set most significant 8 bits of divisor latch to 0
	LPC_USART->OSR = 0xf0; // oversampling ratio = 16
	LPC_USART->LCR &= ~0x80; // disable access to divisor latches
	// Disable stuff that isn't used.
	LPC_USART->ACR = 0; // no auto-baud
	LPC_USART->ICR = 0; // disable IrDA mode
	LPC_USART->HDEN = 0; // disable half-duplex mode
	LPC_USART->SCICTRL = 0; // disable Smart Card interface
	LPC_USART->RS485CTRL = 0; // disable RS-485 mode
	LPC_USART->SYNCCTRL = 0; // disable synchronous mode
	// Set other USART parameters.
	LPC_USART->LCR = 0x03; // no parity, 8 data bits, 1 stop bit
	LPC_USART->MCR = 0; // disable hardware flow control
	LPC_USART->FCR = 1; // enable access to other bits of FCR
	LPC_USART->FCR = 7; // clear receive and transmit FIFOs, trigger level = 1 character
	LPC_USART->TER = 0x80; // enable transmit
	LPC_USART->IER = 7; // enable receive, transmit and error interrupts
	NVIC_EnableIRQ(21); // 21 = USART interrupt
}

/** Interrupt request handler for USART. This is invoked in 3 situations:
  * - whenever a byte is received,
  * - another byte can be shoved into the transmit FIFO,
  * - a receive error occurs.
  */
void UART_IRQHandler(void)
{
	uint32_t source;

	source = ((uint32_t)LPC_USART->IIR >> 1) & 7;
	if (source == 2)
	{
		// Receive data available interrupt.
		// Move bytes from RBR into circular buffer until hardware FIFO is empty.
		while (LPC_USART->LSR & 0x01)
		{
			circularBufferWrite(&receive_buffer, (uint8_t)(LPC_USART->RBR), true);
		}
	}
	else if (source == 1)
	{
		// THRE (Transmit Holding Register Empty) interrupt.
		if (!isCircularBufferEmpty(&transmit_buffer) && (LPC_USART->LSR & 0x20))
		{
			// There's data to send and THR is empty.
			LPC_USART->THR = circularBufferRead(&transmit_buffer, true);
		}
	}
	else
	{
		// Receive line status (or unknown) interrupt.
		LPC_USART->LSR; // read LSR to clear any RLS interrupt
		circularBufferSignalError(&receive_buffer);
	}
}

/** This must be called whenever the transmit buffer transitions from empty
  * to non-empty, in order to initiate the transmission of the contents of the
  * transmit buffer.
  * This function may directly handle the transmission of the first byte (the
  * interrupt handler UART_IRQHandler() will handle the rest).
  */
void serialSendNotify(void)
{
	// Need to disable interrupts otherwise the transmit buffer might be
	// emptied between the check and use.
	__disable_irq();
	if (!isCircularBufferEmpty(&transmit_buffer) && (LPC_USART->LSR & 0x20))
	{
		// There's data to send and THR is empty.
		LPC_USART->THR = circularBufferRead(&transmit_buffer, false);
		// Warning: circularBufferRead() enables interrupts.
	}
	__enable_irq();
}

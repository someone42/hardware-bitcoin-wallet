/** \file serial_fifo.c
  *
  * \brief Implements FIFO buffers and acknowledgement logic for I/O streams.
  *
  * Two software FIFO buffers are maintained, one for receiving and one for
  * transmitting. The buffers are used to make communication more efficient.
  * In order to prevent buffers from overflowing, acknowledgement-based
  * flow control is done, where every n bytes, an acknowledgement is sent
  * which says "you can sent me another n bytes".
  * If the host does not respect this flow control, a buffer overflow will
  * occur. This "buffer overflow" is not the traditional, exploitable one,
  * since storage is implemented as a circular queue. Instead, when a buffer
  * overflow is detected, streamError() is called.
  *
  * The functions in this file don't actually interface with any
  * communications hardware. The interface of circular buffers to hardware
  * must be handled elsewhere.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "LPC11Uxx.h"
#include "usart.h"
#include "serial_fifo.h"
#include "user_interface.h"
#include "../common.h"
#include "../hwinterface.h"
#include "../endian.h"

/** Size of transmit buffer, in number of bytes. There isn't much to be
  * gained from making this significantly larger.
  * \warning This must be a power of 2.
  * \warning This must be >= 16.
  */
#define TRANSMIT_BUFFER_SIZE	32
/** Size of receive buffer, in number of bytes. There isn't much to be
  * gained from making this significantly larger.
  * \warning This must be a power of 2.
  * \warning This must be >= 16.
  */
#define RECEIVE_BUFFER_SIZE		128
/** Initial value for acknowledge counters. */
#define INITIAL_ACKNOWLEDGE		16

/** End address of USB RAM. Transmit and receive buffers are stored in
  * USB RAM (instead of main RAM) to conserve main RAM. There is no security
  * risk (even in the case of a severe hardware or software bug which allows
  * the host to access USB RAM arbitrarily) in storing the buffers in USB RAM,
  * since everything that goes in the transmit/receive buffers also travels
  * over the USB link.
  */
#define USBRAM_END			((volatile uint8_t *)0x20004800)

/** Storage for the transmit buffer.
  * \warning This is stored in USB RAM. See #USBRAM_START for more details.
  */
static volatile uint8_t *transmit_buffer_storage = USBRAM_END - RECEIVE_BUFFER_SIZE - TRANSMIT_BUFFER_SIZE;
/** Storage for the receive buffer.
  * \warning This is stored in USB RAM. See #USBRAM_START for more details.
  */
static volatile uint8_t *receive_buffer_storage = USBRAM_END - RECEIVE_BUFFER_SIZE;
/** The transmit buffer. */
volatile CircularBuffer transmit_buffer;
/** The receive buffer. */
volatile CircularBuffer receive_buffer;

/** Number of bytes which can be received until the next acknowledgement must
  * be sent. */
static uint32_t receive_acknowledge;
/** Number of bytes which can be sent before waiting for the next
  * acknowledgement to be received. */
static uint32_t transmit_acknowledge;

/** Initialise #transmit_buffer and #receive_buffer.
  * \warning This must be called after sanitising RAM, otherwise the storage
  *          pointers won't be set correctly and buffers in USBRAM won't be
  *          cleared.
  */
void initSerialFIFO(void)
{
	LPC_SYSCON->SYSAHBCLKCTRL |= 0x08000000; // enable clock to USBRAM
	memset((void *)transmit_buffer_storage, 0xff, TRANSMIT_BUFFER_SIZE); // just to be sure
	memset((void *)receive_buffer_storage, 0xff, RECEIVE_BUFFER_SIZE); // just to be sure
	memset((void *)transmit_buffer_storage, 0, TRANSMIT_BUFFER_SIZE);
	memset((void *)receive_buffer_storage, 0, RECEIVE_BUFFER_SIZE);
	transmit_buffer.next = 0;
	transmit_buffer.remaining = 0;
	transmit_buffer.size = TRANSMIT_BUFFER_SIZE;
	transmit_buffer.error = 0;
	transmit_buffer.storage = transmit_buffer_storage;
	receive_buffer.next = 0;
	receive_buffer.remaining = 0;
	receive_buffer.size = RECEIVE_BUFFER_SIZE;
	receive_buffer.error = 0;
	receive_buffer.storage = receive_buffer_storage;
	receive_acknowledge = INITIAL_ACKNOWLEDGE;
	transmit_acknowledge = INITIAL_ACKNOWLEDGE;
}

/** Enter LPC11Uxx sleep mode to conserve power. */
static void enterSleepMode(void)
{
	LPC_PMU->PCON = 0; // WFI will enter sleep mode
	SCB->SCR &= ~SCB_SCR_SLEEPDEEP_Msk; // don't enter deep sleep mode
	__asm("wfi"); // wait for interrupt
}

/** Check whether a circular buffer is empty.
  * \param buffer The circular buffer to check.
  * \return Non-zero if it is empty, zero if it is non-empty.
  */
int isCircularBufferEmpty(volatile CircularBuffer *buffer)
{
	return buffer->remaining == 0;
}

/** Tell the reader of the buffer that an error occurred.
  * \param buffer The circular buffer to signal an error in.
  */
void circularBufferSignalError(volatile CircularBuffer *buffer)
{
	buffer->error = 1;
}

/** Read a byte from a circular buffer. This will block until a byte is
  * read.
  * \param buffer The circular buffer to read from.
  * \param is_irq Pass a non-zero value if calling this from an interrupt
  *               request handler, otherwise pass zero.
  * \return The byte that was read from the buffer.
  */
uint8_t circularBufferRead(volatile CircularBuffer *buffer, int is_irq)
{
	uint8_t r;

	while(isCircularBufferEmpty(buffer))
	{
		enterSleepMode();
	}
	if (buffer->error)
	{
		streamError();
		__disable_irq();
		while(1)
		{
			// do nothing
		}
	}
	if (!is_irq)
	{
		__disable_irq();
	}
	r = buffer->storage[buffer->next];
	buffer->remaining--;
	buffer->next = (buffer->next + 1) & (buffer->size - 1);
	if (!is_irq)
	{
		__enable_irq();
	}
	return r;
}

/** Write a byte to a circular buffer. If the buffer is full and is_irq is
  * zero, this will block until the buffer is not full. If the buffer is
  * full and is_irq is non-zero, this will give up and flag a buffer
  * overflow.
  * \param buffer The circular buffer to write to.
  * \param data The byte to write to the buffer.
  * \param is_irq Pass a non-zero value if calling this from an interrupt
  *               request handler, otherwise pass zero.
  */
void circularBufferWrite(volatile CircularBuffer *buffer, uint8_t data, int is_irq)
{
	uint32_t index;

	if (!is_irq)
	{
		if (buffer->error)
		{
			streamError();
			__disable_irq();
			while(1)
			{
				// do nothing
			}
		}
	}
	if (buffer->remaining == buffer->size)
	{
		// Buffer is full.
		if (is_irq)
		{
			// In interrupt handler; cannot block. This can only happen
			// if the host does not honour flow control protocol when sending.
			circularBufferSignalError(buffer);
			return;
		}
		else
		{
			while (buffer->remaining == buffer->size)
			{
				enterSleepMode();
			}
		}
	}
	if (!is_irq)
	{
		__disable_irq();
	}
	index = (buffer->next + buffer->remaining) & (buffer->size - 1);
	buffer->storage[index] = data;
	buffer->remaining++;
	if (!is_irq)
	{
		__enable_irq();
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
	uint8_t buffer[4];
	uint32_t i;

	one_byte = circularBufferRead(&receive_buffer, 0);
	receive_acknowledge--;
	if (receive_acknowledge == 0)
	{
		// Send acknowledgement to other side.
		receive_acknowledge = RECEIVE_BUFFER_SIZE;
		writeU32LittleEndian(buffer, receive_acknowledge);
		circularBufferWrite(&transmit_buffer, 0xff, 0);
		for (i = 0; i < 4; i++)
		{
			circularBufferWrite(&transmit_buffer, buffer[i], 0);
		}
		serialSendNotify();
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
	uint8_t buffer[4];
	uint32_t i;

	circularBufferWrite(&transmit_buffer, one_byte, 0);
	serialSendNotify();
	transmit_acknowledge--;
	if (transmit_acknowledge == 0)
	{
		// Need to wait for acknowledgement from other side.
		do
		{
			// do nothing
		} while (circularBufferRead(&receive_buffer, 0) != 0xff);
		for (i = 0; i < 4; i++)
		{
			buffer[i] = circularBufferRead(&receive_buffer, 0);
		}
		transmit_acknowledge = readU32LittleEndian(buffer);
	}
}

/** Beginning of BSS (zero-initialised) section. */
extern void *__bss_start;

/** This is a separate function so that the saved variables in sanitiseRam()
  * won't get mangled. */
static NOINLINE void sanitiseRamInternal(void)
{
	volatile uint32_t i;

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
	__disable_irq();
	for (i = (uint32_t)&__bss_start; i < (uint32_t)&i; i++)
	{
		*((uint8_t *)i) = 0xff; // just to be sure
		*((uint8_t *)i) = 0;
	}
	__enable_irq();
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
	uint32_t saved_receive_acknowledge;
	uint32_t saved_transmit_acknowledge;

	// Wait until transmit buffer is empty.
	while (!isCircularBufferEmpty(&transmit_buffer))
	{
		// do nothing
	}
	// Receive buffer should be empty. It's probably the case if this function
	// was called as a result of a "unload wallet" packet, since the host
	// isn't supposed to send anything until it receives a response from
	// here.
	saved_receive_acknowledge = receive_acknowledge;
	saved_transmit_acknowledge = transmit_acknowledge;
	sanitiseRamInternal();
	initSerialFIFO();
	receive_acknowledge = saved_receive_acknowledge;
	transmit_acknowledge = saved_transmit_acknowledge;
}

/** \file serial_fifo.c
  *
  * \brief Implements FIFO buffers for I/O streams.
  *
  * Each FIFO buffer is intended to be used in a producer-consumer process,
  * with the producer existing in a non-IRH (Interrupt Request Handler) context
  * and the consumer existing in an IRH context, or vice versa. Synchronisation
  * is handled using critical sections.
  * The functions in this file don't actually interface with any
  * communications hardware. The interface of circular buffers to hardware
  * must be handled elsewhere.
  * Note that this does use the Timer2 peripheral. See enterIdleMode() for
  * reasons why.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
#include <p32xxxx.h>
#include "pic32_system.h"
#include "serial_fifo.h"
#include "usb_callbacks.h" // for usbFatalError()
#include "../common.h"
#include "../hwinterface.h"

/** Clear and initialise contents of circular buffer.
  * \param buffer The circular buffer to initialise and clear.
  * \param storage Storage array for buffer contents. This must be large enough
  *                to store the number of bytes specified by size.
  * \param size Size, in bytes, of the storage array.
  */
void initCircularBuffer(volatile CircularBuffer *buffer, volatile uint8_t *storage, uint32_t size)
{
	memset((void *)storage, 0xff, size); // just to be sure
	memset((void *)storage, 0, size);
	buffer->next = 0;
	buffer->remaining = 0;
	buffer->size = size;
	buffer->storage = storage;
}

/** Enter PIC32 idle mode to conserve power. The CPU will leave idle mode when
  * an interrupt occurs.
  * There is the possibility of a race condition. Say, for example, the caller
  * wishes to wait for a byte to be pushed into a receive FIFO by an interrupt
  * service handler. The caller checks the receive FIFO, and if it is empty,
  * calls this function to wait. However, the receive interrupt may occur
  * after the FIFO check but before the call to this function, in which case
  * the receive interrupt will not bring the CPU out of idle mode.
  * To handle those cases, Timer2 (see serialFIFOInit()) is set to fire
  * interrupts periodically.
  */
static void __attribute__((nomips16)) enterIdleMode(void)
{
	asm volatile("wait");
}

/** Check whether a circular buffer is empty.
  * \param buffer The circular buffer to check.
  * \return Non-zero if it is empty, zero if it is non-empty.
  */
int isCircularBufferEmpty(volatile CircularBuffer *buffer)
{
	return buffer->remaining == 0;
}

/** Obtain the remaining space (in number of bytes) in a circular buffer.
  * It should be safe to call circularBufferWrite() the number of times
  * specified by the return value.
  * \param buffer The circular buffer to check.
  * \return The number of bytes of space remaining in the circular buffer.
  */
uint32_t circularBufferSpaceRemaining(volatile CircularBuffer *buffer)
{
	// No need to put this in a critical section since (outside of init),
	// nothing else touches size.
	return buffer->size - buffer->remaining;
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
	uint32_t status;
	uint8_t r;

	while(isCircularBufferEmpty(buffer))
	{
		if (is_irq)
		{
			// Interrupt service handlers should never try to read from an
			// empty buffer, since they will end up blocking the producer
			// and causing a deadlock.
			usbFatalError();
			return 0;
		}
		enterIdleMode();
	}

	status = disableInterrupts();
	r = buffer->storage[buffer->next];
	buffer->remaining--;
	buffer->next = (buffer->next + 1) & (buffer->size - 1);
	restoreInterrupts(status);
	return r;
}

/** Write a byte to a circular buffer. If the buffer is full, this will block
  * until the buffer is not full.
  * \param buffer The circular buffer to write to.
  * \param data The byte to write to the buffer.
  * \param is_irq Pass a non-zero value if calling this from an interrupt
  *               request handler, otherwise pass zero.
  */
void circularBufferWrite(volatile CircularBuffer *buffer, uint8_t data, int is_irq)
{
	uint32_t status;
	uint32_t index;

	while (buffer->remaining == buffer->size)
	{
		// Buffer is full.
		if (is_irq)
		{
			// In interrupt handler; cannot block, because that will block
			// the consumer and cause a deadlock.
			usbFatalError();
			return;
		}
		enterIdleMode();
	}

	status = disableInterrupts();
	index = (buffer->next + buffer->remaining) & (buffer->size - 1);
	buffer->storage[index] = data;
	buffer->remaining++;
	restoreInterrupts(status);
}

#ifdef PIC32_STARTER_KIT
static uint32_t int_counter;
#endif // #ifdef PIC32_STARTER_KIT

/** Interrupt service handler for Timer2. See enterIdleMode() for
  * justification as to why a serial FIFO implementation needs a timer. */
void __attribute__((vector(_TIMER_2_VECTOR), interrupt(ipl2), nomips16)) _Timer2Handler(void)
{
	IFS0bits.T2IF = 0; // clear interrupt flag
#ifdef PIC32_STARTER_KIT
	// Blink the "everything is running and interrupts are enabled" LED.
	int_counter++;
	if (int_counter == 500)
	{
		PORTDINV = 4; // blink green LED
		int_counter = 0;
	}
#endif // #ifdef PIC32_STARTER_KIT
}

/** Initialise Timer2 for periodic interrupts. Why does a serial FIFO
  * implementation need timer interrupts? To wake up the CPU in the case
  * of a race condition where an interrupt occurs in between a check and
  * the transition to idle state.
  */
void serialFIFOInit(void)
{
	T2CONbits.ON = 0; // turn timer off
	T2CONbits.TCS = 0; // clock source = internal peripheral clock
	T2CONbits.T32 = 0; // 16 bit mode
	T2CONbits.TCKPS = 7; // 1:256 prescaler
	T2CONbits.TGATE = 0; // disable gated time accumulation
	T2CONbits.SIDL = 0; // continue in idle mode
	TMR2 = 0; // clear count
	PR2 = 70; // frequency = about 2 kHz
	T2CONbits.ON = 1; // turn timer on
	IPC2bits.T2IP = 2; // priority level = 2
	IPC2bits.T2IS = 0; // sub-priority level = 0
	IFS0bits.T2IF = 0; // clear interrupt flag
	IEC0bits.T2IE = 1; // enable interrupt
}

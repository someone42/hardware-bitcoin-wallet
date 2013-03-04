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
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
#include <stdbool.h>
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

/** Check whether a circular buffer is empty.
  * \param buffer The circular buffer to check.
  * \return true if it is empty, false if it is non-empty.
  */
bool isCircularBufferEmpty(volatile CircularBuffer *buffer)
{
	if (buffer->remaining == 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

/** Check whether a circular buffer is full.
  * \param buffer The circular buffer to check.
  * \return true if it is full, false if it is not full.
  */
bool isCircularBufferFull(volatile CircularBuffer *buffer)
{
	if (buffer->remaining == buffer->size)
	{
		return true;
	}
	else
	{
		return false;
	}
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
  * \param is_irq Use true if calling this from an interrupt
  *               request handler, otherwise use false.
  * \return The byte that was read from the buffer.
  */
uint8_t circularBufferRead(volatile CircularBuffer *buffer, bool is_irq)
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
  * \param is_irq Use true if calling this from an interrupt
  *               request handler, otherwise use false.
  */
void circularBufferWrite(volatile CircularBuffer *buffer, uint8_t data, bool is_irq)
{
	uint32_t status;
	uint32_t index;

	while (isCircularBufferFull(buffer))
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

/** \file serial_fifo.h
  *
  * \brief Describes types, functions and variables exported by serial_fifo.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef SERIAL_FIFO_H_INCLUDED
#define SERIAL_FIFO_H_INCLUDED

#include <stdbool.h>

/** A circular buffer. */
typedef struct CircularBufferStruct
{
	/** Index of the next element to remove. */
	volatile uint32_t next;
	/** Number of elements remaining in buffer. */
	volatile uint32_t remaining;
	/** The maximum number of elements the buffer can store.
	  * \warning This must be a power of 2.
	  */
	volatile uint32_t size;
	/** Set this to true if an error occurs, otherwise leave it at false. */
	volatile bool error_occurred;
	/** Storage for the buffer. */
	volatile uint8_t *storage;
} CircularBuffer;

/** The transmit buffer. */
extern volatile CircularBuffer transmit_buffer;
/** The receive buffer. */
extern volatile CircularBuffer receive_buffer;

extern void initSerialFIFO(void);
extern bool isCircularBufferEmpty(volatile CircularBuffer *buffer);
extern void circularBufferSignalError(volatile CircularBuffer *buffer);
extern uint8_t circularBufferRead(volatile CircularBuffer *buffer, bool is_irq);
extern void circularBufferWrite(volatile CircularBuffer *buffer, uint8_t data, bool is_irq);

#endif // #ifndef SERIAL_FIFO_H_INCLUDED

/** \file serial_fifo.h
  *
  * \brief Describes types and functions exported by serial_fifo.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef SERIAL_FIFO_H_INCLUDED
#define SERIAL_FIFO_H_INCLUDED

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
	/** Storage for the buffer. */
	volatile uint8_t *storage;
} CircularBuffer;

extern void initCircularBuffer(volatile CircularBuffer *buffer, volatile uint8_t *storage, uint32_t size);
extern int isCircularBufferEmpty(volatile CircularBuffer *buffer);
extern int isCircularBufferFull(volatile CircularBuffer *buffer);
extern uint32_t circularBufferSpaceRemaining(volatile CircularBuffer *buffer);
extern uint8_t circularBufferRead(volatile CircularBuffer *buffer, int is_irq);
extern void circularBufferWrite(volatile CircularBuffer *buffer, uint8_t data, int is_irq);

#endif // #ifndef SERIAL_FIFO_H_INCLUDED

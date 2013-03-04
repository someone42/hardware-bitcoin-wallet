/** \file test_fft.c
  *
  * \brief Tests fft.c for correctness.
  *
  * This file allows the correctness of fft.c to be tested while it is running
  * on actual embedded hardware. As a bonus, this file's code also times how
  * long (in number of cycles) each FFT requires.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifdef TEST_FFT

#include "../fix16.h"
#include "../fft.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "../hwinterface.h"
#include "../endian.h"

/** Receive real number in fixed-point representation from stream.
  * \return The received number.
  */
static fix16_t receiveFix16(void)
{
	uint8_t buffer[4];
	int j;

	for (j = 0; j < 4; j++)
	{
		buffer[j] = streamGetOneByte();
	}
	// The platform-dependent cast below will work correctly on LPC11Uxx,
	// since it uses a two's complement representation of signed integers.
	return (fix16_t)readU32LittleEndian(buffer);
}

/** Send real number in fixed-point representation to stream.
  * \param value The number to send.
  */
static void sendFix16(fix16_t value)
{
	uint8_t buffer[4];
	int j;

	writeU32LittleEndian(buffer, (uint32_t)value);
	for (j = 0; j < 4; j++)
	{
		streamPutOneByte(buffer[j]);
	}
}

/** Test fft() and fftPostProcessReal() by grabbing input data from the
  * stream, computing its FFT and sending it to the stream. The host can
  * then check the output of the FFT.
  *
  * Previously, test cases were stored in this file and this function did
  * all the checking. However, that proved to be infeasible; all
  * microcontrollers in the LPC11Uxx series don't contain enough flash to
  * store a comprehensive set of test cases.
  */
void __attribute__ ((nomips16)) testFFT(void)
{
	ComplexFixed data[FFT_SIZE + 1];
	uint32_t i;
	uint32_t size;
	uint32_t start_count;
	uint32_t end_count;
	uint32_t cycles;
	int test_number;
	bool is_inverse;
	bool failed;
	uint8_t buffer[4];

	while (true)
	{
		// Order of tests:
		// 0 = forward, normal-sized
		// 1 = inverse, normal-sized
		// 2 = forward, double-sized
		// 3 = inverse, double-sized
		for (test_number = 0; test_number < 4; test_number++)
		{
			// Read input data.
			// The host is expected to do the interleaving that
			// fftPostProcessReal() requires.
			for (i = 0; i < FFT_SIZE; i++)
			{
				data[i].real = receiveFix16();
				data[i].imag = receiveFix16();
			}

			// Perform the FFT and measure how long it takes.
			asm volatile("mfc0 %0, $9" : "=r"(start_count));
			if ((test_number == 1) || (test_number == 3))
			{
				is_inverse = true;
			}
			else
			{
				is_inverse = false;
			}
			failed = fft(data, is_inverse);
			if (test_number >= 2)
			{
				if (!failed)
				{
					failed = fftPostProcessReal(data, is_inverse);
				}
			}
			asm volatile("mfc0 %0, $9" : "=r"(end_count)); // read as soon as possible
			cycles = (end_count - start_count) * 2; // Count ticks every 2 cycles

			// Send output data.
			if (test_number >= 2)
			{
				size = FFT_SIZE + 1;
			}
			else
			{
				size = FFT_SIZE;
			}
			if (failed)
			{
				// Failure is marked by output consisting of nothing but
				// fix16_overflow. It's probably impossible for a successful
				// FFT to produce this result.
				for (i = 0; i < size; i++)
				{
					sendFix16(fix16_overflow);
					sendFix16(fix16_overflow);
				}
			}
			else
			{
				for (i = 0; i < size; i++)
				{
					sendFix16(data[i].real);
					sendFix16(data[i].imag);
				}
			}
			// Tell host how long it took
			writeU32LittleEndian(buffer, cycles);
			for (i = 0; i < 4; i++)
			{
				streamPutOneByte(buffer[i]);
			}
		} // end for (test_number = 0; test_number < 4; test_number++)
	} // end while (true)
}

#endif // #ifdef TEST_FFT

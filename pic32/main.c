/** \file main.c
  *
  * \brief Entry point for hardware Bitcoin wallet.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <p32xxxx.h>
#include "usb_hal.h"
#include "usb_standard_requests.h"
#include "usb_callbacks.h"
#include "usb_hid_stream.h"
#include "pic32_system.h"
#include "serial_fifo.h"
#include "ssd1306.h"
#include "atsha204.h"
#include "adc.h"
#include "pushbuttons.h"
#include "sst25x.h"
#include "hwrng.h"
#include "../hwinterface.h"
#include "../endian.h"
#include "../stream_comm.h"

#ifdef TEST_FFT
#include "test_fft.h"
#endif // #ifdef TEST_FFT

/** This will be called whenever an unrecoverable error occurs. This should
  * not return. */
void usbFatalError(void)
{
	fatalError();
}

/** This will be called whenever something very unexpected occurs. This
  * function must not return. */
void fatalError(void)
{
	disableInterrupts();
	PORTDSET = 0x10; // turn on red LED
	while (true)
	{
		// do nothing
	}
}

/** PBKDF2 is used to derive encryption keys. In order to make brute-force
  * attacks more expensive, this should return a number which is as large
  * as possible, without being so large that key derivation requires an
  * excessive amount of time (> 1 s). This is a platform-dependent function
  * because key derivation speed is platform-dependent.
  *
  * In order to permit key recovery when the number of iterations is unknown,
  * this should be a power of 2. That way, an implementation can use
  * successively greater powers of 2 until the correct number of iterations is
  * found.
  * \return Number of iterations to use in PBKDF2 algorithm.
  */
uint32_t getPBKDF2Iterations(void)
{
	return 128;
}

/** Entry point. This is the first thing which is called after startup code.
  * This never returns. */
int main(void)
{
#ifdef TEST_MODE
	uint8_t mode;
	uint8_t counter;
	char string_buffer[2];
	unsigned int i;
#endif // #ifdef TEST_MODE

	disableInterrupts();

	// The BitSafe development board has the Vdd/2 reference connected to
	// a pin which shares the JTAG TMS function. By default, JTAG is enabled
	// and this causes the Vdd/2 voltage to diverge significantly.
	// Disabling JTAG fixes that.
	// This must also be done before calling initSST25x() because one of the
	// external memory interface pins is shared with the JTAG TDI function.
	// Leaving JTAG enabled while calling initSST25x() will cause improper
	// operation of the external memory.
	DDPCONbits.JTAGEN = 0;

	pic32SystemInit();
	initSSD1306();
	initPushButtons();
	initSST25x();
	initATSHA204();
	initADC();
	usbInit();
	usbHIDStreamInit();
	usbDisconnect(); // just in case
	usbSetupControlEndpoint();
	restoreInterrupts(1);

	// The BitSafe development board has VBUS not connected to anything.
	// This causes the PIC32 USB module to think that there is no USB
	// connection. As a workaround, setting VBUSCHG will pull VBUS up.
	// This must be done after calling usbInit() because usbInit() sets
	// the U1OTGCON register.
	U1OTGCONbits.VBUSCHG = 1;

	// All USB-related modules should be initialised before
	// calling usbConnect().
	usbConnect();

#ifdef TEST_MODE
	mode = streamGetOneByte();
	if (mode == 'd')
	{
		displayOn();
	}
	counter = 0;
	while (true)
	{
		if ((mode == 'g') || (mode == 'i') || (mode == 'j'))
		{
			// "Get" test mode, which exclusively uses streamGetOneByte().
			if (mode == 'i')
			{
				delayCycles(100 * CYCLES_PER_MILLISECOND); // pretend to be doing some processing
			}
			else if (mode == 'j')
			{
				delayCycles(10 * CYCLES_PER_SECOND); // pretend to be doing lots of processing
			}
			// Expect data to be an incrementing sequence. This is designed
			// to expose any out-of-order cases.
			if (streamGetOneByte() != counter)
			{
				usbFatalError();
			}
			counter++;
		}
		else if ((mode == 'p') || (mode == 't') || (mode == 'x'))
		{
			// "Put" test mode, which exclusively uses streamPutOneByte().
			if (mode == 't')
			{
				delayCycles(100 * CYCLES_PER_MILLISECOND); // pretend to be doing some processing
			}
			else if (mode == 'x')
			{
				delayCycles(10 * CYCLES_PER_SECOND); // pretend to be doing lots of processing
			}
			// Send data which is an incrementing sequence. This is designed
			// to expose any out-of-order cases.
			streamPutOneByte(counter++);
		}
		else if (mode == 'r')
		{
			// Reply, or loopback mode. This tests simultaneous sending and
			// receiving.
			streamPutOneByte(streamGetOneByte());
		}
		else if (mode == 'd')
		{
			// Display test mode, which sends all received bytes to the
			// display.
			string_buffer[0] = (char)streamGetOneByte();
			string_buffer[1] = '\0';
			writeStringToDisplay(string_buffer);
		}
		else if (mode == 'n')
		{
			// Non-volatile I/O test.
			uint8_t nv_operation;
			uint8_t buffer[16384];
			uint32_t address;
			uint32_t length;

			nv_operation = streamGetOneByte();
			if ((nv_operation == 0x00) || (nv_operation == 0x01))
			{
				for (i = 0; i < 4; i++)
				{
					buffer[i] = streamGetOneByte();
				}
				address = readU32LittleEndian(buffer);
				for (i = 0; i < 4; i++)
				{
					buffer[i] = streamGetOneByte();
				}
				length = readU32LittleEndian(buffer);
				if (length > sizeof(buffer))
				{
					// I/O size is too big.
					usbFatalError();
				}
				else
				{
					if (nv_operation == 0x00)
					{
						nonVolatileRead(buffer, address, length);
						for (i = 0; i < length; i++)
						{
							streamPutOneByte(buffer[i]);
						}
					}
					else
					{
						for (i = 0; i < length; i++)
						{
							buffer[i] = streamGetOneByte();
						}
						nonVolatileWrite(buffer, address, length);
					}
				}
			} // end if ((nv_operation == 0x00) || (nv_operation == 0x01))
			else if (nv_operation == 0x02)
			{
				nonVolatileFlush();
			}
			else
			{
				// Unknown non-volatile memory operation.
				usbFatalError();
			}
		} // end else if (mode == 'n')
		else
		{
			// Unknown test mode.
			usbFatalError();
		}
	} // end while (true)
#elif TEST_FFT
	testFFT();
	while (true)
	{
		// do nothing
	}
#elif TEST_STATISTICS
	testStatistics();
	while (true)
	{
		// do nothing
	}
#else
	while (true)
	{
		processPacket();
	}
#endif // #ifdef TEST_MODE
}

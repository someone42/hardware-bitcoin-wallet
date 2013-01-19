/** \file main.c
  *
  * \brief Entry point for hardware Bitcoin wallet.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
#include <string.h>
#include <p32xxxx.h>
#include "usb_hal.h"
#include "usb_standard_requests.h"
#include "usb_callbacks.h"
#include "usb_hid_stream.h"
#include "pic32_system.h"
#include "serial_fifo.h"
#include "ssd1306.h"
#include "../hwinterface.h"

/** This will be called whenever an unrecoverable error occurs. This should
  * not return. */
void usbFatalError(void)
{
	disableInterrupts();
#ifdef PIC32_STARTER_KIT
	PORTDSET = 1; // turn on red LED
#else
	PORTDSET = 0x10; // turn on red LED
#endif // #ifdef PIC32_STARTER_KIT
	while (1)
	{
		// do nothing
	}
}

/** Entry point. This is the first thing which is called after startup code.
  * This never returns. */
int main(void)
{
	uint8_t mode;
	uint8_t counter;
	char string_buffer[2];

	disableInterrupts();
	pic32SystemInit();
	initSSD1306();
	usbInit();
	usbHIDStreamInit();
	usbDisconnect(); // just in case
	usbSetupControlEndpoint();
	restoreInterrupts(1);

#ifndef PIC32_STARTER_KIT
	// The BitSafe development board has VBUS not connected to anything.
	// This causes the PIC32 USB module to think that there is no USB
	// connection. As a workaround, setting VBUSCHG will pull VBUS up.
	U1OTGCONbits.VBUSCHG = 1;
	// The BitSafe development board has the Vdd/2 reference connected to
	// a pin which shares the JTAG TMS function. By default, JTAG is enabled
	// and this causes the Vdd/2 voltage to diverge significantly.
	// Disabling JTAG fixes that.
	DDPCONbits.JTAGEN = 0;
#endif // #ifndef PIC32_STARTER_KIT

	// All USB-related modules should be initialised before
	// calling usbConnect().
	usbConnect();

	mode = streamGetOneByte();
	if (mode == 'd')
	{
		displayOn();
	}
	counter = 0;
	while (1)
	{
		if ((mode == 'g') || (mode == 'i') || (mode == 'j'))
		{
			// "Get" test mode, which exclusively uses streamGetOneByte().
			if (mode == 'i')
			{
				delayCycles(3600000); // pretend to be doing some processing
			}
			else if (mode == 'j')
			{
				delayCycles(360000000); // pretend to be doing lots of processing
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
				delayCycles(3600000); // pretend to be doing some processing
			}
			else if (mode == 'x')
			{
				delayCycles(360000000); // pretend to be doing lots of processing
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
		else
		{
			usbFatalError();
		}
	}
}

/** \file main.c
  *
  * \brief Entry point for hardware Bitcoin wallet.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <avr/interrupt.h>
#include "../common.h"
#include "../stream_comm.h"
#include "../wallet.h"
#include "../xex.h"
#include "hwinit.h"
#include "lcd_and_input.h"

/** Entry point. This is the first thing which is called after startup code.
  * This never returns. */
int main(void)
{
	uint8_t r;

	initUsart();
	initAdc();
	initLcdAndInput();
	initWallet();

	do
	{
		r = processPacket();
	} while (!r);
	// A fatal error occurred while trying to process the packet.
	// Sending an error message via. the stream would be inappropriate. A
	// safer thing to do is to display an error message on the LCD and then
	// halt.
	streamError();
	cli();
	for (;;)
	{
		// do nothing
	}
}


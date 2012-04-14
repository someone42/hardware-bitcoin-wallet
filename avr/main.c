// ***********************************************************************
// main.c
// ***********************************************************************
//
// Entry point for hardware Bitcoin wallet.
//
// This file is licensed as described by the file LICENCE.

#include <avr/interrupt.h>
#include "../common.h"
#include "../stream_comm.h"
#include "../wallet.h"
#include "../xex.h"
#include "hwinit.h"
#include "lcd_and_input.h"

int main(void)
{
	uint8_t r;

	initUsart();
	initAdc();
	initStreamComm();
	initLcdAndInput();
	initWallet();
	clearEncryptionKey();

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


// ***********************************************************************
// main.c
// ***********************************************************************
//
// Entry point for hardware bitcoin wallet.
//
// This file is licensed as described by the file LICENCE.

#include "../common.h"
#include "../stream_comm.h"
#include "../wallet.h"
#include "../xex.h"
#include "hwinit.h"

int main(void)
{
	u8 r;

	init_usart();
	init_adc();
	init_stream_comm();
	init_lcd_and_input();
	init_wallet();
	clear_keys();

	do
	{
		r = process_packet();
	} while (r == 0);
	// A fatal error occurred while trying to process the packet. Panic!
	for (;;)
	{
		// do nothing
	}
}


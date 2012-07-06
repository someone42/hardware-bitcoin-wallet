/** \file main.c
  *
  * \brief Entry point for hardware Bitcoin wallet.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "LPC11Uxx.h"
#include "usart.h"
#include "serial_fifo.h"
#include "../hwinterface.h"
#include "../stream_comm.h"

/** Upon reset, the LPC11Uxx clock source is its IRC oscillator. This
  * function switches it to run at 48 Mhz the system PLL, using an external
  * crystal as the PLL input.
  */
static void initSystemClock(void)
{
	// Flash access time needs to be configured before changing system clock,
	// otherwise the clock would be too fast for flash access.
	LPC_FLASHCTRL->FLASHCFG = (LPC_FLASHCTRL->FLASHCFG & ~0x03) | 2; // flash access time = 3 clocks
	LPC_SYSCON->SYSOSCCTRL = 0; // crystal oscillator bypass disabled, f = 1 to 20 Mhz
	LPC_SYSCON->SYSPLLCLKSEL = 1; // input to system PLL is crystal
	LPC_SYSCON->SYSPLLCLKUEN = 0; // toggle system PLL clock source update enable
	LPC_SYSCON->SYSPLLCLKUEN = 1;
	LPC_SYSCON->SYSPLLCTRL = 0x23; // M = 4, P = 2 (divider ratio = 4)
	LPC_SYSCON->PDRUNCFG &= ~0xa0; // power up crystal oscillator and system PLL
	while (!(LPC_SYSCON->SYSPLLSTAT & 1)) // wait until system PLL is locked
	{
		// do nothing
	}
	LPC_SYSCON->MAINCLKSEL = 0x03; // select system PLL output as main clock source
	LPC_SYSCON->MAINCLKUEN = 0; // toggle main clock source update enable
	LPC_SYSCON->MAINCLKUEN = 1;
	LPC_SYSCON->SYSAHBCLKDIV = 1; // set system clock divider = 1
}

/** Entry point. This is the first thing which is called after startup code.
  * This never returns. */
int main(void)
{
	initSystemClock();
	initUsart();
	initSerialFIFO();
	__enable_irq();

	do
	{
		processPacket();
	} while (1);
}

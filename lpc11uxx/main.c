/** \file main.c
  *
  * \brief Entry point for hardware Bitcoin wallet.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
#include <stdbool.h>
#include "LPC11Uxx.h"
#include "usart.h"
#include "serial_fifo.h"
#include "ssd1306.h"
#include "user_interface.h"
#include "adc.h"
#include "../hwinterface.h"
#include "../stream_comm.h"

#ifdef TEST_FFT
#include "test_fft.h"
#endif // #ifdef TEST_FFT
#ifdef TEST_STATISTICS
#include "hwrng.h"
#endif // #ifdef TEST_STATISTICS

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

/** This will be called whenever something very unexpected occurs. This
  * function must not return. */
void fatalError(void)
{
	streamError();
	__disable_irq();
	while (true)
	{
		// do nothing
	}
}

#ifdef CHECK_STACK_USAGE
#include "../endian.h"
extern void *__stack_start;
extern void *__stack_end;
#endif // #ifdef CHECK_STACK_USAGE

/** Entry point. This is the first thing which is called after startup code.
  * This never returns. */
int main(void)
{
#ifdef CHECK_STACK_USAGE
	uint32_t i;
	int j;
	uint8_t buffer[4];

	// Mark out stack with 0xcc.
	for (i = (uint32_t)&__stack_start; i < (((uint32_t)&i) - 256); i++)
	{
		*((uint8_t *)i) = 0xcc;
	}
#endif // #ifdef CHECK_STACK_USAGE
	initSystemClock();
	initUsart();
	initSerialFIFO();
	initSSD1306();
	initUserInterface();
	initADC();

	__enable_irq();

#if defined(TEST_FFT)
	testFFT();
	while (true)
	{
		// do nothing
	}
#elif defined(TEST_STATISTICS)
	testStatistics();
	while (true)
	{
		// do nothing
	}
#else
	do
	{
		processPacket();
#ifdef CHECK_STACK_USAGE
		// Find out how much stack space was used by looking for changes to
		// the 0xcc marker.
		for (i = (uint32_t)&__stack_start; i < (((uint32_t)&i) - 256); i++)
		{
			if (*((uint8_t *)i) != 0xcc)
			{
				writeU32LittleEndian(buffer, ((uint32_t)&__stack_end) - i);
				for (j = 0; j < 4; j++)
				{
					streamPutOneByte(buffer[j]);
				}
				break;
			}
		}
#endif // #ifdef CHECK_STACK_USAGE
	} while (true);
#endif // #ifdef TEST_FFT
}

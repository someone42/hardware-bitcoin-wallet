/** \file pic32_system.c
  *
  * \brief Miscellaneous PIC32-related system functions
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
#include <p32xxxx.h>
#include "pic32_system.h"

// This series of #pragma declarations set the device configuration bits.
// TODO: Implemented these in a less Microchip toolchain-specific way.
// System clock = 4 MHz * FPLLMUL / FPLLODIV. These settings assume an
// 8 MHz crystal is connected to the PIC32.
#pragma config FPLLIDIV	= DIV_2
#pragma config FNOSC	= PRIPLL
#pragma config POSCMOD	= XT
#pragma config FSOSCEN	= OFF
#pragma config FPLLMUL	= MUL_18
#pragma config FPLLODIV	= DIV_2
#pragma config FPBDIV	= DIV_1
// USB PLL configuration.
#pragma config UPLLEN	= ON
#pragma config UPLLIDIV	= DIV_2
// Watchdog timer configuration.
#pragma config FWDTEN	= OFF

#ifdef PIC32_STARTER_KIT
/** Counter which counts down number of flashes of USB activity LED. */
static volatile unsigned int usb_activity_counter;
#endif // #ifdef PIC32_STARTER_KIT

/** Disable interrupts.
  * \return Saved value of Status CP0 register, to pass to restoreInterrupts().
  */
uint32_t __attribute__((nomips16)) disableInterrupts(void)
{
	uint32_t status;

	asm volatile("di %0" : "=r"(status));
	return status;
}

/** Restore interrupt handling behaviour.
  * \param status Previous saved value of Status CP0 register (returned
  *               by disableInterrupts()). To unconditionally enable
  *               interrupts, use 1.
  */
void __attribute__((nomips16)) restoreInterrupts(uint32_t status)
{
	if ((status & 1) != 0)
	{
		asm volatile("ei");
	}
}

/** Delay for at least the specified number of cycles.
  * \param num_cycles CPU cycles to delay for.
  */
void __attribute__((nomips16)) delayCycles(uint32_t num_cycles)
{
	uint32_t start_count;
	uint32_t current_count;

	// Note that Count is incremented every 2 CPU cycles.
	num_cycles >>= 1;
	// Use Count register ($9) to count cycles.
	asm volatile("mfc0 %0, $9" : "=r"(start_count));
	do
	{
		asm volatile("mfc0 %0, $9" : "=r"(current_count));
	} while ((current_count - start_count) < num_cycles);
}

/** Initialise caching module. */
static void prefetchInit(void)
{
	// Set 1 wait state. This is okay for CPU operation from 0 to 60 MHz.
	CHECONbits.PFMWS = 1;
	// Enable predictive caching for all regions (cacheable and uncacheable).
	// This eliminates flash wait states for sequential code.
	CHECONbits.PREFEN = 3;
	// Disable data caching.
	CHECONbits.DCSZ = 0;
}

#ifdef PIC32_STARTER_KIT
/** Interrupt service handler for Timer3, used to flash USB activity LED. */
void __attribute__((vector(_TIMER_3_VECTOR), interrupt(ipl2), nomips16)) _Timer3Handler(void)
{
	IFS0bits.T3IF = 0; // clear interrupt flag
	if (usb_activity_counter > 0)
	{
		PORTDINV = 2; // blink orange LED
		usb_activity_counter--;
	}
}

/** Temporarily flash USB activity LED. */
void usbActivityLED(void)
{
	if (usb_activity_counter < 2)
	{
		usb_activity_counter += 2;
	}
}
#endif // #ifdef PIC32_STARTER_KIT

/** Initialise miscellaneous PIC32 system functions such as the prefetch
  * module. */
void pic32SystemInit(void)
{
#ifdef PIC32_STARTER_KIT
	// Set LED pins to output and turn them all off.
	TRISDCLR = 7;
	PORTDCLR = 7;
	// Initialise Timer3 for USB activity LED flashing.
	T3CONbits.ON = 0; // turn timer off
	T3CONbits.TCS = 0; // clock source = internal peripheral clock
	T3CONbits.TCKPS = 7; // 1:256 prescaler
	T3CONbits.TGATE = 0; // disable gated time accumulation
	T3CONbits.SIDL = 0; // continue in idle mode
	TMR3 = 0; // clear count
	PR3 = 7031; // frequency = about 20 Hz
	T3CONbits.ON = 1; // turn timer on
	IPC3bits.T3IP = 2; // priority level = 2
	IPC3bits.T3IS = 0; // sub-priority level = 0
	IFS0bits.T3IF = 0; // clear interrupt flag
	IEC0bits.T3IE = 1; // enable interrupt
#endif // #ifdef PIC32_STARTER_KIT

	INTCONbits.MVEC = 1; // enable multi-vector mode
	prefetchInit();
}

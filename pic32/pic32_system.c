/** \file pic32_system.c
  *
  * \brief Miscellaneous PIC32-related system functions
  *
  * Note that this does use the Timer2 peripheral. See enterIdleMode() for
  * reasons why.
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
// Debugger configuration.
#pragma config ICESEL	= ICS_PGx1
#ifdef __DEBUG
#pragma config DEBUG	= ON
#else
#pragma config DEBUG	= OFF
#endif // #ifdef __DEBUG

/** Counter which counts down number of flashes of USB activity LED. */
static volatile unsigned int usb_activity_counter;

/** Counter which counts _Timer2Handler() calls in order to blink an LED at
  * a reasonable rate. */
static uint32_t timer2_interrupt_counter;

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

/** Delay for at least the specified number of cycles. This is not as precise
  * as delayCycles(), but it consumes less power because the CPU is placed in
  * idle mode while delaying.
  * \param num_cycles CPU cycles to delay for.
  */
void __attribute__((nomips16)) delayCyclesAndIdle(uint32_t num_cycles)
{
	uint32_t start_count;
	uint32_t current_count;

	// Note that Count is incremented every 2 CPU cycles.
	num_cycles >>= 1;
	// Use Count register ($9) to count cycles.
	asm volatile("mfc0 %0, $9" : "=r"(start_count));
	do
	{
		enterIdleMode();
		asm volatile("mfc0 %0, $9" : "=r"(current_count));
	} while ((current_count - start_count) < num_cycles);
}

/** Initialise caching module and set up CPU for instruction caching. */
static void __attribute__ ((nomips16)) prefetchInit(void)
{
	uint32_t config1;

	// Set 1 wait state. This is okay for CPU operation from 0 to 60 MHz.
	CHECONbits.PFMWS = 1;
	// Enable predictive caching for cacheable regions only.
	// This eliminates flash wait states for sequential code.
	// TODO: Maybe don't do this because of that CPU cache errata?
	CHECONbits.PREFEN = 1;
	// Disable data caching.
	CHECONbits.DCSZ = 0;
	// Enable cacheability of kseg0 (it's turned off by default).
	// See section 2.12.13 of the PIC32 family reference manual (revision E),
	// obtained from
	// http://ww1.microchip.com/downloads/en/DeviceDoc/61113E.pdf on
	// 6 November 2012.
	asm volatile("mfc0 %0, $16, 0" : "=r"(config1));
	config1 &= ~0x00000007; // mask out K0
	config1 |= 0x00000003; // set K0 = 3 (cacheable)
	asm volatile("mtc0 %0, $16, 0" : : "r"(config1));
}

/** Enter PIC32 idle mode to conserve power. The CPU will leave idle mode when
  * an interrupt occurs.
  * There is the possibility of a race condition. Say, for example, the caller
  * wishes to wait for a byte to be pushed into a receive FIFO by an interrupt
  * service handler. The caller checks the receive FIFO, and if it is empty,
  * calls this function to wait. However, the receive interrupt may occur
  * after the FIFO check but before the call to this function, in which case
  * the receive interrupt will not bring the CPU out of idle mode.
  */
void __attribute__((nomips16)) enterIdleMode(void)
{
	asm volatile("wait");
}

/** Interrupt service handler for Timer2. See enterIdleMode() for
  * justification as to why a serial FIFO implementation needs a timer. */
void __attribute__((vector(_TIMER_2_VECTOR), interrupt(ipl2), nomips16)) _Timer2Handler(void)
{
	IFS0bits.T2IF = 0; // clear interrupt flag
	// Blink the "everything is running and interrupts are enabled" LED.
	timer2_interrupt_counter++;
	if (timer2_interrupt_counter == 500)
	{
		timer2_interrupt_counter = 0;
		PORTDINV = 4; // blink green LED
	}
}

/** Interrupt service handler for Timer4, used to flash USB activity LED. */
void __attribute__((vector(_TIMER_4_VECTOR), interrupt(ipl2), nomips16)) _Timer4Handler(void)
{
	IFS0bits.T4IF = 0; // clear interrupt flag
	if (usb_activity_counter > 0)
	{
		PORTDINV = 1; // blink blue LED
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

/** Initialise miscellaneous PIC32 system functions such as the prefetch
  * module. */
void pic32SystemInit(void)
{
	// Set LED pins to output and turn them all off.
	TRISDCLR = 0x15;
	PORTDCLR = 0x14;
	PORTDSET = 0x01; // for blue LED, 0 = on, 1 = off

	// Initialise Timer4 for USB activity LED flashing.
	T4CONbits.ON = 0; // turn timer off
	T4CONbits.TCKPS = 7; // 1:256 prescaler
	T4CONbits.T32 = 0; // 16 bit mode
	T4CONbits.TGATE = 0; // disable gated time accumulation
	T4CONbits.SIDL = 0; // continue in idle mode
	TMR4 = 0; // clear count
	PR4 = 7031; // frequency = about 20 Hz
	T4CONbits.ON = 1; // turn timer on
	IPC4bits.T4IP = 2; // priority level = 2
	IPC4bits.T4IS = 0; // sub-priority level = 0
	IFS0bits.T4IF = 0; // clear interrupt flag
	IEC0bits.T4IE = 1; // enable interrupt

	// Initialise Timer2 for periodic interrupts to wake up the CPU in the case
	// of a race condition where an interrupt occurs in between a check and
	// the transition to idle state (enterIdleMode()).
	T2CONbits.ON = 0; // turn timer off
	T2CONbits.T32 = 0; // 16 bit mode
	T2CONbits.TCKPS = 7; // 1:256 prescaler
	T2CONbits.TGATE = 0; // disable gated time accumulation
	T2CONbits.SIDL = 0; // continue in idle mode
	TMR2 = 0; // clear count
	PR2 = 70; // frequency = about 2 kHz
	T2CONbits.ON = 1; // turn timer on
	IPC2bits.T2IP = 2; // priority level = 2
	IPC2bits.T2IS = 0; // sub-priority level = 0
	IFS0bits.T2IF = 0; // clear interrupt flag
	IEC0bits.T2IE = 1; // enable interrupt

	INTCONbits.MVEC = 1; // enable multi-vector mode
	prefetchInit();
}

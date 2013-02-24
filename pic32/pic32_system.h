/** \file pic32_system.h
  *
  * \brief Describes functions and macros exported by pic32_system.c
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef PIC32_SYSTEM_H
#define	PIC32_SYSTEM_H

#include <stdint.h>

/** Virtual addresses are addresses used internally by the CPU to access
  * memory and peripherals. When passing addresses from the CPU to
  * peripherals (eg. for DMA), these virtual addresses need to be converted
  * to physical addresses by setting the most significant 3 bits to 0. */
#define VIRTUAL_TO_PHYSICAL(x)		(((uint32_t)(x)) & 0x1fffffff)

/** Number of CPU cycles per microsecond. */
#define CYCLES_PER_MICROSECOND		72
/** Number of CPU cycles per millisecond. */
#define CYCLES_PER_MILLISECOND		(CYCLES_PER_MICROSECOND * 1000)
/** Number of CPU cycles per second. */
#define CYCLES_PER_SECOND			(CYCLES_PER_MILLISECOND * 1000)

extern uint32_t __attribute__((nomips16)) disableInterrupts(void);
extern void __attribute__((nomips16)) restoreInterrupts(uint32_t status);
extern void __attribute__((nomips16)) delayCycles(uint32_t num_cycles);
extern void __attribute__((nomips16)) delayCyclesAndIdle(uint32_t num_cycles);
extern void __attribute__((nomips16)) enterIdleMode(void);
extern void pic32SystemInit(void);
extern void usbActivityLED(void);

#endif // #ifndef PIC32_SYSTEM_H

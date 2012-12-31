/** \file pic32_system.h
  *
  * \brief Describes functions exported by pic32_system.c
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef PIC32_SYSTEM_H
#define	PIC32_SYSTEM_H

#include <stdint.h>

extern uint32_t __attribute__((nomips16)) disableInterrupts(void);
extern void __attribute__((nomips16)) restoreInterrupts(uint32_t status);
extern void __attribute__((nomips16)) delayCycles(uint32_t num_cycles);
extern void __attribute__((nomips16)) enterIdleMode(void);
extern void pic32SystemInit(void);
extern void usbActivityLED(void);

#endif // #ifndef PIC32_SYSTEM_H

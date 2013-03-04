/** \file pushbuttons.h
  *
  * \brief Describes functions exported by pushbuttons.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef PIC32_PUSHBUTTONS_H_INCLUDED
#define PIC32_PUSHBUTTONS_H_INCLUDED

#include <stdbool.h>

extern void initPushButtons(void);
extern void waitForNoButtonPress(void);
extern bool waitForButtonPress(void);

#endif // #ifndef PIC32_PUSHBUTTONS_H_INCLUDED

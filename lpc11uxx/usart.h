/** \file usart.h
  *
  * \brief Describes functions exported by usart.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef LPC11UXX_USART_H_INCLUDED
#define LPC11UXX_USART_H_INCLUDED

#include "../common.h"

extern void initUsart(void);
extern void serialSendNotify(void);

#endif // #ifndef LPC11UXX_USART_H_INCLUDED

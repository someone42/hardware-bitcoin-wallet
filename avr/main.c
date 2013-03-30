/** \file main.c
  *
  * \brief Entry point for hardware Bitcoin wallet.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <avr/interrupt.h>
#include "../common.h"
#include "../stream_comm.h"
#include "../wallet.h"
#include "../xex.h"
#include "hwinit.h"
#include "lcd_and_input.h"

/** This will be called whenever something very unexpected occurs. This
  * function must not return. */
void fatalError(void)
{
	streamError();
	cli();
	for (;;)
	{
		// do nothing
	}
}

/** PBKDF2 is used to derive encryption keys. In order to make brute-force
  * attacks more expensive, this should return a number which is as large
  * as possible, without being so large that key derivation requires an
  * excessive amount of time (> 1 s). This is a platform-dependent function
  * because key derivation speed is platform-dependent.
  *
  * In order to permit key recovery when the number of iterations is unknown,
  * this should be a power of 2. That way, an implementation can use
  * successively greater powers of 2 until the correct number of iterations is
  * found.
  * \return Number of iterations to use in PBKDF2 algorithm.
  */
uint32_t getPBKDF2Iterations(void)
{
	return 128;
}

/** Entry point. This is the first thing which is called after startup code.
  * This never returns. */
int main(void)
{
	initUsart();
	initAdc();
	initLcdAndInput();

	do
	{
		processPacket();
	} while (true);
}


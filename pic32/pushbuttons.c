/** \file pushbuttons.c
  *
  * \brief Reads the state of the pushbuttons.
  *
  * This file handles user input (accept/cancel pushbuttons). For details on
  * the input hardware requirements, see #ACCEPT_PIN and #CANCEL_PIN.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <p32xxxx.h>
#include "pic32_system.h"

/** Number of consistent samples (each sample is 1 ms apart) required to
  * register a button press. */
#define DEBOUNCE_COUNT	50

/** Bit which specifies which pin (1 = RD0, 2 = RD1, 4 = RD2 etc.) on port D
  * the accept pushbutton is connected to. The pushbutton should connect
  * across the specified pin and ground. A 10 kohm pull-up resistor between
  * the pin and VDD is also required.*/
#define ACCEPT_PIN		(1 << 10)
/** Bit which specifies which pin (1 = RD0, 2 = RD1, 4 = RD2 etc.) on port D
  * the cancel pushbutton is connected to. The pushbutton should connect
  * across the specified pin and ground. A 10 kohm pull-up resistor between
  * the pin and VDD is also required.*/
#define CANCEL_PIN		(1 << 11)

/** Set up PIC32 GPIO to get input from two pushbuttons. */
void initPushButtons(void)
{
	TRISDSET = ACCEPT_PIN | CANCEL_PIN;
}

/** Returns 1 if the accept button is being pressed, 0 if it is not. This
  * function does not do debouncing. */
static int isAcceptPressed(void)
{
	if ((PORTD & ACCEPT_PIN) == 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

/** Returns 1 if the cancel button is being pressed, 0 if it is not. This
  * function does not do debouncing. */
static int isCancelPressed(void)
{
	if ((PORTD & CANCEL_PIN) == 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

/** Wait for approximately 1 millisecond. */
static void wait1ms(void)
{
	delayCyclesAndIdle(1 * CYCLES_PER_MILLISECOND);
}

/** Wait until neither accept nor cancel buttons are being pressed. This
  * function does do debouncing. */
void waitForNoButtonPress(void)
{
	unsigned int counter;

	counter = DEBOUNCE_COUNT;
	while (counter > 0)
	{
		wait1ms();
		if (isAcceptPressed() || isCancelPressed())
		{
			counter = DEBOUNCE_COUNT; // reset debounce counter
		}
		else
		{
			counter--;
		}
	}
}

/** Wait until accept or cancel button is pressed. This function does do
  * debouncing.
  * \return 0 if the accept button was pressed, non-zero if the cancel
  *         button was pressed. If both buttons were pressed simultaneously,
  *         non-zero will be returned.
  */
int waitForButtonPress(void)
{
	uint32_t counter;
	int accept_pressed;
	int cancel_pressed;

	counter = DEBOUNCE_COUNT;
	while (counter > 0)
	{
		wait1ms();
		accept_pressed = isAcceptPressed();
		cancel_pressed = isCancelPressed();
		if (!accept_pressed && !cancel_pressed)
		{
			counter = DEBOUNCE_COUNT; // reset debounce counter
		}
		else
		{
			counter--;
		}
	}
	if (cancel_pressed)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

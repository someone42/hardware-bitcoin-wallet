// ***********************************************************************
// lcd_and_input.c
// ***********************************************************************
//
// Containes functions which drive a HD44780-based LCD. It's assumed
// that the LCD has 2 lines, each character is 5x8 dots and there are 40
// bytes per line of DDRAM.
// The datasheet was obtained on 22-September-2011, from:
// http://lcd-linux.sourceforge.net/pdfdocs/hd44780.pdf
// All references to "the datasheet" refer to this document.
// This also (incidentally) deals with button inputs, since there's a
// timer ISR which can handle the debouncing.
//
// This file is licensed as described by the file LICENCE.

#include <avr/io.h>
#include <util/delay.h>
#include <avr/interrupt.h>
#include <avr/pgmspace.h>
#include <string.h>

#include "../common.h"
#include "../hwinterface.h"

// Maximum number of address/amount pairs that can be stored in RAM waiting
// for confirmation from the user. This incidentally sets the maximum
// number of outputs per transaction that parse_transaction() can deal with.
// This must be < 256.
#define MAX_OUTPUTS		2

// The Arduino pin numbers that the LCD interface is connected to.
#define RS_PIN			12 // register select
#define E_PIN			11 // starts read/write
#define D4_PIN			5
#define D5_PIN			4
#define D6_PIN			3
#define D7_PIN			2

// The Arduino pin numbers that the input buttons are connected to.
#define ACCEPT_PIN		6
#define	CANCEL_PIN		7

// Number of columns per line.
#define NUM_COLUMNS		16
// Scroll speed, in multiples of 5 ms. Example: 100 means scroll will happen
// every 500 ms. Must be < 65536.
#define SCROLL_SPEED	150
// Scroll pause length, in multiples of 5 ms. Whenever a string is written
// to the LCD, scrolling will pause for this long. Must be < 65536.
#define SCROLL_PAUSE	450

// Number of consistent samples (each sample is 5 ms apart) required to
// register a button press. Must be < 256.
#define DEBOUNCE_COUNT	8

// Set one of the digital output pins based on the Arduino pin mapping.
// pin is the Arduino pin number (0 to 13 inclusive) and value is non-zero
// for output high and zero for output low.
static inline void writeArduinoPin(const uint8_t pin, const uint8_t value)
{
	uint8_t bit;

	bit = 1;
	if (pin < 8)
	{
		bit = (uint8_t)(bit << pin);
		DDRD |= bit;
		if (value)
		{
			PORTD |= bit;
		}
		else
		{
			PORTD = (uint8_t)(PORTD & ~bit);
		}
	}
	else
	{
		bit = (uint8_t)(bit << (pin - 8));
		DDRB |= bit;
		if (value)
		{
			PORTB |= bit;
		}
		else
		{
			PORTB = (uint8_t)(PORTB & ~bit);
		}
	}
}

// Write the least-significant 4 bits of value to the HD44780.
// See page 49 of the datasheet for EN timing. All delays have at least
// a 2x safety factor.
static void write4(uint8_t value)
{
	writeArduinoPin(D4_PIN, (uint8_t)(value & 0x01));
	writeArduinoPin(D5_PIN, (uint8_t)(value & 0x02));
	writeArduinoPin(D6_PIN, (uint8_t)(value & 0x04));
	writeArduinoPin(D7_PIN, (uint8_t)(value & 0x08));
	_delay_us(2);
	writeArduinoPin(E_PIN, 0);
	_delay_us(2);
	writeArduinoPin(E_PIN, 1);
	_delay_us(2);
	writeArduinoPin(E_PIN, 0);
	_delay_us(2);
	// From page 24 of the datasheet, most commands require 37 us to complete.
	_delay_us(74);
}

// Write 8 bits to the HD44780 using write4() twice.
// Warning: have you set RS_PIN to your desired value?
static void write8(uint8_t value)
{
	write4((uint8_t)(value >> 4));
	write4(value);
}

// Set one of the Arduino digital I/O pins to be an input pin with
// internal pull-up enabled.
static inline void setArduinoPinInput(const uint8_t pin)
{
	uint8_t bit;

	bit = 1;
	if (pin < 8)
	{
		bit = (uint8_t)(bit << pin);
		DDRD = (uint8_t)(DDRD & ~bit);
		PORTD |= bit;
	}
	else
	{
		bit = (uint8_t)(bit << (pin - 8));
		DDRB = (uint8_t)(DDRB & ~bit);
		PORTB |= bit;
	}
}

// Returns non-zero if the Arduino digital I/O pin is high, returns 0 if it
// is low.
static inline uint8_t sampleArduinoPin(const uint8_t pin)
{
	uint8_t bit;

	bit = 1;
	if (pin < 8)
	{
		bit = (uint8_t)(bit << pin);
		return (uint8_t)(PIND & bit);
	}
	else
	{
		bit = (uint8_t)(bit << (pin - 8));
		return (uint8_t)(PINB & bit);
	}
}

// 0-based column index.
static uint8_t current_column;
// Largest size (in number of characters) of either line.
static uint8_t max_line_size;
// Scroll position (0 = leftmost) in number of characters.
static uint8_t scroll_pos;
// 0 = towards the right (text appears to move left), non-zero = towards
// the left (text appears to move right).
static uint8_t scroll_direction;
// Countdown to next scroll.
static uint16_t scroll_counter;
// Status of accept/cancel buttons; 0 = not pressed, non-zero = pressed.
static volatile uint8_t accept_button;
static volatile uint8_t cancel_button;
// Debounce counters for accept/cancel buttons
static uint8_t accept_debounce;
static uint8_t cancel_debounce;

// Storage for amount/address pairs.
static char list_amount[MAX_OUTPUTS][22];
static char list_address[MAX_OUTPUTS][36];
static uint8_t list_index;

// This does the scrolling and checks the state of the buttons.
ISR(TIMER0_COMPA_vect)
{
	uint8_t temp;

	scroll_counter--;
	if (scroll_counter == 0)
	{
		if (max_line_size > NUM_COLUMNS)
		{
			if (scroll_direction)
			{
				if (scroll_pos == 0)
				{
					scroll_direction = 0;
				}
				else
				{
					writeArduinoPin(RS_PIN, 0);
					write8(0x1c);
					scroll_pos--;
				}
			}
			else
			{
				if (scroll_pos == (max_line_size - NUM_COLUMNS))
				{
					scroll_direction = 1;
				}
				else
				{
					writeArduinoPin(RS_PIN, 0);
					write8(0x18);
					scroll_pos++;
				}
			}
		}
		scroll_counter = SCROLL_SPEED;
	}

	temp = sampleArduinoPin(ACCEPT_PIN);
	if ((accept_button && temp) || (!accept_button && !temp))
	{
		// Mismatching state; accumulate debounce counter until threshold
		// is reached, then make states consistent.
		accept_debounce++;
		if (accept_debounce == DEBOUNCE_COUNT)
		{
			accept_button = (uint8_t)!accept_button;
		}
	}
	else
	{
		accept_debounce = 0;
	}
	temp = sampleArduinoPin(CANCEL_PIN);
	if ((cancel_button && temp) || (!cancel_button && !temp))
	{
		// Mismatching state; accumulate debounce counter until threshold
		// is reached, then make states consistent.
		cancel_debounce++;
		if (cancel_debounce == DEBOUNCE_COUNT)
		{
			cancel_button = (uint8_t)!cancel_button;
		}
	}
	else
	{
		cancel_debounce = 0;
	}
}

static void clearLcd(void)
{
	current_column = 0;
	max_line_size = 0;
	scroll_pos = 0;
	scroll_direction = 0;
	scroll_counter = SCROLL_SPEED;
	writeArduinoPin(RS_PIN, 0);
	write8(0x01); // clear display
	_delay_ms(10);
}

// See page 46 of the datasheet. All delays have a 2x safety factor.
// This also sets up timer 0 to fire an interrupt every 5 ms.
void initLcdAndInput(void)
{
	cli();
	TCCR0A = _BV(WGM01);
	TCCR0B = _BV(CS02) | _BV(CS00);
	TCNT0 = 0;
	OCR0A = 78; // (16000000 / 1024) * 0.005
	TIMSK0 = _BV(OCIE0A);
	scroll_counter = 1000; // make sure no attempt at scrolling is made yet
	MCUCR = (uint8_t)(MCUCR & ~_BV(PUD));
	setArduinoPinInput(ACCEPT_PIN);
	setArduinoPinInput(CANCEL_PIN);
	accept_button = 0;
	cancel_button = 0;
	accept_debounce = 0;
	cancel_debounce = 0;
	sei();
	writeArduinoPin(E_PIN, 0);
	writeArduinoPin(RS_PIN, 0);
	_delay_ms(80);
	write4(3);
	_delay_ms(8.2);
	write4(3);
	_delay_ms(0.2);
	write4(3);
	write4(2);
	// Now in 4-bit mode.
	write8(0x28); // function set: 4-bit mode, 2 lines, 5x8 dots
	write8(0x0c); // display on/off control: display on, no cursor
	clearLcd();
	write8(0x06); // entry mode set: increment, no display shift
	list_index = 0;
}

// If line is zero, this sets the cursor to the start of the first line,
// otherwise this sets the cursor to the start of the second line.
static void gotoStartOfLine(uint8_t line)
{
	writeArduinoPin(RS_PIN, 0);
	if (!line)
	{
		write8(0x80);
	}
	else
	{
		write8(0xc0);
	}
	current_column = 0;
}

// Write a null-terminated string str to the display. Characters past
// column 40 are dropped.
// If is_progmem is non-zero, then str is treated as a pointer to program
// memory.
static void writeString(char *str, uint8_t is_progmem)
{
	char c;

	writeArduinoPin(RS_PIN, 1);
	if (is_progmem)
	{
		c = (char)pgm_read_byte(str);
	}
	else
	{
		c = *str;
	}
	str++;
	while ((c != 0) && (current_column < 40))
	{
		write8((uint8_t)c);
		if (is_progmem)
		{
			c = (char)pgm_read_byte(str);
		}
		else
		{
			c = *str;
		}
		str++;
		current_column++;
		if (current_column > max_line_size)
		{
			max_line_size = current_column;
		}
	}
	scroll_counter = SCROLL_PAUSE;
}

// Notify the user interface that the transaction parser has seen a new
// Bitcoin amount/address pair. Both the amount and address are
// null-terminated text strings such as "0.01" and
// "1RaTTuSEN7jJUDiW1EGogHwtek7g9BiEn" respectively. If no error occurred,
// return 0. If there was not enough space to store the amount/address pair,
// then return some non-zero value.
uint8_t newOutputSeen(char *text_amount, char *text_address)
{
	char *amount_dest;
	char *address_dest;

	if (list_index >= MAX_OUTPUTS)
	{
		return 1; // not enough space to store the amount/address pair
	}
	amount_dest = list_amount[list_index];
	address_dest = list_address[list_index];
	strncpy(amount_dest, text_amount, 22);
	strncpy(address_dest, text_address, 36);
	amount_dest[21] = '\0';
	address_dest[35] = '\0';
	list_index++;
	return 0;
}

// Notify the user interface that the list of Bitcoin amount/address pairs
// should be cleared.
void clearOutputsSeen(void)
{
	list_index = 0;
}

// Wait until neither accept nor cancel are being pressed.
static void waitForNoButtonPress(void)
{
	do
	{
		// do nothing
	} while (accept_button || cancel_button);
}

// Wait until accept or cancel is pressed. Returns 0 if the accept button
// was pressed, non-zero if the cancel button was pressed.
static uint8_t waitForButtonPress(void)
{
	uint8_t current_accept_button;
	uint8_t current_cancel_button;

	do
	{
		// Copy to avoid race condition.
		current_accept_button = accept_button;
		current_cancel_button = cancel_button;
	} while (!current_accept_button && !current_cancel_button);
	if (current_accept_button)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

// The code would be much more readable if the string literals were all
// implicitly defined within ask_user(). However, then they eat up valuable
// RAM. Declaring them here means that they can have the PROGMEM attribute
// added (to place them in program memory).
static char str_delete_line0[] PROGMEM = "Delete existing wallet";
static char str_delete_line1[] PROGMEM = "and start a new one?";
static char str_new_line0[] PROGMEM = "Create new";
static char str_new_line1[] PROGMEM = "address?";
static char str_sign_part0[] PROGMEM = "Sending ";
static char str_sign_part1[] PROGMEM = " BTC to";
static char str_format_line0[] PROGMEM = "Do you want to";
static char str_format_line1[] PROGMEM = "delete everything?";
static char str_change_line0[] PROGMEM = "Change the name";
static char str_change_line1[] PROGMEM = "of your wallet?";
static char str_unknown_line0[] PROGMEM = "Unknown command in ask_user()";
static char str_unknown_line1[] PROGMEM = "Press any button to continue";
static char str_stream_error[] PROGMEM = "Stream error";

// Ask user if they want to allow some action. Returns 0 if the user
// accepted, non-zero if the user denied.
uint8_t askUser(AskUserCommand command)
{
	uint8_t i;
	uint8_t r; // what will be returned

	clearLcd();

	if (command == ASKUSER_NUKE_WALLET)
	{
		waitForNoButtonPress();
		gotoStartOfLine(0);
		writeString(str_delete_line0, 1);
		gotoStartOfLine(1);
		writeString(str_delete_line1, 1);
		r = waitForButtonPress();
	}
	else if (command == ASKUSER_NEW_ADDRESS)
	{
		waitForNoButtonPress();
		gotoStartOfLine(0);
		writeString(str_new_line0, 1);
		gotoStartOfLine(1);
		writeString(str_new_line1, 1);
		r = waitForButtonPress();
	}
	else if (command == ASKUSER_SIGN_TRANSACTION)
	{
		for (i = 0; i < list_index; i++)
		{
			clearLcd();
			waitForNoButtonPress();
			gotoStartOfLine(0);
			writeString(str_sign_part0, 1);
			writeString(list_amount[i], 0);
			writeString(str_sign_part1, 1);
			gotoStartOfLine(1);
			writeString(list_address[i], 0);
			r = waitForButtonPress();
			if (r)
			{
				// All outputs must be confirmed in order for a transaction
				// to be signed. Thus if the user denies spending to one
				// output, the entire transaction is forfeit.
				break;
			}
		}
	}
	else if (command == ASKUSER_FORMAT)
	{
		waitForNoButtonPress();
		gotoStartOfLine(0);
		writeString(str_format_line0, 1);
		gotoStartOfLine(1);
		writeString(str_format_line1, 1);
		r = waitForButtonPress();
	}
	else if (command == ASKUSER_CHANGE_NAME)
	{
		waitForNoButtonPress();
		gotoStartOfLine(0);
		writeString(str_change_line0, 1);
		gotoStartOfLine(1);
		writeString(str_change_line1, 1);
		r = waitForButtonPress();
	}
	else
	{
		waitForNoButtonPress();
		gotoStartOfLine(0);
		writeString(str_unknown_line0, 1);
		gotoStartOfLine(1);
		writeString(str_unknown_line1, 1);
		waitForButtonPress();
		r = 1; // unconditionally deny
	}

	clearLcd();
	return r;
}

// Notify user of stream error via. LCD.
void streamError(void)
{
	clearLcd();
	gotoStartOfLine(0);
	writeString(str_stream_error, 1);
}

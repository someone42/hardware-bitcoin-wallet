// ***********************************************************************
// adc.c
// ***********************************************************************
//
// Containes functions which sample from one of the AVR's analog-to-digital
// convertor inputs. Hopefully that input is connected to a hardware
// random number generator.
//
// This file is licensed as described by the file LICENCE.

#include <avr/io.h>

#include "../common.h"
#include "../hwinterface.h"
#include "hwinit.h"

// Enable ADC with prescaler 128 (ADC clock 125 kHz), pointing at input ADC0.
void init_adc(void)
{
	ADMUX = _BV(REFS0);
	ADCSRA = _BV(ADEN) |  _BV(ADPS2) |  _BV(ADPS1) |  _BV(ADPS0);
	ADCSRB = 0;
	PRR = (u8)(PRR & ~_BV(PRADC));
}

static u16 adc_sample(void)
{
	u8 sample_lo;
	u8 sample_hi;

	ADCSRA |= _BV(ADSC);
	while (ADCSRA & _BV(ADSC))
	{
		// do nothing
	}
	sample_lo = ADCL;
	sample_hi = ADCH;

	return ((u16)sample_hi << 8) | sample_lo; 
}

// Fill buffer with n random bytes. Return an estimate of the total number
// of bits (not bytes) of entropy in the buffer.
u16 hardware_random_bytes(u8 *buffer, u8 n)
{
	u16 sample;
	u16 entropy;

	// Just assume each sample has 4 bits of entropy
	entropy = (u16)((u16)n << 2);
	for (; n--; )
	{
		sample = adc_sample();
		// Each sample is 10 bits. XOR the most-significant (MS) 2 bits into
		// the least-significant (LS) 2 bits. As long as they are not
		// significantly correlated, this shouldn't result in a decrease in
		// total entropy. Since the MS 2 bits and LS 2 bits are a factor of
		// 256 apart (in significance), this correlation should be minimal.
		buffer[n] = (u8)((u8)sample ^ (u8)(sample >> 8));
	}
	return entropy;
}

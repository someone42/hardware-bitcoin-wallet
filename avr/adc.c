/** \file adc.c
  *
  * \brief Samples the AVR's analog-to-digital convertor.
  *
  * Contains functions which sample from one of the AVR's analog-to-digital
  * convertor inputs. Hopefully that input (see initAdc() for which input
  * is selected) is connected to a hardware random number generator.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <avr/io.h>

#include "../common.h"
#include "../hwinterface.h"
#include "hwinit.h"

/** Enable ADC with prescaler 128 (ADC clock 125 kHz), pointing at input ADC0.
  * On Arduino, that's analog in, pin 0.
  */
void initAdc(void)
{
	ADMUX = _BV(REFS0);
	ADCSRA = _BV(ADEN) |  _BV(ADPS2) |  _BV(ADPS1) |  _BV(ADPS0);
	ADCSRB = 0;
	PRR = (uint8_t)(PRR & ~_BV(PRADC));
}

/** Get one 10 bit sample from the ADC. */
static uint16_t adcSample(void)
{
	uint8_t sample_lo;
	uint8_t sample_hi;

	ADCSRA |= _BV(ADSC);
	while (ADCSRA & _BV(ADSC))
	{
		// do nothing
	}
	sample_lo = ADCL;
	sample_hi = ADCH;

	return ((uint16_t)sample_hi << 8) | sample_lo; 
}

/** Fill buffer with random bytes from a hardware random number generator.
  * \param buffer The buffer to fill. This should have enough space for n
  *               bytes.
  * \param n The size of the buffer.
  * \return An estimate of the total number of bits (not bytes) of entropy in
  *         the buffer.
  */
uint16_t hardwareRandomBytes(uint8_t *buffer, uint8_t n)
{
	uint16_t sample;
	uint16_t entropy;

	// Just assume each sample has 4 bits of entropy.
	// A better method would be to estimate it after running some statistical
	// tests (for example, estimating bias and bandwidth).
	entropy = (uint16_t)((uint16_t)n << 2);
	for (; n--; )
	{
		sample = adcSample();
		// Each sample is 10 bits. XOR the most-significant (MS) 2 bits into
		// the least-significant (LS) 2 bits. As long as they are not
		// significantly correlated, this shouldn't result in a decrease in
		// total entropy. Since the MS 2 bits and LS 2 bits are a factor of
		// 256 apart (in significance), this correlation should be minimal.
		buffer[n] = (uint8_t)((uint8_t)sample ^ (uint8_t)(sample >> 8));
	}
	return entropy;
}

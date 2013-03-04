/** \file adc.c
  *
  * \brief Driver for the LPC11Uxx's analog-to-digital converter (ADC).
  *
  * Analog-to-digital conversions are initiated by a timer, so that the rate
  * of conversions is about 22.05 kHz. This sample rate was chosen because
  * it's a "standard" audio sample rate, so most audio programs can handle
  * PCM data at that rate. It's slow enough that the code in fft.c can handle
  * real-time FFTs at that sample rate. Conversions are done with a fixed
  * period in between each conversion so that the results of FFTs are
  * meaningful.
  *
  * The results of conversions go into #adc_sample_buffer. To begin a series
  * of conversions, call beginFillingADCBuffer(), then wait
  * until #sample_buffer_full is true. #adc_sample_buffer will then
  * contain #SAMPLE_BUFFER_SIZE samples. This interface allows one buffer of
  * samples to be collected while the previous one is processed, which speeds
  * up entropy collection.
  *
  * For details on hardware interfacing requirements, see initADC().
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "../common.h"
#include "LPC11Uxx.h"
#include "adc.h"

/** A place to store samples from the ADC. When #sample_buffer_full is
  * true, every entry in this array will be filled with ADC samples
  * taken periodically. */
volatile uint16_t adc_sample_buffer[SAMPLE_BUFFER_SIZE];
/** Index into #sample_buffer where the next sample will be written. */
static volatile uint32_t sample_buffer_current_index;
/** Whether #sample_buffer is full.  */
volatile bool sample_buffer_full;

/** Set up ADC to sample from AD5 (pin 19 on mbed) periodically using the
  * 32-bit counter CT32B0. */
void initADC(void)
{
	LPC_SYSCON->SYSAHBCLKCTRL |= 0x12000; // enable clock to IOCON and ADC
	LPC_IOCON->PIO0_16 = 0x01; // set AD5 pin, analog mode, disable everything else
	LPC_SYSCON->PDRUNCFG &= ~0x10; // power up ADC
	// Select AD5, set divider = 24 (so ADC clock = 2 Mhz),
	// software-controlled mode, 10 bit accuracy, start on rising edge of
	// CT32B0_MAT0.
	LPC_ADC->CR = 0x04001820;
	LPC_ADC->INTEN = 0x20; // interrupt on AD5 conversion completion
	LPC_CT32B0->TCR = 0; // disable timer
	LPC_SYSCON->SYSAHBCLKCTRL |= 0x200; // enable clock to CT32B0
	LPC_CT32B0->PR = 63; // prescaler = 64
	LPC_CT32B0->MR0 = 17; // match = 17 (f = 44118 Hz)
	LPC_CT32B0->MCR = 2; // reset on MR0
	LPC_CT32B0->EMR = 0x30; // toggle CT32B0_MAT0 on match
	NVIC_EnableIRQ(24); // 24 = ADC interrupt
}

/** Interrupt handler that is called whenever an analog-to-digital conversion
  * is complete. */
void ADC_IRQHandler(void)
{
	uint32_t sample;

	// Always read DR5 so that the ADC interrupt is cleared.
	sample = (LPC_ADC->DR5 >> 6) & 0x3ff;
	if (sample_buffer_current_index >= SAMPLE_BUFFER_SIZE)
	{
		LPC_CT32B0->TCR = 0; // disable timer
		sample_buffer_full = true;
	}
	else
	{
		adc_sample_buffer[sample_buffer_current_index] = (uint16_t)sample;
		sample_buffer_current_index++;
	}
}

/** Begin collecting #SAMPLE_BUFFER_SIZE samples, filling
  * up #adc_sample_buffer. This will return before all the samples have been
  * collected, allowing the caller to do something else while samples are
  * collected in the background. #sample_buffer_full can be used to indicate
  * when #adc_sample_buffer is full.
  *
  * It is okay to call this while the sample buffer is still being filled up.
  * In that case, calling this will reset #sample_buffer_current_index so that
  * the sample buffer will commence filling from the start.
  */
void beginFillingADCBuffer(void)
{
	__disable_irq();
	sample_buffer_current_index = 0;
	sample_buffer_full = false;
	LPC_CT32B0->TCR = 1; // enable timer
	__enable_irq();
}

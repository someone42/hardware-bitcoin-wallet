/** \file adc.c
  *
  * \brief Driver for the PIC32's analog-to-digital converter (ADC).
  *
  * Analog-to-digital conversions are initiated by Timer3, so that the rate
  * of conversions is about 24 kHz. This sample rate was chosen because
  * it's a "standard" audio sample rate, so most audio programs can handle
  * PCM data at that rate. It's slow enough that the code in fft.c can handle
  * real-time FFTs at that sample rate. Conversions are done with a fixed
  * period in between each conversion so that the results of FFTs are
  * meaningful.
  *
  * The results of conversions are written into #adc_sample_buffer using DMA
  * transfers. To begin a series of conversions, call beginFillingADCBuffer(),
  * then wait until isADCBufferFull() returns
  * true. #adc_sample_buffer will then contain #ADC_SAMPLE_BUFFER_SIZE
  * samples. This interface allows one buffer of samples to be collected while
  * the previous one is processed, which speeds up entropy collection.
  *
  * For details on hardware interfacing requirements, see initADC().
  *
  * All references to the "PIC32 Family Reference Manual" refer to section 17,
  * revision E, obtained from
  * http://ww1.microchip.com/downloads/en/DeviceDoc/61104E.pdf
  * on 28 January 2013.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
#include <p32xxxx.h>
#include "adc.h"
#include "pic32_system.h"

/** A place to store samples from the ADC. When isADCBufferFull() returns
  * true, every entry in this array will be filled with ADC samples
  * taken periodically. */
volatile uint16_t adc_sample_buffer[ADC_SAMPLE_BUFFER_SIZE];

/** Set up the PIC32 ADC to sample from AN2 periodically using Timer3 as the
  * trigger. DMA is used to move the ADC result into #adc_sample_buffer. */
void initADC(void)
{
	// Initialise DMA module and DMA channel 0.
	// Why use DMA? DMA transfers will continue even when interrupts are
	// disabled, making sampling more robust (especially against USB
	// activity). DMA transfers also introduce less interference into the
	// signal, compared to using an interrupt service handler.
	DMACONbits.ON = 0; // disable DMA controller
	asm("nop"); // just to be safe
	IEC1bits.DMA0IE = 0; // disable DMA channel 0 interrupt
	IFS1bits.DMA0IF = 0; // clear DMA channel 0 interrupt flag
	DMACONbits.ON = 1; // enable DMA controller
	DMACONbits.SUSPEND = 0; // disable DMA suspend
	DCH0CON = 0;
	DCH0CONbits.CHPRI = 3; // priority = highest
	DCH0ECON = 0;
	DCH0ECONbits.CHSIRQ = _ADC_IRQ; // start transfer on ADC interrupt
	DCH0ECONbits.SIRQEN = 1; // start cell transfer on IRQ
	DCH0INTCLR = 0x00ff00ff; // clear existing events, disable all interrupts

	// Initialise ADC module.
	AD1CON1bits.ON = 0; // turn ADC module off
	asm("nop"); // just to be safe
	// This follows section 17.4 of the PIC32 family reference manual.
	AD1PCFGbits.PCFG2 = 0; // set AN2 pin to analog mode
	TRISBbits.TRISB2 = 1; // set RB2 as input (disable digital output)
	TRISCbits.TRISC13 = 1; // set RC13 as input (disable digital output)
	TRISCbits.TRISC14 = 1; // set RC14 as input (disable digital output)
	AD1CHSbits.CH0SA = 2; // select AN2 as MUX A positive source
	AD1CHSbits.CH0NA = 0; // select AVss as MUX a negative source
	AD1CON1bits.FORM = 4; // output format = 32 bit integer
	AD1CON1bits.SSRC = 2; // use Timer3 to trigger conversions
	AD1CON1bits.ASAM = 1; // enable automatic sampling
	AD1CON2bits.VCFG = 0; // use AVdd/AVss as references
	AD1CON2bits.CSCNA = 0; // disable scan mode
	AD1CON2bits.SMPI = 0; // 1 sample per interrupt
	AD1CON2bits.BUFM = 0; // single buffer mode
	AD1CON2bits.ALTS = 0; // disable alternate mode (always use MUX A)
	AD1CON3bits.ADRC = 0; // derive ADC conversion clock from PBCLK
	// Don't need to set SAMC since ADC is not in auto-convert (continuous)
	// mode.
	//AD1CON3bits.SAMC = 12; // sample time = 12 ADC conversion clocks
	AD1CON3bits.ADCS = 15; // ADC conversion clock = 2.25 MHz
	AD1CON1bits.SIDL = 1; // discontinue operation in idle mode
	AD1CON1bits.CLRASAM = 0; // don't clear ASAM; overwrite buffer contents
	AD1CON1bits.SAMP = 0; // don't start sampling immediately
	AD1CON2bits.OFFCAL = 0; // disable offset calibration mode
	AD1CON1bits.ON = 1; // turn ADC module on
	IFS1bits.AD1IF = 0; // clear interrupt flag
	IEC1bits.AD1IE = 0; // disable interrupt
	delayCycles(4 * CYCLES_PER_MICROSECOND); // wait 4 microsecond for ADC to stabilise

	// Initialise Timer3 to trigger ADC conversions.
	T3CONbits.ON = 0; // turn timer off
	T3CONbits.SIDL = 0; // continue operation in idle mode
	T3CONbits.TCKPS = 0; // 1:1 prescaler
	T3CONbits.TGATE = 0; // disable gated time accumulation
	T3CONbits.SIDL = 0; // continue in idle mode
	TMR3 = 0; // clear count
	PR3 = 1500; // frequency = 48000 Hz
	IFS0bits.T3IF = 0; // clear interrupt flag
	IEC0bits.T3IE = 0; // disable timer interrupt
	T3CONbits.ON = 1; // turn timer on
}

/** Begin collecting #ADC_SAMPLE_BUFFER_SIZE samples, filling
  * up #adc_sample_buffer. This will return before all the samples have been
  * collected, allowing the caller to do something else while samples are
  * collected in the background. isADCBufferFull() can be used to determine
  * when #adc_sample_buffer is full.
  *
  * It is okay to call this while the sample buffer is still being filled up.
  * In that case, calling this will abort the current fill and commence
  * filling from the start.
  */
void beginFillingADCBuffer(void)
{
	uint32_t status;

	status = disableInterrupts();
	DCH0CONbits.CHEN = 0; // disable channel
	asm("nop"); // just to be safe
	DCH0ECONbits.CABORT = 1; // abort any existing transfer and reset pointers
	// Delay a couple of cycles, just to be safe. DMA transfers are observed
	// to require up to 7 cycles (depending on source/destination alignment).
	asm("nop");
	asm("nop");
	asm("nop");
	asm("nop");
	asm("nop");
	asm("nop");
	asm("nop");
	asm("nop");
	DCH0ECONbits.CABORT = 0;
	DCH0INTCLR = 0x00ff00ff; // clear existing events, disable all interrupts
	DCH0SSA = VIRTUAL_TO_PHYSICAL(&ADC1BUF0); // transfer source physical address
	DCH0DSA = VIRTUAL_TO_PHYSICAL(&adc_sample_buffer); // transfer destination physical address
	DCH0SSIZ = sizeof(uint16_t); // source size
	DCH0DSIZ = sizeof(adc_sample_buffer); // destination size
	DCH0CSIZ = sizeof(uint16_t); // cell size (bytes transferred per event)
	DCH0CONbits.CHEN = 1; // enable channel
	restoreInterrupts(status);
}

/** Check whether ADC buffer (#adc_sample_buffer) is full.
  * \return false if ADC buffer is not full, true if it is.
  */
bool isADCBufferFull(void)
{
	if (DCH0INTbits.CHBCIF != 0)
	{
		return true;
	}
	else
	{
		return false;
	}
}

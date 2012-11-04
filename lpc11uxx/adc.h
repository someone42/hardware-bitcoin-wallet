/** \file adc.h
  *
  * \brief Describes functions, variables and constants exported by adc.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef LPC11UXX_ADC_H_INCLUDED
#define LPC11UXX_ADC_H_INCLUDED

#include "../fft.h" // for FFT_SIZE

/** Size of #sample_buffer, in number of samples.
  * \warning This must be a multiple of 16, or else hardwareRandom32Bytes()
  *          will attempt to read past the end of the sample buffer.
  */
#define SAMPLE_BUFFER_SIZE		(FFT_SIZE * 2)

extern volatile uint16_t adc_sample_buffer[SAMPLE_BUFFER_SIZE];
extern volatile int sample_buffer_full;

extern void initADC(void);
extern void beginFillingADCBuffer(void);

#endif // #ifndef LPC11UXX_ADC_H_INCLUDED

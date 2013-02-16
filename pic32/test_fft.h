/** \file test_fft.h
  *
  * \brief Describes functions exported by test_fft.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef PIC32_TEST_FFT_H_INCLUDED
#define PIC32_TEST_FFT_H_INCLUDED

#ifdef TEST_FFT
extern void __attribute__ ((nomips16)) testFFT(void);
#endif // #ifdef TEST_FFT

#endif // #ifndef PIC32_TEST_FFT_H_INCLUDED

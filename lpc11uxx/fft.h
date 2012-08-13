/** \file fft.h
  *
  * \brief Describes functions, constants and types exported by fft.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef LPC11UXX_FFT_H_INCLUDED
#define LPC11UXX_FFT_H_INCLUDED

#include <stdint.h>
#include "fix16.h"

/** The size of the FFT that fft() processes. If this value is changed, then
  * many things in fft.c need to be changed (those places are marked with
  * preprocessor checks).
  *
  * Since fft() does a complex FFT, this size refers to the size of the
  * FFT when the input is complex-valued. If the input is real-valued, then
  * fft() is capable of doing an FFT of twice this size. When doing a
  * real-valued FFT of twice this size, some post-processing is necessary;
  * see fftPostProcessReal() for more information.
  */
#define FFT_SIZE	256

/** A complex number, in Cartesian coordinates. Numbers are stored in
  * fixed-point format; see #fix16_t for details. */
typedef struct ComplexFixed_struct
{
	/** The real component of the complex number. */
	fix16_t real;
	/** The imaginary component of the complex number. */
	fix16_t imag;
} ComplexFixed;

extern int fft(ComplexFixed *data, int is_inverse);
extern int fftPostProcessReal(ComplexFixed *data, int is_inverse);

#endif // #ifndef LPC11UXX_FFT_H_INCLUDED

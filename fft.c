/** \file fft.c
  *
  * \brief Performs a Fast Fourier Transform (FFT).
  *
  * The ability to do a FFT is useful when testing a hardware random number
  * generator. The FFT and its inverse can be used to calculate the power
  * spectral density and autocorrelation of the generator's signal.
  *
  * Some implementation details:
  * - Real numbers are represented using fixed-point, because in typical
  *   embedded systems it's much faster, results in smaller code and is more
  *   reliable (don't have to worry about potentially buggy floating-point
  *   emulation).
  * - The FFT size is fixed by #FFT_SIZE. If the FFT size is changed, some
  *   parts of this file will also need to be modified.
  * - The use of lookup tables is minimised, resulting in smaller code at
  *   the expense of slightly slower speed.
  * - The aim was for the code to be fast enough so that the LPC11Uxx (running
  *   at 48 Mhz) microcontrollers be capable of performing size 512 real FFTs
  *   on a 22050 Hz bandwidth signal in real-time.
  * - Another aim was to have code size (including required fixed-point
  *   functions) be below 2 kilobytes on ARM Cortex-M0 microcontrollers.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "fix16.h"
#include "fft.h"

/** 3rd level of #R_DEF0 definition. */
#define R_DEF3(x)	x,			x + 8
/** 2nd level of #R_DEF0 definition. */
#define R_DEF2(x)	R_DEF3(x),	R_DEF3(x + 4)
/** 1st level of #R_DEF0 definition. */
#define R_DEF1(x)	R_DEF2(x),	R_DEF2(x + 2)
/** Recursively defined contents of #bit_reverse_lookup.
  * Inspired by http://graphics.stanford.edu/~seander/bithacks.html#ParityLookupTable
  * accessed 18-July-2012. */
#define R_DEF0(x)	R_DEF1(x),	R_DEF1(x + 1)

/** Bit reverse lookup table. Its contents are defined by recursively using
  * the C preprocessor. reverseBits() uses this to reverse groups of bits. */
static const uint8_t bit_reverse_lookup[16] =
{R_DEF0(0)};

#if FFT_SIZE != 256
#error "You may need to update twiddle_factor_lookup using gen_twiddle."
#endif
/** Lookup table of twiddle factors (complex roots of unity). This table is
  * just sin(phi), where phi is in [0, pi / 2). A full lookup table of twiddle
  * factors would need both sines and cosines for phi in [0, pi), needing 4
  * times as much space as this table. To recover the other values,
  * getTwiddleFactor() exploits various symmetries of the sine and cosine
  * functions.
  *
  * The sin(phi) values are multiplied by 65536 and rounded to the nearest
  * integer. This process assumes that the underlying fixed-point format
  * is Q16.16.
  *
  * Table generated using gen_twiddle.
  * FFT size: 512.
  */
const uint16_t twiddle_factor_lookup[128] = {
0x0000, 0x0324, 0x0648, 0x096c, 0x0c90, 0x0fb3, 0x12d5, 0x15f7,
0x1918, 0x1c38, 0x1f56, 0x2274, 0x2590, 0x28ab, 0x2bc4, 0x2edc,
0x31f1, 0x3505, 0x3817, 0x3b27, 0x3e34, 0x413f, 0x4447, 0x474d,
0x4a50, 0x4d50, 0x504d, 0x5348, 0x563e, 0x5932, 0x5c22, 0x5f0f,
0x61f8, 0x64dd, 0x67be, 0x6a9b, 0x6d74, 0x7049, 0x731a, 0x75e6,
0x78ad, 0x7b70, 0x7e2f, 0x80e8, 0x839c, 0x864c, 0x88f6, 0x8b9a,
0x8e3a, 0x90d4, 0x9368, 0x95f7, 0x9880, 0x9b03, 0x9d80, 0x9ff7,
0xa268, 0xa4d2, 0xa736, 0xa994, 0xabeb, 0xae3c, 0xb086, 0xb2c9,
0xb505, 0xb73a, 0xb968, 0xbb8f, 0xbdaf, 0xbfc7, 0xc1d8, 0xc3e2,
0xc5e4, 0xc7de, 0xc9d1, 0xcbbc, 0xcd9f, 0xcf7a, 0xd14d, 0xd318,
0xd4db, 0xd696, 0xd848, 0xd9f2, 0xdb94, 0xdd2d, 0xdebe, 0xe046,
0xe1c6, 0xe33c, 0xe4aa, 0xe610, 0xe76c, 0xe8bf, 0xea0a, 0xeb4b,
0xec83, 0xedb3, 0xeed9, 0xeff5, 0xf109, 0xf213, 0xf314, 0xf40c,
0xf4fa, 0xf5df, 0xf6ba, 0xf78c, 0xf854, 0xf913, 0xf9c8, 0xfa73,
0xfb15, 0xfbad, 0xfc3b, 0xfcc0, 0xfd3b, 0xfdac, 0xfe13, 0xfe71,
0xfec4, 0xff0e, 0xff4e, 0xff85, 0xffb1, 0xffd4, 0xffec, 0xfffb
};

/** Add two complex numbers.
  * \param op1 The first operand.
  * \param op2 The second operand.
  * \return The complex sum of op1 and op2 (op1 plus op2).
  */
static ComplexFixed complexFixedAdd(ComplexFixed op1, ComplexFixed op2)
{
	ComplexFixed r;

	r.real = fix16_add(op1.real, op2.real);
	r.imag = fix16_add(op1.imag, op2.imag);
	return r;
}

/** Subtract two complex numbers.
  * \param op1 The first operand.
  * \param op2 The second operand.
  * \return The complex difference of op1 and op2 (op1 minus op2).
  */
static ComplexFixed complexFixedSubtract(ComplexFixed op1, ComplexFixed op2)
{
	ComplexFixed r;

	r.real = fix16_sub(op1.real, op2.real);
	r.imag = fix16_sub(op1.imag, op2.imag);
	return r;
}

/** Multiply two complex numbers.
  * \param op1 The first operand.
  * \param op2 The second operand.
  * \return The complex multiplication of op1 and op2 (op1 times op2).
  */
static ComplexFixed complexFixedMultiply(ComplexFixed op1, ComplexFixed op2)
{
	ComplexFixed r;

	r.real = fix16_sub(fix16_mul(op1.real, op2.real), fix16_mul(op1.imag, op2.imag));
	r.imag = fix16_add(fix16_mul(op1.real, op2.imag), fix16_mul(op1.imag, op2.real));
	return r;
}

/** Get the complex conjugate of a complex number.
  * \param op1 The operand.
  * \return The complex conjugate of op1.
  */
static ComplexFixed complexFixedConjugate(ComplexFixed op1)
{
	ComplexFixed r;

	r.real = op1.real;
	r.imag = fix16_sub(fix16_zero, op1.imag);
	return r;
}

/** Reverse the bits in an integer. For example, 0x59 (0b01011001) becomes
  * 0x9A (0b10011010).
  * \param op1 The integer to reverse.
  * \return The integer, with bits reversed.
  * \warning The implementation of this function depends on #FFT_SIZE.
  *          If #FFT_SIZE is changed, the code for this function will also
  *          need to be changed.
  */
static uint32_t reverseBits(uint32_t op1)
{
#if FFT_SIZE != 256
#error "You may need to update reverseBits()."
#endif
	return ((bit_reverse_lookup[op1 & 15] << 4)
		+ bit_reverse_lookup[(op1 >> 4) & 15]);
}

/** Get the complex twiddle factor (complex root of unity) for a given angle.
  * This function uses the lookup table #twiddle_factor_lookup and complements
  * it with trigonometric symmetries.
  * \param tf_index The angle, in radian * FFT_SIZE / (2 * pi). This parameter
  *                 is range-checked.
  * \return The complex twiddle factor.
  */
static ComplexFixed getTwiddleFactor(uint32_t tf_index)
{
	ComplexFixed r;
	uint32_t first_quadrant_tf_index;

	if (tf_index > FFT_SIZE)
	{
		// tf_index too large.
		r.real = fix16_zero;
		r.imag = fix16_zero;
		fix16_error_occurred = true;
		return r;
	}
	// tf_index must now be in [0, FFT_SIZE].
	first_quadrant_tf_index = tf_index;
	if (tf_index > (FFT_SIZE / 2))
	{
		// sin(pi - phi) = sin(phi).
		first_quadrant_tf_index = FFT_SIZE - first_quadrant_tf_index;
	}
	// first_quadrant_tf_index must now be in [0, FFT_SIZE / 2].
	if (first_quadrant_tf_index == 0)
	{
		r.real = fix16_one;
		r.imag = fix16_zero;
	}
	else if (first_quadrant_tf_index == (FFT_SIZE / 2))
	{
		r.real = fix16_zero;
		r.imag = fix16_one;
	}
	else
	{
		// cos(phi) = sin(pi / 2 - phi)
		r.real = twiddle_factor_lookup[(FFT_SIZE / 2) - first_quadrant_tf_index];
		r.imag = twiddle_factor_lookup[first_quadrant_tf_index];
	}
	if (tf_index > (FFT_SIZE / 2))
	{
		// cos(pi - phi) = -cos(phi).
		r.real = fix16_sub(fix16_zero, r.real);
	}

	return r;
}

/** Perform a complex, in-place Fast Fourier Transform using the radix-2
  * Cooley-Tukey algorithm.
  * This does a complex FFT of size #FFT_SIZE. If the input data is purely
  * real, this can do a real FFT of size #FFT_SIZE * 2, but that requires
  * some post-processing. See fftRealPostProcess() for more details.
  *
  * The code was heavily inspired by Sergey Chernenko's FFT code, available
  * from http://www.librow.com/articles/article-10, accessed 18-July-2012.
  * Like Sergey's code, no recursion is used. Some changes:
  * - A lookup table for twiddle factors (see getTwiddleFactor()) is used
  *   instead of a trigonometric recurrence relation. This gives better
  *   numerical performance, at little space cost.
  * - If the twiddle factor is 1, no multiplication is done. For a size
  *   512 complex FFT, this removes 12.5% of the multiplications, at little
  *   space cost.
  *
  * \param data The input data array. The output of the FFT will also be
  *             written here. This must be an array of size #FFT_SIZE.
  * \param is_inverse Whether to perform an inverse FFT instead of a forward
  *                   FFT.
  * \return false for success, true if an arithmetic error (eg. overflow)
  *         occurred.
  */
bool fft(ComplexFixed *data, bool is_inverse)
{
	uint32_t i;
	uint32_t j;
	uint32_t pair;
	uint32_t jump;
	uint32_t match;
	uint32_t tf_index; // twiddle factor index
	uint32_t tf_step; // twiddle factor index increment
	ComplexFixed factor; // twiddle factor
	ComplexFixed product;
	ComplexFixed temp;

	fix16_error_occurred = false;

	// Do in-place input data reordering.
	for (i = 0; i < FFT_SIZE; i++)
	{
		j = reverseBits(i);
		if (j > i) // only swap if not already swapped
		{
			temp = data[i];
			data[i] = data[j];
			data[j] = temp;
		}
	}

	// Perform the actual FFT calculation.
	tf_step = FFT_SIZE;
	for (i = 1; i < FFT_SIZE; i <<= 1)
	{
		jump = i << 1;
		tf_index = 0;
		for (j = 0; j < i; j++)
		{
			factor = getTwiddleFactor(tf_index);
			if (!is_inverse)
			{
				factor = complexFixedConjugate(factor);
			}
			for (pair = j; pair < FFT_SIZE; pair += jump)
			{
				match = pair + i;
				if (tf_index == 0)
				{
					// Save multiplications since factor = 1.0.
					product = data[match];
				}
				else
				{
					product = complexFixedMultiply(factor, data[match]);
				}
				data[match] = complexFixedSubtract(data[pair], product);
				data[pair] = complexFixedAdd(data[pair], product);
			}
			tf_index += tf_step;
		}
		tf_step >>= 1;
	} // end for (i = 1; i < FFT_SIZE; i <<= 1)

	if (is_inverse)
	{
		// Need to rescale output.
		for (i = 0; i < FFT_SIZE; i++)
		{
			data[i].real = fix16_mul(data[i].real, FIX16_RECIPROCAL_OF(FFT_SIZE));
			data[i].imag = fix16_mul(data[i].imag, FIX16_RECIPROCAL_OF(FFT_SIZE));
		}
	}

	return fix16_error_occurred;
}

/** Post-process the results of a complex FFT to get the results of a real FFT
  * of twice the size. To do a real FFT:
  * - Place even entries of the real input data into the real components of
  *   the complex input data,
  * - Place odd entries of the real input data into the imaginary components
  *   of the complex input data,
  * - Call fft() to perform the FFT,
  * - Call this function to post-process the output of fft().
  *
  * The final output of this function should look like the output of a real
  * FFT of size 2 * #FFT_SIZE. However, since this function operates on the
  * data in-place, the output will be truncated after the Nyquist bin. This
  * is no loss because the output of a real FFT has Hermitian symmetry.
  *
  * The code for this function was heavily inspired by the "realbifftstage()"
  * function from http://www.katjaas.nl/realFFT/realFFT2.html, accessed 4
  * August 2012.
  *
  * \param data The data array which fft() has operated on. This must be an
  *             array of size #FFT_SIZE + 1.
  * \param is_inverse Whether to perform an inverse FFT instead of a forward
  *                   FFT.
  * \return false for success, true if an arithmetic error (eg. overflow)
  *         occurred.
  * \warning The size of the data array must be #FFT_SIZE + 1, not #FFT_SIZE,
  *          because this function requires one extra entry for the Nyquist
  *          frequency bin.
  */
bool fftPostProcessReal(ComplexFixed *data, bool is_inverse)
{
	uint32_t i;
	uint32_t j;
	fix16_t real_sum;
	fix16_t imag_diff;
	fix16_t temp;
	ComplexFixed twiddled;
	ComplexFixed twiddle_factor;

	fix16_error_occurred = false;

	// Split the real and imaginary spectra.
	i = FFT_SIZE / 2;
	j = FFT_SIZE / 2;
	while (i != 0)
	{
		real_sum = fix16_add(data[i].real, data[j].real);
		twiddled.real = fix16_sub(data[i].real, data[j].real); // real_diff
		twiddled.imag = fix16_add(data[i].imag, data[j].imag); // imag_sum
		imag_diff = fix16_sub(data[i].imag, data[j].imag);
		// Since the input is the result of a FFT of size FFT_SIZE and we want
		// a FFT of size FFT_SIZE * 2, additional twiddling is necessary.
		twiddle_factor = getTwiddleFactor(i);
		if (!is_inverse)
		{
			twiddle_factor = complexFixedConjugate(twiddle_factor);
		}
		twiddled = complexFixedMultiply(twiddled, twiddle_factor);
		data[i].real = fix16_mul(fix16_add(real_sum, twiddled.imag), FIX16_RECIPROCAL_OF(2));
		data[i].imag = fix16_mul(fix16_sub(imag_diff, twiddled.real), FIX16_RECIPROCAL_OF(2));
		data[j].real = fix16_mul(fix16_sub(real_sum, twiddled.imag), FIX16_RECIPROCAL_OF(2));
		data[j].imag = fix16_mul(fix16_add(twiddled.real, imag_diff), FIX16_RECIPROCAL_OF(2));
		data[j] = complexFixedConjugate(data[j]);
		i--;
		j++;
	}

	// Fix up DC and Nyquist bins.
	temp = data[0].real;
	data[0].real = fix16_add(temp, data[0].imag);
	data[FFT_SIZE].real = fix16_sub(temp, data[0].imag);
	data[0].imag = fix16_zero;
	data[FFT_SIZE].imag = fix16_zero;

	if (is_inverse)
	{
		for (i = 0; i < (FFT_SIZE + 1); i++)
		{
			data[i].real = fix16_mul(data[i].real, FIX16_RECIPROCAL_OF(2));
			data[i].imag = fix16_mul(data[i].imag, FIX16_RECIPROCAL_OF(2));
		}
	}

	return fix16_error_occurred;
}



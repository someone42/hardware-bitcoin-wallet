/** \file statistics.h
  *
  * \brief Describes functions and constants exported by statistics.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef LPC11UXX_STATISTICS_H_INCLUDED
#define LPC11UXX_STATISTICS_H_INCLUDED

#include "fix16.h"

/** Number of bins for histogram buffer. This should be large enough that
  * every possible ADC value can be placed in a separate bin. Since the
  * LPC11Uxx microcontrollers have a 10-bit ADC, this is 2 ^ 10.
  */
#define HISTOGRAM_NUM_BINS			1024
/** Number of bits of storage space allocated to each histogram bin. The
  * maximum value of each bin is limited by this, so this should be
  * large enough to store the maximum expected histogram count.
  */
#define	BITS_PER_HISTOGRAM_BIN		11

/** Number of samples to take before running statistical tests.
  * \warning This must be a multiple of #FFT_SIZE * 2, so that a FFT can be
  *          performed on all samples.
  */
#define SAMPLE_COUNT				4096
/** Scale-down factor to apply to sample values so that overflow doesn't occur
  * in statistical tests. This can't be too small or overflow will occur, but
  * it can't be too big or fixed-point rounding errors will be significant.
  * \warning This must be a power of 2, because the #FIX16_RECIPROCAL_OF
  *          macro is used to replace division with multiplication.
  */
#define SAMPLE_SCALE_DOWN			64

#ifdef TEST_STATISTICS
extern void testStatistics(void);
#endif // #ifdef TEST_STATISTICS

#endif // #ifndef LPC11UXX_STATISTICS_H_INCLUDED

/** \file statistics.c
  *
  * \brief Calculates statistical properties.
  *
  * The functions in this file calculate statistical properties such as the
  * mean and variance. These properties can be used to assess the quality of
  * a hardware random number generator (HWRNG). Since the implementation of a
  * HWRNG is highly platform-dependent, these functions only calculate
  * statistical properties; they do not interpret them.
  *
  * Some implementation details:
  * - Real numbers are represented using fixed-point, because in typical
  *   embedded systems it's much faster, results in smaller code and is more
  *   reliable (don't have to worry about potentially buggy floating-point
  *   emulation).
  * - Some (RAM) space efficiency is achieved by storing samples in a
  *   histogram (see #packed_histogram_buffer), instead of storing them in a
  *   FIFO buffer.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "fix16.h"
#include "fft.h"
#include "statistics.h"

/** The maximum number of counts which can be held in one histogram bin. */
#define MAX_HISTOGRAM_VALUE			((1 << BITS_PER_HISTOGRAM_BIN) - 1)

/** The buffer where histogram counts are stored. The buffer needs to be
  * persistent, because counts are accumulated across many calls to
  * hardwareRandom32Bytes(). In order to conserve valuable RAM, the buffer is
  * bit-packed.
  *
  * A histogram is much more space-efficient than storing a buffer of
  * individual samples, since (for the calculation of most statistical
  * properties) the order of samples doesn't matter. Each bin represents a
  * value, and each bin has an associated count, which represents how many
  * times that value occurred.
  */
static uint32_t packed_histogram_buffer[((HISTOGRAM_NUM_BINS * BITS_PER_HISTOGRAM_BIN) / 32) + 1];

/** An estimate of the power spectral density of the HWRNG. As more samples
  * are collected, FFT results will be accumulated here. The more samples,
  * the more accurate the estimate will be.
  */
fix16_t psd_accumulator[FFT_SIZE + 1];

/** This will be true if there was an arithmetic error in the calculation
  * of power spectral density (see #psd_accumulator). This will be false if
  * there haven't been any arithmetic errors so far.
  */
bool psd_accumulator_error_occurred;

/** This will be set to true if one of the histogram bins overflows. */
bool histogram_overflow_occurred;
/** Number of samples that have been placed in the histogram. */
uint32_t samples_in_histogram;
/** The index (bin number) into the histogram buffer where the histogram
  * iterator is currently at. */
static uint32_t iterator_index;
/** The count within a histogram bin where the histogram iterator is currently
  * at. */
static uint32_t iterator_count;
/** Cached value of histogram counts in the bin specified by #iterator_index.
  * This is used to speed up getTermFromIterator(). */
static uint32_t cached_histogram_count;
/** Cached value of scaled sample value for the bin specified
  * by #iterator_index. This is used to speed up getTermFromIterator(). */
static fix16_t cached_scaled_sample;

/** Reset all histogram counts to 0. */
void clearHistogram(void)
{
	memset(packed_histogram_buffer, 0, sizeof(packed_histogram_buffer));
	samples_in_histogram = 0;
	histogram_overflow_occurred = false;
}

/** Gets an entry from the histogram counts buffer.
  * \param index The histogram bin to query.
  * \return The number of counts in the specified bin.
  */
static uint32_t getHistogram(uint32_t index)
{
	uint32_t bit_index;
	uint32_t word_index;
	uint32_t shift_amount;
	uint32_t r;

	if (index >= HISTOGRAM_NUM_BINS)
	{
		// This should never happen.
		fix16_error_occurred = true;
		return 0;
	}
	bit_index = index * BITS_PER_HISTOGRAM_BIN;
	word_index = bit_index >> 5;
	bit_index = bit_index & 31;
	r = packed_histogram_buffer[word_index] >> bit_index;
	r &= MAX_HISTOGRAM_VALUE;
	if ((bit_index + BITS_PER_HISTOGRAM_BIN) > 32)
	{
		// Entry straddles uint32_t boundary.
		shift_amount = 32 - bit_index;
		r |= packed_histogram_buffer[word_index + 1] << shift_amount;
		r &= MAX_HISTOGRAM_VALUE;
	}

	return r;
}

/** Sets an entry in the histogram counts buffer.
  * \param index The histogram bin to set.
  * \param value The number of counts to set the bin to.
  */
static void putHistogram(uint32_t index, uint32_t value)
{
	uint32_t bit_index;
	uint32_t word_index;
	uint32_t mask;
	uint32_t shift_amount;

	if (index >= HISTOGRAM_NUM_BINS)
	{
		// This should never happen.
		fix16_error_occurred = true;
		return;
	}
	if (value > MAX_HISTOGRAM_VALUE)
	{
		// Overflow in one of the bins.
		histogram_overflow_occurred = true;
		return;
	}
	bit_index = index * BITS_PER_HISTOGRAM_BIN;
	word_index = bit_index >> 5;
	bit_index = bit_index & 31;
	mask = MAX_HISTOGRAM_VALUE << bit_index;
	packed_histogram_buffer[word_index] &= (~mask);
	packed_histogram_buffer[word_index] |= (value << bit_index);
	if ((bit_index + BITS_PER_HISTOGRAM_BIN) > 32)
	{
		// Entry straddles uint32_t boundary.
		shift_amount = 32 - bit_index;
		word_index++;
		mask = (1 << (BITS_PER_HISTOGRAM_BIN - shift_amount)) - 1;
		packed_histogram_buffer[word_index] &= (~mask);
		packed_histogram_buffer[word_index] |= (value >> shift_amount);
	}
}

/** Increments the count of a histogram bin.
  * \param index The histogram bin to modify.
  */
void incrementHistogram(uint32_t index)
{
	putHistogram(index, getHistogram(index) + 1);
	samples_in_histogram++;
}

/** Apply scaling and an offset to ADC sample values so that overflow will
  * be less likely to occur in statistical calculations.
  * \param sample_int The ADC sample number.
  * \return The scaled sample value.
  */
fix16_t scaleSample(int sample_int)
{
	fix16_t r;

	sample_int -= (HISTOGRAM_NUM_BINS / 2); // centre ADC range on 0.0
	r = fix16_from_int(sample_int);
	r = fix16_mul(r, FIX16_RECIPROCAL_OF(SAMPLE_SCALE_DOWN));
	return r;
}

/** This must be called whenever the iterator is active and #iterator_index
  * changes. */
static void updateIteratorCache(void)
{
	cached_histogram_count = getHistogram(iterator_index);
	cached_scaled_sample = scaleSample((int)iterator_index);
}

/** Reset the histogram iterator back to the start. */
static void resetIterator(void)
{
	iterator_index = 0;
	iterator_count = 0;
	updateIteratorCache();
}

/** Uses an iterator over the histogram to obtain one term in a central
  * moment calculation. The iterator goes over each item (count) from each
  * histogram bin (index).
  * \param mean The mean to calculate the central moment about.
  * \param power Which central moment to calculate (1 = first, 2 = second
  *              etc.). This must be positive and non-zero.
  * \return One term for the calculation of the specified central moment.
  */
static fix16_t getTermFromIterator(fix16_t mean, uint32_t power)
{
	uint32_t i;
	fix16_t scaled_sample;
	fix16_t r;

	// Search for the index (bin number) of the next count.
	while (iterator_count >= cached_histogram_count)
	{
		iterator_count = 0;
		iterator_index++;
		if (iterator_index >= HISTOGRAM_NUM_BINS)
		{
			// Iterator ran past end of samples. This should never happen.
			fix16_error_occurred = true;
			return fix16_zero;
		}
		updateIteratorCache();
	}

	iterator_count++;
	scaled_sample = fix16_sub(cached_scaled_sample, mean);
	r = scaled_sample;
	for (i = 1; i < power; i++)
	{
		r = fix16_mul(r, scaled_sample);
	}
	return r;
}

/** Recursive handler for calculateCentralMoment(). Recursion is used to do
  * pairwise averaging. Pairwise averaging is just like pairwise summation,
  * except there's a divide by 2 after each sum.
  * Why do pairwise averaging? So that overflow is less likely to occur.
  * \param mean The mean to calculate the central moment about.
  * \param power Which central moment to calculate (1 = first, 2 = second
  *              etc.).
  * \param level The number of terms to use in the estimation of the central
  *              moment.
  * \return An estimate of the value of the specified central moment.
  */
static fix16_t calculateCentralMomentRecursive(fix16_t mean, uint32_t power, uint32_t level)
{
	fix16_t term1;
	fix16_t term2;

	if (level <= 2)
	{
		term1 = getTermFromIterator(mean, power);
		term2 = getTermFromIterator(mean, power);
	}
	else
	{
		term1 = calculateCentralMomentRecursive(mean, power, level >> 1);
		term2 = calculateCentralMomentRecursive(mean, power, level >> 1);
	}
	return fix16_mul(fix16_add(term1, term2), FIX16_RECIPROCAL_OF(2));
}

/** Examines the histogram and calculates a central moment from it. This does
  * require the mean to be known. If the mean is not known, it can be
  * calculated using this function by passing mean = 0.0 and power = 1.
  * \param mean The mean to calculate the central moment about.
  * \param power Which central moment to calculate (1 = first, 2 = second
  *              etc.).
  * \return The value of the specified central moment
  */
fix16_t calculateCentralMoment(fix16_t mean, uint32_t power)
{
	resetIterator();
	return calculateCentralMomentRecursive(mean, power, SAMPLE_COUNT);
}

/** Obtains an estimate of the (Shannon) entropy per sample, based on the
  * histogram.
  * \return The value of the estimate, in bits per sample.
  */
fix16_t estimateEntropy(void)
{
	uint32_t i;
	fix16_t sum;
	fix16_t term;
	fix16_t log_term;

	// Definition of (Shannon) entropy: H(X) = sum(-p(x_i) * log(p(x_i))).
	sum = fix16_zero;
	for (i = 0; i < HISTOGRAM_NUM_BINS; i++)
	{
		term = fix16_from_int(getHistogram(i));
		if (term != fix16_zero)
		{
			term = fix16_mul(term, FIX16_RECIPROCAL_OF(SAMPLE_COUNT));
			log_term = fix16_log2(term);
			term = fix16_mul(term, log_term);
			sum = fix16_sub(sum, term);
		}
	}
	return sum;
}

/** Subtract the mean off every input value in a FFT buffer. Both real and
  * imaginary components are considered in the calculation of the mean, and
  * both real and imaginary components are affected by the subtraction. Thus
  * this function is intended to be used with double-sized real FFTs.
  * \param fft_buffer The array of FFT input values. This must be large
  *                   enough to hold #FFT_SIZE complex values.
  */
void subtractMeanFromFftBuffer(ComplexFixed *fft_buffer)
{
	uint32_t i;
	fix16_t fft_mean;

	fft_mean = fix16_zero;
	for (i = 0; i < FFT_SIZE; i++)
	{
		fft_mean = fix16_add(fft_mean, fft_buffer[i].real);
		fft_mean = fix16_add(fft_mean, fft_buffer[i].imag);
	}
	fft_mean = fix16_mul(fft_mean, FIX16_RECIPROCAL_OF(FFT_SIZE * 2));
	for (i = 0; i < FFT_SIZE; i++)
	{
		fft_buffer[i].real = fix16_sub(fft_buffer[i].real, fft_mean);
		fft_buffer[i].imag = fix16_sub(fft_buffer[i].imag, fft_mean);
	}
}

/** Set power spectral density estimate to all zeroes. */
void clearPowerSpectralDensity(void)
{
	memset(psd_accumulator, 0, sizeof(psd_accumulator));
	psd_accumulator_error_occurred = false;
}

/** Calculate (an estimate of) the power spectral density of a bunch of
  * time-domain samples. The result will be accumulated in #psd_accumulator.
  * \param source_buffer The array of time-domain samples to calculate the
  *                      power spectral density estimate of. This must have
  *                      exactly #FFT_SIZE * 2 entries in it.
  */
void accumulatePowerSpectralDensity(volatile uint16_t *source_buffer)
{
	uint32_t i;
	uint32_t index;
	fix16_t scaled_sample;
	fix16_t term1;
	fix16_t term2;
	fix16_t sum_of_squares;
	ComplexFixed fft_buffer[FFT_SIZE + 1];

	// Fill FFT buffer with entire contents of ADC sample data.
	// Real/imaginary interleaving is done to allow a double-size real
	// FFT to be performed; see fftPostProcessReal() for more details.
	for (i = 0; i < (FFT_SIZE * 2); i++)
	{
		index = i >> 1;
		scaled_sample = scaleSample((int)source_buffer[i]);
		if ((i & 1) == 0)
		{
			fft_buffer[index].real = scaled_sample;
		}
		else
		{
			fft_buffer[index].imag = scaled_sample;
		}
	}

	// Before computing the FFT, the mean of the FFT buffer is subtracted
	// out. This is because we're not interested in the DC component of
	// the FFT result (testing the sample mean is done elsewhere in this
	// file). Almost the same thing could be accomplished by ignoring
	// fft_buffer[0] in the PSD accumulation loop, but pre-subtraction
	// reduces the chance of overflow occurring.
	subtractMeanFromFftBuffer(fft_buffer);
	if (fft(fft_buffer, false))
	{
		psd_accumulator_error_occurred = true;
	}
	if (fftPostProcessReal(fft_buffer, false))
	{
		psd_accumulator_error_occurred = true;
	}
	fix16_error_occurred = false;
	for (i = 0; i < (FFT_SIZE + 1); i++)
	{
		// Rescale terms to make overflow less likely when squaring them.
		term1 = fix16_mul(fft_buffer[i].real, FIX16_RECIPROCAL_OF(8));
		term1 = fix16_mul(term1, term1);
		term2 = fix16_mul(fft_buffer[i].imag, FIX16_RECIPROCAL_OF(8));
		term2 = fix16_mul(term2, term2);
		sum_of_squares = fix16_add(term1, term2);
		// PSD is scaled down according to the number of samples. This
		// will normalise the result, since total power scales as the
		// number of samples.
		// Since FIX16_RECIPROCAL_OF expects an integer, SAMPLE_COUNT must
		// be >= 512.
#if SAMPLE_COUNT < 512
#error "SAMPLE_COUNT too small (it's < 512)"
#endif // #if SAMPLE_COUNT < 512
		sum_of_squares = fix16_mul(sum_of_squares, FIX16_RECIPROCAL_OF(SAMPLE_COUNT / 512));
		psd_accumulator[i] = fix16_add(psd_accumulator[i], sum_of_squares);
	}
	if (fix16_error_occurred)
	{
		psd_accumulator_error_occurred = true;
	}
}

/** Calculate the (cyclic) autocorrelation by using the power spectral density
  * estimate (#psd_accumulator).
  * \param fft_buffer The result of the autocorrelation computation will be
  *                   written here.
  * \return false if the calculation completed successfully, true if there was
  *         some arithmetic error.
  */
bool calculateAutoCorrelation(ComplexFixed *fft_buffer)
{
	fix16_t sample;
	uint32_t i;
	uint32_t fft_index;
	uint32_t psd_index;

	psd_index = 0;
	for (i = 0; i < (FFT_SIZE * 2); i++)
	{
		sample = psd_accumulator[psd_index];
		fft_index = i >> 1;
		if ((i & 1) == 0)
		{
			fft_buffer[fft_index].real = sample;
		}
		else
		{
			fft_buffer[fft_index].imag = sample;
		}
		if (i < FFT_SIZE)
		{
			psd_index++;
		}
		else
		{
			psd_index--;
		}
	}

	if (fft(fft_buffer, true))
	{
		return true;
	}
	if (fftPostProcessReal(fft_buffer, true))
	{
		return true;
	}
	return false;
}

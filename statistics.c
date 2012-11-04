/** \file statistics.c
  *
  * \brief Calculates and compares statistical properties of HWRNG samples.
  *
  * Why bother going to all the trouble to test the hardware random number
  * generator (HWRNG)? Many cryptographic operations (eg. signing, wallet
  * seed generation) depend on the quality of their entropy source. Hardware
  * failure could compromise a HWRNG's quality. The tests in this file aim
  * to test for hardware failure. The tests will not detect every failure
  * and will not detect intentional tampering (although they make such
  * tampering more difficult). The assumption made here is that the HWRNG is
  * a white Gaussian noise source.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "../common.h"
#include <stdint.h>
#include <string.h>
#include "fix16.h"
#include "fft.h"
#include "statistics.h"
#include "adc.h"

#ifdef TEST_STATISTICS
#include "ssd1306.h"
#include "../endian.h"
#include "../hwinterface.h"
#include "LPC11Uxx.h"

static void reportStatistics(uint32_t tests_failed);
static void reportFftResults(ComplexFixed *fft_buffer);

// These are copies of some variables in histogramTestsFailed() and
// fftTestsFailed() which are reported by reportStatistics().
static fix16_t most_recent_mean;
static fix16_t most_recent_variance;
static fix16_t most_recent_kappa3;
static fix16_t most_recent_kappa4;
static int most_recent_max_bin;
static int most_recent_bandwidth;
static fix16_t most_recent_max_autocorrelation;
static fix16_t most_recent_entropy_estimate;

/** Set to non-zero to send statistical properties to stream. 1 = moment-based
  * statistical properties, 2 = power spectral density estimate, 3 = bandwidth
  * estimate, 4 = autocorrelation results, 5 = maximum autocorrelation value
  * and entropy estimate. */
static int report_to_stream;
#endif // #ifdef TEST_STATISTICS

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
static fix16_t psd_accumulator[FFT_SIZE + 1];

/** This will be non-zero if there was an arithmetic error in the calculation
  * of power spectral density (see #psd_accumulator). This will be zero if
  * there haven't been any arithmetic errors so far.
  */
static uint8_t psd_accumulator_error;

/** This is normally 0, but it will be set to non-zero if one of the histogram
  * bins overflowed. */
static int histogram_overflow;
/** Number of samples that have been placed in the histogram. */
static uint32_t samples_in_histogram;
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


/** This will be zero if the next sample to be returned by
  * hardwareRandom32Bytes() is the first sample to be placed in a histogram
  * bin. This will be non-zero if that next sample is not the first
  * sample to be placed in a histogram bin. This variable was defined in
  * that way so that it is initially 0.
  */
static int is_not_first_in_histogram;
/** Number of samples in the sample buffer that hardwareRandom32Bytes() has
  * used up. */
static uint32_t sample_buffer_consumed;

/** Reset all histogram counts to 0. */
static void clearHistogram(void)
{
	memset(packed_histogram_buffer, 0, sizeof(packed_histogram_buffer));
	samples_in_histogram = 0;
	histogram_overflow = 0;
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
		fix16_error_flag = 1;
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
		fix16_error_flag = 1;
		return;
	}
	if (value > MAX_HISTOGRAM_VALUE)
	{
		// Overflow in one of the bins.
		histogram_overflow = 1;
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
static void incrementHistogram(uint32_t index)
{
	putHistogram(index, getHistogram(index) + 1);
	samples_in_histogram++;
}

/** Apply scaling and an offset to ADC sample values so that overflow will
  * be less likely to occur in statistical calculations.
  * \param sample_int The ADC sample number.
  * \return The scaled sample value.
  */
static fix16_t scaleSample(int sample_int)
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
			fix16_error_flag = 1;
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
static fix16_t calculateCentralMoment(fix16_t mean, uint32_t power)
{
	resetIterator();
	return calculateCentralMomentRecursive(mean, power, SAMPLE_COUNT);
}

/** Subtract the mean off every input value in a FFT buffer. Both real and
  * imaginary components are considered in the calculation of the mean, and
  * both real and imaginary components are affected by the subtraction. Thus
  * this function is intended to be used with double-sized real FFTs.
  * \param fft_buffer The array of FFT input values. This must be large
  *                   enough to hold #FFT_SIZE complex values.
  */
static void subtractMean(ComplexFixed *fft_buffer)
{
	uint32_t i;
	fix16_t fft_mean;

	fft_mean = fix16_zero;
	for (i = 0; i < FFT_SIZE; i++)
	{
		fft_mean = fix16_add(fft_mean, fft_buffer[i].real);
		fft_mean = fix16_add(fft_mean, fft_buffer[i].imag);
	}
	fft_mean = fix16_mul(fft_mean, FIX16_RECIPROCAL_OF(SAMPLE_BUFFER_SIZE));
	for (i = 0; i < FFT_SIZE; i++)
	{
		fft_buffer[i].real = fix16_sub(fft_buffer[i].real, fft_mean);
		fft_buffer[i].imag = fix16_sub(fft_buffer[i].imag, fft_mean);
	}
}

/** Obtains an estimate of the (Shannon) entropy per sample, based on the
  * histogram.
  * \return The value of the estimate.
  */
static fix16_t estimateEntropy(void)
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

/** Obtains an estimate of the bandwidth of the HWRNG, based on the power
  * spectrum density estimate (see #psd_accumulator).
  * \param out_max_bin Pointer to variable which will receive the bin number
  *                    of the peak value in the power spectrum.
  * \return The bandwidth, in number of FFT bins.
  */
static int estimateBandwidth(int *out_max_bin)
{
	int i;
	fix16_t threshold;
	int max_bin;
	int left_bin;
	int right_bin;
	int below_counter;

	threshold = fix16_zero;
	max_bin = 0;
	for (i = 0; i < (FFT_SIZE + 1); i++)
	{
		if (psd_accumulator[i] > threshold)
		{
			threshold = psd_accumulator[i];
			max_bin = i;
		}
	}
	threshold = fix16_mul(threshold, F16(PSD_BANDWIDTH_THRESHOLD));

	// Search for left edge.
	below_counter = 0;
	left_bin = 0;
	for (i = max_bin; i >= 0; i--)
	{
		if (psd_accumulator[i] < threshold)
		{
			below_counter++;
		}
		else
		{
			below_counter = 0;
		}
		if (below_counter >= PSD_THRESHOLD_REPETITIONS)
		{
			left_bin = i + PSD_THRESHOLD_REPETITIONS;
			break;
		}
	}
	// Search for right edge.
	below_counter = 0;
	right_bin = FFT_SIZE;
	for (i = max_bin; i < (FFT_SIZE + 1); i++)
	{
		if (psd_accumulator[i] < threshold)
		{
			below_counter++;
		}
		else
		{
			below_counter = 0;
		}
		if (below_counter >= PSD_THRESHOLD_REPETITIONS)
		{
			right_bin = i - PSD_THRESHOLD_REPETITIONS;
			break;
		}
	}
	*out_max_bin = max_bin;
	return right_bin - left_bin;
}

/** Calculate the (cyclic) autocorrelation by using the power spectral density
  * estimate (#psd_accumulator).
  * \param fft_buffer The result of the autocorrelation computation will be
  *                   written here.
  * \return 0 if the calculation completed successfully, non-zero if there was
  *         some arithmetic error.
  */
static int calculateAutoCorrelation(ComplexFixed *fft_buffer)
{
	int r;
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
	r = 0;
	if (fft(fft_buffer, 1))
	{
		r = 1;
	}
	if (fftPostProcessReal(fft_buffer, 1))
	{
		r = 1;
	}
	return r;
}

/** Find the magnitude of the largest autocorrelation amplitude.
  * Theoretically, for an infinitely large sample and a perfect noise source,
  * the autocorrelation amplitude should be 0 everywhere (except for lag = 0).
  * Thus the maximum magnitude quantifies how non-ideal the HWRNG is.
  * \param fft_buffer The correlogram, as calculated by
  *                   calculateAutoCorrelation(). This should have at
  *                   least #FFT_SIZE + 1 entries.
  */
static fix16_t findMaximumAutoCorrelation(ComplexFixed *fft_buffer)
{
	fix16_t max;
	fix16_t sample;
	uint32_t i;

	max = fix16_zero;
	for (i = AUTOCORR_START_LAG; i < (FFT_SIZE + 1); i++)
	{
		sample = fft_buffer[i].real;
		if (sample < fix16_zero)
		{
			sample = -sample;
		}
		if (sample > max)
		{
			max = sample;
		}
	}
	return max;
}

/** Run histogram-based statistical tests on HWRNG signal and report any
  * failures.
  * This only should be called once the histogram is full.
  * \param variance After it is calculated, the variance will be written here
  *                 (it's needed so that fftTestsFailed() can do some
  *                 normalisation).
  * \return 0 if all tests passed, non-zero if any tests failed.
  */
static NOINLINE uint32_t histogramTestsFailed(fix16_t *variance)
{
	uint32_t tests_failed;
	int moment_error;
	int entropy_error;
	fix16_t mean;
	fix16_t kappa3; // non-standardised skewness
	fix16_t kappa4; // non-standardised kurtosis
	fix16_t variance_squared;
	fix16_t three_times_variance_squared;
	fix16_t variance_cubed;
	fix16_t kappa3_squared;
	fix16_t term1;
	fix16_t entropy_estimate;

	fix16_error_flag = 0;
	mean = calculateCentralMoment(fix16_zero, 1);
	*variance = calculateCentralMoment(mean, 2);
	kappa3 = calculateCentralMoment(mean, 3);
	kappa4 = calculateCentralMoment(mean, 4);
	moment_error = fix16_error_flag;
	fix16_error_flag = 0;
	entropy_estimate = estimateEntropy();
	entropy_error = fix16_error_flag;

#ifdef TEST_STATISTICS
	most_recent_mean = mean;
	most_recent_variance = *variance;
	most_recent_kappa3 = kappa3;
	most_recent_kappa4 = kappa4;
	most_recent_entropy_estimate = entropy_estimate;
#endif // #ifdef TEST_STATISTICS

	tests_failed = 0;
	// STATTEST_MIN_MEAN and STATTEST_MAX_MEAN are in ADC output numbers.
	// To be comparable to mean, they need to be scaled and offset, just
	// as samples are in updateIteratorCache().
	if (mean <= F16((STATTEST_MIN_MEAN - (HISTOGRAM_NUM_BINS / 2)) / SAMPLE_SCALE_DOWN))
	{
		tests_failed |= 1; // mean below minimum
	}
	if (mean >= F16((STATTEST_MAX_MEAN - (HISTOGRAM_NUM_BINS / 2)) / SAMPLE_SCALE_DOWN)) 
	{
		tests_failed |= 1; // mean above maximum
	}
	if (*variance <= F16((STATTEST_MIN_VARIANCE / SAMPLE_SCALE_DOWN) / SAMPLE_SCALE_DOWN))
	{
		tests_failed |= 2; // variance below minimum
	}
	if (*variance >= F16((STATTEST_MAX_VARIANCE / SAMPLE_SCALE_DOWN) / SAMPLE_SCALE_DOWN))
	{
		tests_failed |= 2; // variance below minimum
	}
	// kappa3 is supposed to be standardised by dividing by
	// variance ^ (3/2), but this would involve one division and one square
	// root. But since skewness = kappa3 / variance ^ (3/2), this implies
	// that kappa3 ^ 2 = variance ^ 3 * skewness ^ 2.
	variance_squared = fix16_mul(*variance, *variance);
	variance_cubed = fix16_mul(variance_squared, *variance);
	kappa3_squared = fix16_mul(kappa3, kappa3);
	// Thanks to the squaring of kappa3, only one test is needed.
	if (kappa3_squared >= fix16_mul(variance_cubed, F16(STATTEST_MAX_SKEWNESS * STATTEST_MAX_SKEWNESS)))
	{
		tests_failed |= 4; // skewness out of bounds
	}
	// kappa4 is supposed to be standardised by dividing by variance ^ 2, but
	// this would involve division. But since
	// kurtosis = kappa4 / variance ^ 2 - 3, this implies that
	// kappa_4 = kurtosis * variance ^ 2 + 3 * variance ^ 2.
	three_times_variance_squared = fix16_mul(fix16_from_int(3), variance_squared);
	term1 = fix16_mul(F16(STATTEST_MIN_KURTOSIS), variance_squared);
	if (kappa4 <= fix16_add(term1, three_times_variance_squared))
	{
		tests_failed |= 8; // kurtosis below minimum
	}
	term1 = fix16_mul(F16(STATTEST_MAX_KURTOSIS), variance_squared);
	if (kappa4 >= fix16_add(term1, three_times_variance_squared))
	{
		tests_failed |= 8; // kurtosis above maximum
	}
	if (moment_error || histogram_overflow)
	{
		tests_failed |= 15; // arithmetic error (probably overflow)
	}
	if (entropy_estimate < F16(STATTEST_MIN_ENTROPY))
	{
		tests_failed |= 128; // entropy per sample below minimum
	}
	if (entropy_error)
	{
		tests_failed |= 128; // arithmetic error (probably overflow)
	}

	return tests_failed;
}

/** Run FFT-based statistical tests on HWRNG signal and report any failures.
  * This only should be called once the power spectral density accumulator
  * (see #psd_accumulator) has accumulated enough samples.
  * \param variance The variance, as calculated by histogramTestsFailed().
  * \return 0 if all tests passed, non-zero if any tests failed.
  */
static NOINLINE uint32_t fftTestsFailed(fix16_t variance)
{
	uint32_t tests_failed;
	int autocorrelation_error;
	int bandwidth; // as FFT bin number
	int max_bin; // as FFT bin number
	fix16_t max_autocorrelation;
	ComplexFixed fft_buffer[FFT_SIZE + 1];

	fix16_error_flag = 0;
	bandwidth = estimateBandwidth(&max_bin);
	fix16_error_flag = 0;
	autocorrelation_error = calculateAutoCorrelation(fft_buffer);
	max_autocorrelation = findMaximumAutoCorrelation(fft_buffer);

#ifdef TEST_STATISTICS
	if (report_to_stream == 4)
	{
		// Report autocorrelation results.
		reportFftResults(fft_buffer);
	}
	most_recent_max_bin = max_bin;
	most_recent_bandwidth = bandwidth;
	most_recent_max_autocorrelation = max_autocorrelation;
#endif // #ifdef TEST_STATISTICS

	tests_failed = 0;
	if (fix16_from_int(max_bin) < F16(PSD_MIN_PEAK * 2.0 * FFT_SIZE))
	{
		tests_failed |= 16; // peak in power spectrum is below minimum frequency
	}
	if (fix16_from_int(max_bin) > F16(PSD_MAX_PEAK * 2.0 * FFT_SIZE))
	{
		tests_failed |= 16; // peak in power spectrum is below minimum frequency
	}
	if (fix16_from_int(bandwidth) < F16(PSD_MIN_BANDWIDTH * 2.0 * FFT_SIZE))
	{
		tests_failed |= 32; // bandwidth of HWRNG below minimum
	}
	if (psd_accumulator_error)
	{
		tests_failed |= 48; // arithmetic error (probably overflow)
	}
	if (max_autocorrelation > fix16_mul(variance, F16(AUTOCORR_THRESHOLD)))
	{
		tests_failed |= 64; // maximum autocorrelation amplitude above maximum
	}
	if (autocorrelation_error)
	{
		tests_failed |= 64; // arithmetic error (probably overflow)
	}
	return tests_failed;
}

/** Calculate (an estimate of) the power spectral density of the HWRNG. The
  * result will be accumulated in #psd_accumulator.
  * \param source_buffer An array of samples from the ADC which is connected
  *                      to the HWRNG. This must have #SAMPLE_BUFFER_SIZE
  *                      entries in it.
  */
static void NOINLINE accumulatePowerSpectralDensity(volatile uint16_t *source_buffer)
{
	uint32_t i;
	uint32_t index;
	fix16_t scaled_sample;
	fix16_t term1;
	fix16_t term2;
	fix16_t sum_of_squares;
	ComplexFixed fft_buffer[FFT_SIZE + 1];

	// The code below which calculates a FFT and accumulates the result
	// assumes that SAMPLE_BUFFER_SIZE is FFT_SIZE * 2 (i.e. the sample
	// buffer is conveniently large enough to perform a double-sized real
	// FFT on).
#if SAMPLE_BUFFER_SIZE != (FFT_SIZE * 2)
#error "SAMPLE_BUFFER_SIZE not twice FFT_SIZE"
#endif // #if SAMPLE_BUFFER_SIZE != (FFT_SIZE * 2)
	// Fill FFT buffer with entire contents of ADC sample data.
	// Real/imaginary interleaving is done to allow a double-size real
	// FFT to be performed; see fftPostProcessReal() for more details.
	for (i = 0; i < SAMPLE_BUFFER_SIZE; i++)
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
	// reduces the chance of overflow
	subtractMean(fft_buffer);
	if (fft(fft_buffer, 0))
	{
		psd_accumulator_error = 1;
	}
	if (fftPostProcessReal(fft_buffer, 0))
	{
		psd_accumulator_error = 1;
	}
	fix16_error_flag = 0;
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
	if (fix16_error_flag)
	{
		psd_accumulator_error = 1;
	}
}

/** Fill buffer with 32 random bytes from a hardware random number generator.
  * \param buffer The buffer to fill. This should have enough space for 32
  *               bytes.
  * \return An estimate of the total number of bits (not bytes) of entropy in
  *         the buffer.
  */
int hardwareRandom32Bytes(uint8_t *buffer)
{
	uint32_t i;
	uint32_t sample;
	uint32_t tests_failed;
	fix16_t variance;

	if (!is_not_first_in_histogram)
	{
		// This is the first sample in a series of SAMPLE_COUNT samples. Thus
		// everything needs to start from a blank state.
		clearHistogram();
		memset(psd_accumulator, 0, sizeof(psd_accumulator));
		psd_accumulator_error = 0;
		// The histogram is empty. The sample buffer is also assumed to be
		// empty, since this may be the first call to hardwareRandom32Bytes()
		// after power-on. Therefore an extra call to beginFillingADCBuffer()
		// needs to be done to ensure that a full, current sample buffer is
		// available.
		sample_buffer_consumed = 0;
		beginFillingADCBuffer();
		is_not_first_in_histogram = 1;
	}
	if (sample_buffer_consumed == 0)
	{
		// Need to wait until next sample buffer has been filled.
		while (!sample_buffer_full)
		{
			// do nothing
		}
	}
	// From here on, code can assume that a full, current sample buffer is
	// available.

	// The following loop assumes that #SAMPLE_BUFFER_SIZE is a multiple
	// of 16.
#if ((SAMPLE_BUFFER_SIZE & 15) != 0)
#error "SAMPLE_BUFFER_SIZE not a multiple of 16"
#endif // #if ((SAMPLE_BUFFER_SIZE & 15) != 0)
	for (i = 0; i < 16; i++)
	{
		sample = adc_sample_buffer[sample_buffer_consumed];
		incrementHistogram(sample);
		// Fill entropy buffer with ADC sample data.
		buffer[i * 2] = (uint8_t)sample;
		buffer[i * 2 + 1] = (uint8_t)(sample >> 8);
		sample_buffer_consumed++;
	}

	if (sample_buffer_consumed >= SAMPLE_BUFFER_SIZE)
	{
		accumulatePowerSpectralDensity(adc_sample_buffer);
		// Sample buffer fully consumed; need to get a new buffer.
		sample_buffer_consumed = 0;
		beginFillingADCBuffer();
	}

	if (samples_in_histogram >= SAMPLE_COUNT)
	{
		// Histogram is full. Statistical properties can now be calculated.
		is_not_first_in_histogram = 0;
		tests_failed = histogramTestsFailed(&variance);
		tests_failed |= fftTestsFailed(variance);
#ifdef TEST_STATISTICS
		reportStatistics(tests_failed);
#endif // #ifdef TEST_STATISTICS
		if (tests_failed != 0)
		{
			return -1; // statistical tests indicate HWRNG failure
		}
		// Why return 512 (bits)? This ensures that hardwareRandom32Bytes()
		// will be called a minimum number of times per getRandom256() call,
		// assuming an entropy safety factor of 2 in prandom.c.
		// This is extremely conservative, given any reasonable value of
		// SAMPLE_COUNT. For example, for a SAMPLE_COUNT of 4096, this
		// probably underestimates the usable entropy by a factor of about 50.
		return 512;
	}
	else
	{
		// Indicate to caller that more samples are needed in order to do
		// statistical tests.
		return 0;
	}
}

#ifdef TEST_STATISTICS

/** Quick and dirty conversion of fix16 to string.
  * \param buffer Character buffer where null-terminated will be written to.
  *               Must have space for 16 characters.
  * \param in Number to convert to string.
  */
static void sprintFix16(char *buffer, fix16_t in)
{
	int suppress_leading_zeroes;
	int i;
	int index;
	uint32_t int_part;
	uint32_t digit;
	char temp[5];

	// Check sign.
	index = 0;
	if (in < fix16_zero)
	{
		in = -in;
		buffer[index++] = '-';
	}

	// Convert integer part.
	int_part = ((uint32_t)in) >> 16;
	for (i = 0; i < 5; i++)
	{
		digit = int_part % 10;
		int_part = int_part / 10;
		temp[i] = (char)(digit + '0');
	}
	suppress_leading_zeroes = 1;
	for (i = 0; i < 5; i++)
	{
		if (!suppress_leading_zeroes || (temp[4 - i] != '0'))
		{
			buffer[index++] = temp[4 - i];
			suppress_leading_zeroes = 0;
		}
	}
	// If integer part is 0, include one leading zero.
	if (suppress_leading_zeroes)
	{
		buffer[index++] = '0';
	}
	buffer[index++] = '.';

	// Convert fractional part.
	in = (fix16_t)(((uint32_t)in) & 0xffff);
	for (i = 0; i < 7; i++)
	{
		in *= 10;
		digit = ((uint32_t)in) >> 16;
		buffer[index++] = (char)(digit + '0');
		in = (fix16_t)(((uint32_t)in) & 0xffff);
	}

	buffer[index++] = '\0';
}

/** Send null-terminated string to stream.
  * \param buffer The string to send.
  */
static void sendString(const char *buffer)
{
	for(; *buffer != '\0'; buffer++)
	{
		streamPutOneByte(*buffer);
	}
}

/** Write contents of FFT buffer to stream so that the host may capture FFT
  * results into a comma-seperated variable file.
  * \param fft_buffer The FFT buffer whose contents will be dumped onto the
  *                   stream. This must have #FFT_SIZE + 1 entries.
  */
static void reportFftResults(ComplexFixed *fft_buffer)
{
	uint32_t i;
	char buffer[20];

	for (i = 0; i < (FFT_SIZE + 1); i++)
	{
		sprintFix16(buffer, fix16_from_int(i));
		sendString(buffer);
		sendString(", ");
		sprintFix16(buffer, fft_buffer[i].real);
		sendString(buffer);
		sendString(", ");
		sprintFix16(buffer, fft_buffer[i].imag);
		sendString(buffer);
		sendString("\r\n");
	}
}

/** Write statistical properties to screen so that they may be inspected in
  * real-time. Because there are too many properties to fit on-screen,
  * there are various testing modes which will write different properties.
  * If reporting to stream is enabled, the properties are also written to the
  * stream so that the host may capture them into a comma-seperated variable
  * file.
  * \param tests_failed Indicates which tests failed. 0 means that no tests
  *                     failed. Non-zero means that at least one test failed.
  *                     The bit position of each bit that is set expresses
  *                     which test failed.
  */
static void reportStatistics(uint32_t tests_failed)
{
	int i;
	char buffer[20];

	displayOn();
	clearDisplay();

	if ((report_to_stream == 2) || (report_to_stream == 1) || (report_to_stream == 0))
	{
		// Report moment-based properties.
		sprintFix16(buffer, most_recent_mean);
		writeStringToDisplay(buffer);
		if (report_to_stream == 1)
		{
			sendString(buffer);
			sendString(", ");
		}
		nextLine();
		sprintFix16(buffer, most_recent_variance);
		writeStringToDisplay(buffer);
		if (report_to_stream == 1)
		{
			sendString(buffer);
			sendString(", ");
		}
		nextLine();
		sprintFix16(buffer, most_recent_kappa3);
		writeStringToDisplay(buffer);
		if (report_to_stream == 1)
		{
			sendString(buffer);
			sendString(", ");
		}
		nextLine();
		sprintFix16(buffer, most_recent_kappa4);
		writeStringToDisplay(buffer);
		if (report_to_stream == 1)
		{
			sendString(buffer);
		}
	} // end if ((report_to_stream == 2) || (report_to_stream == 1) || (report_to_stream == 0))

	if (report_to_stream == 2)
	{
		// Report power spectral density estimate.
		for (i = 0; i < (FFT_SIZE + 1); i++)
		{
			sprintFix16(buffer, fix16_from_int(i));
			sendString(buffer);
			sendString(", ");
			sprintFix16(buffer, psd_accumulator[i]);
			sendString(buffer);
			sendString("\r\n");
		}
	}

	if (report_to_stream == 3)
	{
		// Report peak frequency and signal bandwidth estimate.
		sprintFix16(buffer, fix16_from_int(most_recent_max_bin));
		writeStringToDisplay(buffer);
		sendString(buffer);
		sendString(", ");
		nextLine();
		sprintFix16(buffer, fix16_from_int(most_recent_bandwidth));
		writeStringToDisplay(buffer);
		sendString(buffer);
		nextLine();
	}

	if ((report_to_stream == 4) || (report_to_stream == 5))
	{
		// Report maximum autocorrelation value and entropy estimate.
		sprintFix16(buffer, most_recent_variance);
		writeStringToDisplay(buffer);
		nextLine();
		sprintFix16(buffer, most_recent_max_autocorrelation);
		writeStringToDisplay(buffer);
		if (report_to_stream == 5)
		{
			sendString(buffer);
			sendString(", ");
		}
		nextLine();
		sprintFix16(buffer, most_recent_entropy_estimate);
		writeStringToDisplay(buffer);
		if (report_to_stream == 5)
		{
			sendString(buffer);
		}
		nextLine();
	}

	writeStringToDisplay(" ");
	for (i = 0; i < 8; i++)
	{
		if ((tests_failed & 1) == 0)
		{
			writeStringToDisplay("p");
			if (report_to_stream == 1)
			{
				sendString(", pass");
			}
		}
		else
		{
			writeStringToDisplay("F");
			if (report_to_stream == 1)
			{
				sendString(", fail");
			}
		}
		tests_failed >>= 1;
	}
	if (report_to_stream != 0)
	{
		sendString("\r\n");
	}
}

/** Send real number in fixed-point representation to stream.
  * \param value The number to send.
  */
static void sendFix16(fix16_t value)
{
	uint8_t buffer[4];
	int j;

	writeU32LittleEndian(buffer, (uint32_t)value);
	for (j = 0; j < 4; j++)
	{
		streamPutOneByte(buffer[j]);
	}
}

/** Test statistical testing functions. The testing mode is set by the first
  * byte received from the stream.
  * - 'R': Send what hardwareRandom32Bytes() returns.
  * - 'S': Send moment-based statistical properties of HWRNG to stream.
  * - 'P': Send power-spectral density estimate of HWRNG to stream.
  * - 'B': Send bandwidth estimate off HWRNG to stream.
  * - 'A': Send results of autocorrelation computation to stream.
  * - 'E': Send maximum autocorrelation amplitude and entropy esimate to
  *        stream.
  * - Anything which is not an uppercase letter: grab input data from the
  *   stream, compute various statistical values and send them to the stream.
  *   The host can then check the output.
  */
void testStatistics(void)
{
	uint8_t mode;
	uint8_t buffer[4];
	uint8_t random_bytes[32];
	uint32_t cycles;
	uint32_t i;
	uint32_t sample;
	fix16_t mean;
	fix16_t variance;
	fix16_t kappa3; // non-standardised skewness
	fix16_t kappa4; // non-standardised kurtosis
	fix16_t entropy_estimate;

	mode = streamGetOneByte();
	if ((mode >= 'A') || (mode <= 'Z'))
	{
		if (mode == 'S')
		{
			report_to_stream = 1;
		}
		else if (mode == 'P')
		{
			report_to_stream = 2;
		}
		else if (mode == 'B')
		{
			report_to_stream = 3;
		}
		else if (mode == 'A')
		{
			report_to_stream = 4;
		}
		else if (mode == 'E')
		{
			report_to_stream = 5;
		}
		else
		{
			report_to_stream = 0;
		}
		while(1)
		{
			hardwareRandom32Bytes(random_bytes);
			if (!report_to_stream)
			{
				// Spam hardwareRandom32Bytes() output to stream,
				// so that host can inspect the raw HWRNG samples.
				for (i = 0; i < sizeof(random_bytes); i++)
				{
					streamPutOneByte(random_bytes[i]);
				}
			}
		}
	} // end if ((mode >= 'A') || (mode <= 'Z'))
	else
	{
		while(1)
		{
			clearHistogram();
			for (i = 0; i < SAMPLE_COUNT; i++)
			{
				sample = streamGetOneByte();
				sample |= (streamGetOneByte() << 8);
				incrementHistogram(sample);
			}

			SysTick->CTRL = 4; // disable system tick timer, frequency = CPU
			SysTick->VAL = 0; // clear system tick timer
			SysTick->LOAD = 0x00FFFFFF; // set timer reload to max
			SysTick->CTRL = 5; // enable system tick timer, frequency = CPU

			mean = calculateCentralMoment(fix16_zero, 1);
			variance = calculateCentralMoment(mean, 2);
			kappa3 = calculateCentralMoment(mean, 3);
			kappa4 = calculateCentralMoment(mean, 4);
			entropy_estimate = estimateEntropy();

			cycles = SysTick->VAL; // read as soon as possible
			cycles = (0x00FFFFFF - cycles);

			sendFix16(mean);
			sendFix16(variance);
			sendFix16(kappa3);
			sendFix16(kappa4);
			sendFix16(entropy_estimate);
			// Tell host how long it took
			writeU32LittleEndian(buffer, cycles);
			for (i = 0; i < 4; i++)
			{
				streamPutOneByte(buffer[i]);
			}
		} // end while(1)
	} // end else clause of if ((mode >= 'A') || (mode <= 'Z'))
}

#endif // #ifdef TEST_STATISTICS

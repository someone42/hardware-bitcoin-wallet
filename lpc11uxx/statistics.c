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

#include <stdint.h>
#include <string.h>
#include "fix16.h"
#include "statistics.h"
#include "adc.h"

#ifdef TEST_STATISTICS
#include "../endian.h"
#include "../hwinterface.h"
#include "LPC11Uxx.h"
#endif // #ifdef TEST_STATISTICS

/** The maximum number of counts which can be held in one histogram bin. */
#define MAX_HISTOGRAM_VALUE			((1 << BITS_PER_HISTOGRAM_BIN) - 1)

/** The buffer where histogram counts are stored. The buffer needs to be
  * persistent, because counts are accumulated across many calls to
  * hardwareRandomBytes(). In order to conserve valuable RAM, the buffer is
  * bit-packed.
  *
  * A histogram is much more space-efficient than storing a buffer of
  * individual samples, since (for the calculation of most statistical
  * properties) the order of samples doesn't matter. Each bin represents a
  * value, and each bin has an associated count, which represents how many
  * times that value occurred.
  */
static uint32_t packed_histogram_buffer[((HISTOGRAM_NUM_BINS * BITS_PER_HISTOGRAM_BIN) / 32) + 1];

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
static void clearHistogram(void)
{
	memset(packed_histogram_buffer, 0, sizeof(packed_histogram_buffer));
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
		fix16_error_flag = 1;
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
}

/** This must be called whenever the iterator is active and #iterator_index
  * changes. */
static void updateIteratorCache(void)
{
	int sample_int;

	cached_histogram_count = getHistogram(iterator_index);
	sample_int = iterator_index;
	// Centre middle of histogram range on 0.0, so that overflow will be less
	// likely to occur.
	sample_int -= (HISTOGRAM_NUM_BINS / 2);
	cached_scaled_sample = fix16_from_int(sample_int);
	cached_scaled_sample = fix16_mul(cached_scaled_sample, FIX16_RECIPROCAL_OF(SAMPLE_SCALE_DOWN));
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
  * require the mean to be known. If the mean is not known, if can be
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

/** This will be zero if the next sample to be returned by
  * hardwareRandomBytes() is the first sample to be placed in a histogram
  * bin. This will be non-zero if that next sample is not the first
  * sample to be placed in a histogram bin. This variable was defined in
  * that way so that it is initially 0.
  */
static int is_not_first_in_histogram;
/** Number of bytes of the sample buffer that hardwareRandomBytes() has used
  * up. */
static uint32_t sample_buffer_consumed;

/** Fill buffer with random bytes from a hardware random number generator.
  * \param buffer The buffer to fill. This should have enough space for n
  *               bytes.
  * \param n The size of the buffer.
  * \return An estimate of the total number of bits (not bytes) of entropy in
  *         the buffer.
  */
uint16_t hardwareRandomBytes(uint8_t *buffer, uint8_t n)
{
	int got_to_end;
	uint32_t i;

	if (!is_not_first_in_histogram)
	{
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

	got_to_end = 0;
	for (i = 0; i < n; i++)
	{
		if (sample_buffer_consumed >= (SAMPLE_BUFFER_SIZE * sizeof(uint16_t)))
		{
			got_to_end = 1;
			break;
		}
		if ((sample_buffer_consumed & 1) == 0)
		{
			buffer[i] = (uint8_t)adc_sample_buffer[sample_buffer_consumed >> 1];
		}
		else
		{
			buffer[i] = (uint8_t)(adc_sample_buffer[sample_buffer_consumed >> 1] >> 8);
		}
		sample_buffer_consumed++;
	}

	if (sample_buffer_consumed >= (SAMPLE_BUFFER_SIZE * sizeof(uint16_t)))
	{
		// Need to get a new buffer.
		sample_buffer_consumed = 0;
		beginFillingADCBuffer();
	}
	if (got_to_end)
	{
		return 0; // just to be safe
	}
	else
	{
		return 8;
	}
}

#ifdef TEST_STATISTICS

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
  * - 'R': Send what hardwareRandomBytes() returns.
  * - Anything else: grab input data from the stream, compute various
  *   statistical values and send them to the stream. The host can then check
  *   the output.
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
	fix16_t skewness; // not normalised
	fix16_t kurtosis; // not normalised
	fix16_t entropy_estimate;

	mode = streamGetOneByte();
	if (mode == 'R')
	{
		while(1)
		{
			// Spam hardwareRandomBytes() output to stream, so that host can
			// inspect the raw HWRNG samples.
			hardwareRandomBytes(random_bytes, sizeof(random_bytes));
			for (i = 0; i < sizeof(random_bytes); i++)
			{
				streamPutOneByte(random_bytes[i]);
			}
		}
	}
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
			skewness = calculateCentralMoment(mean, 3);
			kurtosis = calculateCentralMoment(mean, 4);
			entropy_estimate = estimateEntropy();

			cycles = SysTick->VAL; // read as soon as possible
			cycles = (0x00FFFFFF - cycles);

			sendFix16(mean);
			sendFix16(variance);
			sendFix16(skewness);
			sendFix16(kurtosis);
			sendFix16(entropy_estimate);
			// Tell host how long it took
			writeU32LittleEndian(buffer, cycles);
			for (i = 0; i < 4; i++)
			{
				streamPutOneByte(buffer[i]);
			}
		} // end while(1)
	} // end if (mode == 'R')
}

#endif // #ifdef TEST_STATISTICS

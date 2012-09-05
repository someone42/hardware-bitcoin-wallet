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

#ifdef TEST_STATISTICS
#include "../endian.h"
#include "../hwinterface.h"
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

/** Reset the histogram iterator back to the start. */
static void resetIterator(void)
{
	iterator_index = 0;
	iterator_count = 0;
}

/** Uses an iterator over the histogram to obtain one term in a central
  * moment calculation. The iterator goes over each item (count) from each
  * histogram bin (index).
  * \param mean The mean to calculate the central moment about.
  * \param power Which central moment to calculate (1 = first, 2 = second
  *              etc.).
  * \return One term for the calculation of the specified central moment.
  */
static fix16_t getTermFromIterator(fix16_t mean, uint32_t power)
{
	int sample_int;
	uint32_t i;
	fix16_t scaled_sample;
	fix16_t r;

	// Search for the index (bin number) of the next count.
	while (iterator_count >= getHistogram(iterator_index))
	{
		iterator_count = 0;
		iterator_index++;
		if (iterator_index >= HISTOGRAM_NUM_BINS)
		{
			// Iterator ran past end of samples. This should never happen.
			fix16_error_flag = 1;
			return fix16_zero;
		}
	}

	sample_int = iterator_index;
	iterator_count++;
	// Centre middle of histogram range on 0.0, so that overflow will be less
	// likely to occur.
	sample_int -= (HISTOGRAM_NUM_BINS / 2);
	scaled_sample = fix16_from_int(sample_int);
	scaled_sample = fix16_mul(scaled_sample, FIX16_RECIPROCAL_OF(SAMPLE_SCALE_DOWN));
	scaled_sample = fix16_sub(scaled_sample, mean);
	r = fix16_one;
	for (i = 0; i < power; i++)
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

/** Test statistical testing functions by grabbing input data from the
  * stream, computing various statistical values and sending them to the
  * stream. The host can then check the outputs.
  */
void testStatistics(void)
{
	uint32_t i;
	uint32_t sample;
	fix16_t mean;

	while(1)
	{
		clearHistogram();
		for (i = 0; i < SAMPLE_COUNT; i++)
		{
			sample = streamGetOneByte();
			sample |= (streamGetOneByte() << 8);
			incrementHistogram(sample);
		}
		mean = calculateCentralMoment(fix16_zero, 1);
		sendFix16(mean);
		sendFix16(calculateCentralMoment(mean, 2)); // variance
		sendFix16(calculateCentralMoment(mean, 3)); // skewness
		sendFix16(calculateCentralMoment(mean, 4)); // kurtosis
		sendFix16(estimateEntropy());
	} // end while(1)
}

#endif // #ifdef TEST_STATISTICS

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
#include "ssd1306.h"
#include "../endian.h"
#include "../hwinterface.h"
#include "LPC11Uxx.h"

static void sprintFix16(char *buffer, fix16_t in);
static void sendString(const char *buffer);

/** Set to non-zero to send statistical properties to stream. */
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

/** Run statistical tests on histogram and report any failures.
  * This only should be called once the histogram is full.
  * \return 0 if all tests passed, non-zero if any tests failed.
  */
static int histogramTestsFailed(void)
{
	int r;
	fix16_t mean;
	fix16_t variance;
	fix16_t kappa3; // non-standardised skewness
	fix16_t kappa4; // non-standardised kurtosis
	fix16_t variance_squared;
	fix16_t three_times_variance_squared;
	fix16_t variance_cubed;
	fix16_t kappa3_squared;
	fix16_t term1;
#ifdef TEST_STATISTICS
	int i;
	int temp_r;
	char buffer[20];
#endif // #ifdef TEST_STATISTICS

	fix16_error_flag = 0;
	mean = calculateCentralMoment(fix16_zero, 1);
	variance = calculateCentralMoment(mean, 2);
	kappa3 = calculateCentralMoment(mean, 3);
	kappa4 = calculateCentralMoment(mean, 4);

#ifdef TEST_STATISTICS
	// Write moments to screen so that they may be inspected in real-time.
	// If reporting to stream is enabled, they are also written to the stream
	// so that the host may capture them into a comma-seperated variable file.
	displayOn();
	clearDisplay();
	sprintFix16(buffer, mean);
	writeStringToDisplay(buffer);
	if (report_to_stream)
	{
		sendString(buffer);
		sendString(", ");
	}
	nextLine();
	sprintFix16(buffer, variance);
	writeStringToDisplay(buffer);
	if (report_to_stream)
	{
		sendString(buffer);
		sendString(", ");
	}
	nextLine();
	sprintFix16(buffer, kappa3);
	writeStringToDisplay(buffer);
	if (report_to_stream)
	{
		sendString(buffer);
		sendString(", ");
	}
	nextLine();
	sprintFix16(buffer, kappa4);
	writeStringToDisplay(buffer);
	if (report_to_stream)
	{
		sendString(buffer);
	}
#endif // #ifdef TEST_STATISTICS

	r = 0;
	// STATTEST_MIN_MEAN and STATTEST_MAX_MEAN are in ADC output numbers.
	// To be comparable to mean, they need to be scaled and offset, just
	// as samples are in updateIteratorCache().
	if (mean <= F16((STATTEST_MIN_MEAN - (HISTOGRAM_NUM_BINS / 2)) / SAMPLE_SCALE_DOWN))
	{
		r |= 1; // mean below minimum
	}
	if (mean >= F16((STATTEST_MAX_MEAN - (HISTOGRAM_NUM_BINS / 2)) / SAMPLE_SCALE_DOWN)) 
	{
		r |= 1; // mean above maximum
	}
	if (variance <= F16((STATTEST_MIN_VARIANCE / SAMPLE_SCALE_DOWN) / SAMPLE_SCALE_DOWN))
	{
		r |= 2; // variance below minimum
	}
	if (variance >= F16((STATTEST_MAX_VARIANCE / SAMPLE_SCALE_DOWN) / SAMPLE_SCALE_DOWN))
	{
		r |= 2; // variance below minimum
	}
	// kappa3 is supposed to be standardised by dividing by
	// variance ^ (3/2), but this would involve one division and one square
	// root. But since skewness = kappa3 / variance ^ (3/2), this implies
	// that kappa3 ^ 2 = variance ^ 3 * skewness ^ 2.
	variance_squared = fix16_mul(variance, variance);
	variance_cubed = fix16_mul(variance_squared, variance);
	kappa3_squared = fix16_mul(kappa3, kappa3);
	// Thanks to the squaring of kappa3, only one test is needed.
	if (kappa3_squared >= fix16_mul(variance_cubed, F16(STATTEST_MAX_SKEWNESS * STATTEST_MAX_SKEWNESS)))
	{
		r |= 4; // skewness out of bounds
	}
	// kappa4 is supposed to be standardised by dividing by variance ^ 2, but
	// this would involve division. But since
	// kurtosis = kappa4 / variance ^ 2 - 3, this implies that
	// kappa_4 = kurtosis * variance ^ 2 + 3 * variance ^ 2.
	three_times_variance_squared = fix16_mul(fix16_from_int(3), variance_squared);
	term1 = fix16_mul(F16(STATTEST_MIN_KURTOSIS), variance_squared);
	if (kappa4 <= fix16_add(term1, three_times_variance_squared))
	{
		r |= 8; // kurtosis below minimum
	}
	term1 = fix16_mul(F16(STATTEST_MAX_KURTOSIS), variance_squared);
	if (kappa4 >= fix16_add(term1, three_times_variance_squared))
	{
		r |= 8; // kurtosis above maximum
	}
	if (fix16_error_flag || histogram_overflow)
	{
		r |= 15; // arithmetic error (probably overflow)
	}

#ifdef TEST_STATISTICS
	temp_r = r;
	writeStringToDisplay(" ");
	for (i = 0; i < 4; i++)
	{
		if ((temp_r & 1) == 0)
		{
			writeStringToDisplay("p");
			if (report_to_stream)
			{
				sendString(", pass");
			}
		}
		else
		{
			writeStringToDisplay("F");
			if (report_to_stream)
			{
				sendString(", fail");
			}
		}
		temp_r >>= 1;
	}
	sendString("\r\n");
#endif // #ifdef TEST_STATISTICS

	return r;
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

	if (!is_not_first_in_histogram)
	{
		clearHistogram();
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
		buffer[i * 2] = (uint8_t)sample;
		buffer[i * 2 + 1] = (uint8_t)(sample >> 8);
		sample_buffer_consumed++;
	}

	if (sample_buffer_consumed >= SAMPLE_BUFFER_SIZE)
	{
		// Sample buffer fully consumed; need to get a new buffer.
		sample_buffer_consumed = 0;
		beginFillingADCBuffer();
	}

	if (samples_in_histogram >= SAMPLE_COUNT)
	{
		// Histogram is full. Statistical properties can now be calculated.
		is_not_first_in_histogram = 0;
		if (histogramTestsFailed())
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
	fix16_t kappa3; // non-standardised skewness
	fix16_t kappa4; // non-standardised kurtosis
	fix16_t entropy_estimate;

	mode = streamGetOneByte();
	if ((mode == 'R') || (mode == 'S'))
	{
		if (mode == 'S')
		{
			report_to_stream = 1;
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
	} // end if ((mode == 'R') || (mode == 'S'))
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
	} // end else clause of if ((mode == 'R') || (mode == 'S'))
}

#endif // #ifdef TEST_STATISTICS

/** \file hwrng_limits.h
  *
  * \brief Statistical limits on what is considered a working HWRNG.
  *
  * The code in hwrng.c does statistical testing of samples from the
  * hardware random number generator (HWRNG). These constants define the limits
  * for each statistical test. These values are very dependent on the
  * implementation of the HWRNG.
  *
  * This file is licensed as described by the file LICENCE.
  */

// TODO: Adjust values for BitSafe development board thermal noise source.

#ifndef PIC32_HWRNG_LIMITS_H_INCLUDED
#define PIC32_HWRNG_LIMITS_H_INCLUDED

/** Nominal mean, in ADC output number. This was measured. */
#define STATTEST_CENTRAL_MEAN		311.47
/** Minimum acceptable mean, in ADC output number.
  * This differs from STATTEST_CENTRAL_MEAN by the following:
  * - Factor of 0.968: worst case decrease due to 2 1% tolerance resistors
  *   with a 60 K temperature change at 100 ppm/K.
  * - Offset of 65: worst case decrease due to 7 millivolt op-amp input offset
  *   voltage multiplied by a gain of 30.
  * - Offset of 4: maximum total absolute error of ADC.
  */
#define STATTEST_MIN_MEAN			(0.968 * STATTEST_CENTRAL_MEAN - 65.0 - 4.0)
/** Maximum acceptable mean, in ADC output number.
  * This differs from STATTEST_CENTRAL_MEAN by the following:
  * - Factor of 1.032: worst case increase due to 2 1% tolerance resistors
  *   with a 60 K temperature change at 100 ppm/K.
  * - Offset of 65: worst case increase due to 7 millivolt op-amp input offset
  *   voltage multiplied by a gain of 30.
  * - Offset of 4: maximum total absolute error of ADC.
  */
#define STATTEST_MAX_MEAN			(1.032 * STATTEST_CENTRAL_MEAN + 65.0 + 4.0)
/** Nominal variance, in ADC output number squared. This was measured. */
#define STATTEST_CENTRAL_VARIANCE	1201.7
/** Minimum acceptable variance, in ADC output number squared.
  * This differs from #STATTEST_CENTRAL_VARIANCE by the following factors:
  * - Factor of 0.846: variation in amplitude of Johnson-Nyquist noise due to
  *   temperature decrease from 293 K to 248 K.
  * - Factor of 0.817: worst case decrease due to 7 1% tolerance resistors
  *   with a 45 K temperature change at 100 ppm/K.
  * - Factor of 0.805: 5 sigma statistical fluctuations for N = 4096. This was
  *   measured.
  * - Factor of 0.988: 0.6% gain error from ADC.
  */
#define STATTEST_MIN_VARIANCE		(0.846 * 0.817 * 0.805 * 0.988 * STATTEST_CENTRAL_VARIANCE)
/** Maximum acceptable variance, in ADC output number squared.
  * This differs from #STATTEST_CENTRAL_VARIANCE by the following factors:
  * - Factor of 1.154: variation in amplitude of Johnson-Nyquist noise due to
  *   temperature increase from 293 K to 338 K.
  * - Factor of 1.224: worst case increase due to 7 1% tolerance resistors
  *   with a 45 K temperature change at 100 ppm/K.
  * - Factor of 1.195: 5 sigma statistical fluctuations for N = 4096. This was
  *   measured.
  * - Factor of 1.012: 0.6% gain error from ADC.
  */
#define STATTEST_MAX_VARIANCE		(1.154 * 1.224 * 1.195 * 1.012 * STATTEST_CENTRAL_VARIANCE)
/** Maximum acceptable skewness (standardised 3rd central moment) in either
  * the positive or negative direction. This is approximately 5 standard
  * deviations (calculated using N = 4096) from the theoretical value of 0.
  * This was measured.
  */
#define STATTEST_MAX_SKEWNESS		0.237
/** Minimum acceptable kurtosis (standardised 4th central moment - 3). This is
  * approximately 5 standard deviations (calculated using N = 4096) below the
  * theoretical value of 0. This was measured.
  */
#define STATTEST_MIN_KURTOSIS		-0.48
/** Maximum acceptable kurtosis (standardised 4th central moment - 3). This is
  * approximately 5 standard deviations (calculated using N = 4096) above the
  * theoretical value of 0. This was measured.
  * Note that even for N = 4096, the skewness of kurtosis distribution is
  * significant (about 0.35); that's why this is not just the negation
  * of #STATTEST_MIN_KURTOSIS.
  */
#define STATTEST_MAX_KURTOSIS		0.65
/** The bandwidth of the HWRNG is defined as the frequency range over which
  * the power spectral density remains higher than this threshold, relative
  * to the peak value. Conventionally, this would be 0.5, corresponding to
  * 3 dB. However, because statistics.c calculates a power spectral density
  * estimate, this must be lower than 0.5 to account for statistical
  * fluctuations.
  *
  * Like #PSD_THRESHOLD_REPETITIONS, this is a value which needs to be
  * determined empirically (in other words, tweak it until you get sensible
  * results). Too high a value will cause the bandwidth to be
  * underestimated, too low a value will cause overestimation. As some
  * guidance, for N = 4096, each bin in the PSD has a standard deviation of
  * about 1.7 dB (this was measured), so accounting for 5 sigma fluctuations
  * of a single bin means lowering the 3 dB threshold by about 8.5 dB.
  */
#define PSD_BANDWIDTH_THRESHOLD		0.0329
/** Number of consecutive power spectrum bins which must be below the
  * threshold (see #PSD_BANDWIDTH_THRESHOLD) before the code in statistics.c
  * considers a bin as an edge of the HWRNG bandwidth. Making this value
  * larger has the effect of reducing the impact of statistical fluctuations.
  *
  * Like #PSD_BANDWIDTH_THRESHOLD, this is a value which needs to be
  * determined empirically (in other words, tweak it until you get sensible
  * results). As some guidance, to have a one in a million
  * chance of a falsely registered edge, the threshold must be lowered
  * by approximately inverf(1 - 1 / (500000 ^ (1 / (this)))) * sqrt(2)
  * standard deviations.
  */
#define PSD_THRESHOLD_REPETITIONS	5
/** The minimum acceptable value for the peak frequency in the power spectrum.
  * The value is expressed as a fraction of the sampling rate.
  * This value corresponds to about 500 Hz and was chosen because it is well
  * below the HWRNG filter's high-pass cutoff.
  */
#define PSD_MIN_PEAK				0.0227
/** The maximum acceptable value for the peak frequency in the power spectrum.
  * The value is expressed as a fraction of the sampling rate.
  * This value corresponds to about 9 kHz and was chosen because it is well
  * above the HWRNG filter's low-pass cutoff.
  */
#define PSD_MAX_PEAK				0.408
/** The minimum acceptable value for the bandwidth of the HWRNG.
  * The value is expressed as a fraction of the sampling rate.
  * Note that this should not be lowered to account for statistical
  * fluctuations, as they're should be taken care of
  * in the values of #PSD_BANDWIDTH_THRESHOLD and #PSD_THRESHOLD_REPETITIONS.
  *
  * The measured 3 dB bandwidth of the current HWRNG is about 1.6 kHz.
  */
#define PSD_MIN_BANDWIDTH			0.0726
/** The lag, in samples, to start applying the autocorrelation threshold
  * (see #AUTOCORR_THRESHOLD) to.
  *
  * For an ideal white noise source, this should be 1, so that every point
  * (excluding the first, corresponding to lag 0, which will trivially be a
  * large positive value) in the correlogram will be considered. However, in
  * reality, filtering of the HWRNG signal will cause low-lag parts of
  * the correlogram to divert away from 0 significantly. Those parts should be
  * ignored, as they are artefacts of filtering and not genuine indicators
  * of HWRNG failure.
  *
  * This value was estimated from an ensemble of measured correlograms.
  */
#define AUTOCORR_START_LAG			12
/** The normalised autocorrelation threshold. If the magnitude of any values
  * in the correlogram exceed this threshold, then the HWRNG is considered
  * to possess too much autocorrelation (i.e. it is not random).
  *
  * This is "normalised" in the following sense: the actual threshold is
  * this value, multiplied by the variance. This is done because
  * autocorrelation amplitude scales linearly with signal variance.
  *
  * This value was estimated from an ensemble of measured correlograms.
  */
#define AUTOCORR_THRESHOLD			1.94
/** Minimum acceptable entropy estimate (in bits) per sample. This is
  * approximately 10 standard deviations (calculated using N = 4096) below
  * the mean entropy estimate for a Gaussian distribution with a standard
  * deviation of 24. This was calculated using Monte Carlo simulation.
  */
#define STATTEST_MIN_ENTROPY		6.43

#endif // #ifndef PIC32_HWRNG_LIMITS_H_INCLUDED

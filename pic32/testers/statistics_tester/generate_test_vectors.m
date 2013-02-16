% generate_test_vectors.m
%
% This is a GNU Octave script file. It will probably work with Matlab as well.
% It has been run successfully on GNU Octave 3.2.2.
% This script generates test vectors (which it places into a file named
% "statistics_test_vectors.txt") which statistics_tester.c can process.
%
% This file is licensed as described by the file LICENCE.

global SAMPLE_COUNT = 4096; % number of samples per test
global SAMPLE_OFFSET = -512; % offset to add to samples (before scale-down)
global SAMPLE_SCALE_DOWN = 64; % scale-down factor for samples
global HISTOGRAM_NUM_BINS = 1024; % sample values must be lower than this

global file_id; % file ID of file to write test vectors to

function outputTestCase(v)
	global file_id;
	global SAMPLE_OFFSET;
	global SAMPLE_SCALE_DOWN;
	global HISTOGRAM_NUM_BINS;

	v = max(v, 0); % clamp at lower end
	v = min(v, HISTOGRAM_NUM_BINS - 1); % clamp at upper end
	fprintf(file_id, "%d\n", v);
	scaled_v = (v + SAMPLE_OFFSET) / SAMPLE_SCALE_DOWN;
	mean = mean(scaled_v);
	% 10 digits means more than 32 bits of precision, which should cover all
	% possible Q16.16 values.
	fprintf(file_id, "%.10g\n", mean);
	scaled_v = scaled_v - mean;
	fprintf(file_id, "%.10g\n", moment(scaled_v, 2));
	fprintf(file_id, "%.10g\n", moment(scaled_v, 3));
	fprintf(file_id, "%.10g\n", moment(scaled_v, 4));
	entropy_estimate = entropy(histc(v, unique(v)) / size(v, 1));
	fprintf(file_id, "%.10g\n", entropy_estimate);
end

file_id = fopen("statistics_test_vectors.txt", "wt");

% Check what happens when samples are at the end of the range of possible
% values. They can't all be in one bin, or the bin will overflow.
fprintf(file_id, "Lowest four values\n");
x = zeros(SAMPLE_COUNT / 4, 1);
x = cat(1, x, ones(SAMPLE_COUNT / 4, 1));
x = cat(1, x, ones(SAMPLE_COUNT / 4, 1) * 2);
x = cat(1, x, ones(SAMPLE_COUNT / 4, 1) * 3);
outputTestCase(x);

% The statistical properties of a histogram should be independent of the
% order in which the samples were placed in bins.
fprintf(file_id, "Lowest four values reversed\n");
x = ones(SAMPLE_COUNT / 4, 1) * 3;
x = cat(1, x, ones(SAMPLE_COUNT / 4, 1) * 2);
x = cat(1, x, ones(SAMPLE_COUNT / 4, 1));
x = cat(1, x, zeros(SAMPLE_COUNT / 4, 1));
outputTestCase(x);

% Check what happens when samples are at the other end of the range of
% possible values.
fprintf(file_id, "Highest four values\n");
x = ones(SAMPLE_COUNT / 4, 1) * (HISTOGRAM_NUM_BINS - 4);
x = cat(1, x, ones(SAMPLE_COUNT / 4, 1) * (HISTOGRAM_NUM_BINS - 3));
x = cat(1, x, ones(SAMPLE_COUNT / 4, 1) * (HISTOGRAM_NUM_BINS - 2));
x = cat(1, x, ones(SAMPLE_COUNT / 4, 1) * (HISTOGRAM_NUM_BINS - 1));
outputTestCase(x);

% Mess with the order again.
fprintf(file_id, "Highest four values reversed\n");
x = ones(SAMPLE_COUNT / 4, 1) * (HISTOGRAM_NUM_BINS - 1);
x = cat(1, x, ones(SAMPLE_COUNT / 4, 1) * (HISTOGRAM_NUM_BINS - 2));
x = cat(1, x, ones(SAMPLE_COUNT / 4, 1) * (HISTOGRAM_NUM_BINS - 3));
x = cat(1, x, ones(SAMPLE_COUNT / 4, 1) * (HISTOGRAM_NUM_BINS - 4));
outputTestCase(x);

% Use normally-distributed pseudo-random samples. These resemble the samples
% that should be produced by a working hardware noise source. The standard
% deviation is varied because different hardware noise sources may have
% different amplitudes.
test_stdev = 8;
while (test_stdev < 200)
	fprintf(file_id, "Pseudo-random normal, stdev = %g\n", test_stdev);
	x = round(randn(SAMPLE_COUNT, 1) * test_stdev + 512);
	outputTestCase(x);
	test_stdev = test_stdev * 1.07;
end

% Use normally-distributed pseudo-random samples again, but vary the mean.
for my_mean = 100:20:HISTOGRAM_NUM_BINS - 100
	fprintf(file_id, "Pseudo-random normal, mean = %g\n", my_mean);
	x = round(randn(SAMPLE_COUNT, 1) * 64 + my_mean);
	outputTestCase(x);
end

% Use normally-distributed pseudo-random samples again, but make the
% standard deviation lopsided. This should result in very different
% skewness values.
test_stdev = 8;
while (test_stdev < 200)
	fprintf(file_id, "Pseudo-random lopsided normal, right stdev = %g\n", test_stdev);
	x = round(randn(SAMPLE_COUNT / 2, 1) .^ 2 * test_stdev + 512);
	x = cat(1, x, round(-randn(SAMPLE_COUNT / 2, 1) .^ 2 * 64 + 512));
	outputTestCase(x);
	test_stdev = test_stdev * 1.2;
end

% Vary the other side.
test_stdev = 8;
while (test_stdev < 200)
	fprintf(file_id, "Pseudo-random lopsided normal, left stdev = %g\n", test_stdev);
	x = round(-randn(SAMPLE_COUNT / 2, 1) .^ 2 * test_stdev + 512);
	x = cat(1, x, round(randn(SAMPLE_COUNT / 2, 1) .^ 2 * 64 + 512));
	outputTestCase(x);
	test_stdev = test_stdev * 1.2;
end

% Use uniformly-distributed pseudo-random samples. This should result in
% very different kurtosis values.
test_width = 8;
while (test_width < HISTOGRAM_NUM_BINS)
	fprintf(file_id, "Pseudo-random uniform, width = %g\n", test_width);
	x = round(rand(SAMPLE_COUNT, 1) * test_width);
	outputTestCase(x);
	test_width = test_width * 1.1;
end

% Explicit tests for entropy estimation aren't needed because the above tests
% (especially the ones with varying standard deviation) should cover a wide
% range of entropy per sample values.

fclose(file_id);

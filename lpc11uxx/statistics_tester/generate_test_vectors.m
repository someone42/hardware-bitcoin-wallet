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
global SAMPLE_SCALE_DOWN = 32; % scale-down factor for samples

global file_id; % file ID of file to write test vectors to

function outputTestCase(v)
	global file_id;
	global SAMPLE_OFFSET;
	global SAMPLE_SCALE_DOWN;
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

fprintf(file_id, "Test\n");
x = round(randn(SAMPLE_COUNT, 1) * 30 + 512);
outputTestCase(x);

% TODO: More tests.

fclose(file_id);

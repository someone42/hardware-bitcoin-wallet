% generate_test_vectors.m
%
% This is a GNU Octave script file. It will probably work with Matlab as well.
% It has been run successfully on GNU Octave 3.2.2.
% This script generates test vectors (which it places into a file named
% "fft_test_vectors.txt") which fft_tester.c can process.
%
% ../fft.c is capable of both forward and inverse FFTs, and can do a
% double-size real (forward or inverse) FFT. So all those FFT variants need to
% be tested. Thus the test code in ../fft.c expects the test cases to have the
% following variants, in order:
% 1. forward, normal-sized,
% 2. inverse, normal-sized,
% 3. forward, double-sized,
% 4. inverse, double-sized.
%
% This file is licensed as described by the file LICENCE.

global FFT_SIZE = 256; % size of normal-sized FFT
global file_id; % file ID of file to write test vectors to

function outputRealArray(v)
	global file_id;
	% 10 digits means more than 32 bits of precision, which should cover all
	% possible Q16.16 values.
	fprintf(file_id, "%.10g\n", v);
end

function outputComplexArray(v)
	global file_id;
	fprintf(file_id, "%.10g\n", real(v));
	fprintf(file_id, "%.10g\n", imag(v));
end

file_id = fopen("fft_test_vectors.txt", "wt");

% Convention: x = time domain, X = frequency domain.
% Sometimes, the inverse tests will have the input scaled up so that the
% output isn't pitifully small.

% Test zero response. This is mainly a check to make sure the device under
% test is accepting test cases probably.
x = zeros(FFT_SIZE, 1);
X = fft(x);
fprintf(file_id, "Forward zero response (normal)\n");
outputComplexArray(x);
outputComplexArray(X);
X = zeros(FFT_SIZE, 1);
x = ifft(X);
fprintf(file_id, "Inverse zero response (normal)\n");
outputComplexArray(X);
outputComplexArray(x);
x = zeros(FFT_SIZE * 2, 1);
X = fft(x);
fprintf(file_id, "Forward zero response (double)\n");
outputRealArray(x);
outputComplexArray(X(1: FFT_SIZE + 1));
X = zeros(FFT_SIZE * 2, 1);
x = ifft(X);
fprintf(file_id, "Inverse zero response (double)\n");
outputRealArray(X);
outputComplexArray(x(1: FFT_SIZE + 1));

% Test overflow detection. These tests must have "overflow detection"
% in their names.
x = ones(FFT_SIZE, 1) * 1000;
X = zeros(FFT_SIZE, 1);
fprintf(file_id, "Forward overflow detection (normal)\n");
outputComplexArray(x);
outputComplexArray(X);
X = ones(FFT_SIZE, 1) * 1000;
x = zeros(FFT_SIZE, 1);
fprintf(file_id, "Inverse overflow detection (normal)\n");
outputComplexArray(X);
outputComplexArray(x);
x = ones(FFT_SIZE * 2, 1) * 1000;
X = zeros(FFT_SIZE * 2, 1);
fprintf(file_id, "Forward overflow detection (double)\n");
outputRealArray(x);
outputComplexArray(X(1: FFT_SIZE + 1));
X = ones(FFT_SIZE * 2, 1) * 1000;
x = zeros(FFT_SIZE * 2, 1);
fprintf(file_id, "Inverse overflow detection (double)\n");
outputRealArray(X);
outputComplexArray(x(1: FFT_SIZE + 1));

% Test unit impulse response. This is one of the simplest non-zero FFT test
% cases. If these tests fail, there's little hope that any of the following
% tests will succeed.
x = zeros(FFT_SIZE, 1);
x(1) = 1;
X = fft(x);
fprintf(file_id, "Forward unit impulse response (normal)\n");
outputComplexArray(x);
outputComplexArray(X);
X = zeros(FFT_SIZE, 1);
X(1) = 1;
x = ifft(X);
fprintf(file_id, "Inverse unit impulse response (normal)\n");
outputComplexArray(X);
outputComplexArray(x);
x = zeros(FFT_SIZE * 2, 1);
x(1) = 1;
X = fft(x);
fprintf(file_id, "Forward unit impulse response (double)\n");
outputRealArray(x);
outputComplexArray(X(1: FFT_SIZE + 1));
X = zeros(FFT_SIZE * 2, 1);
X(1) = 1;
x = ifft(X);
fprintf(file_id, "Inverse unit impulse response (double)\n");
outputRealArray(X);
outputComplexArray(x(1: FFT_SIZE + 1));

% Test FFT on constant signal. This is dual to the unit response test.
x = ones(FFT_SIZE, 1) * -2;
X = fft(x);
fprintf(file_id, "Forward constant signal (normal)\n");
outputComplexArray(x);
outputComplexArray(X);
X = ones(FFT_SIZE, 1) * -2;
x = ifft(X);
fprintf(file_id, "Inverse constant signal (normal)\n");
outputComplexArray(X);
outputComplexArray(x);
x = ones(FFT_SIZE * 2, 1) * -2;
X = fft(x);
fprintf(file_id, "Forward constant signal (double)\n");
outputRealArray(x);
outputComplexArray(X(1: FFT_SIZE + 1));
X = ones(FFT_SIZE * 2, 1) * -2;
x = ifft(X);
fprintf(file_id, "Inverse constant signal (double)\n");
outputRealArray(X);
outputComplexArray(x(1: FFT_SIZE + 1));

% Test shift property of FFT. This is a basic property which the FFT obeys.
% This does not exhaustively test the shift property.
x = zeros(FFT_SIZE, 1);
x(5) = 1;
X = fft(x);
fprintf(file_id, "Forward shift property (normal)\n");
outputComplexArray(x);
outputComplexArray(X);
X = zeros(FFT_SIZE, 1);
X(5) = 100;
x = ifft(X);
fprintf(file_id, "Inverse shift property (normal)\n");
outputComplexArray(X);
outputComplexArray(x);
x = zeros(FFT_SIZE * 2, 1);
x(5) = 1;
X = fft(x);
fprintf(file_id, "Forward shift property (double)\n");
outputRealArray(x);
outputComplexArray(X(1: FFT_SIZE + 1));
X = zeros(FFT_SIZE * 2, 1);
X(5) = 100;
x = ifft(X);
fprintf(file_id, "Inverse shift property (double)\n");
outputRealArray(X);
outputComplexArray(x(1: FFT_SIZE + 1));

% Test linearity of FFT. This is a basic property which the FFT obeys.
% This does not exhaustively test linearity.
x = zeros(FFT_SIZE, 1);
x(5) = 7 - j;
x(20) = -2 - 2j;
X = fft(x);
fprintf(file_id, "Forward linearity 1 (normal)\n");
outputComplexArray(x);
outputComplexArray(X);
X = zeros(FFT_SIZE, 1);
X(2) = -40 - j;
X(3) = 42 + 43j;
x = ifft(X);
fprintf(file_id, "Inverse linearity 1 (normal)\n");
outputComplexArray(X);
outputComplexArray(x);
x = zeros(FFT_SIZE * 2, 1);
x(2) = 7;
x(21) = -2;
X = fft(x);
fprintf(file_id, "Forward linearity 1 (double)\n");
outputRealArray(x);
outputComplexArray(X(1: FFT_SIZE + 1));
X = zeros(FFT_SIZE * 2, 1);
X((2 * FFT_SIZE) - 2) = -40;
X((2 * FFT_SIZE) - 1) = 42;
x = ifft(X);
fprintf(file_id, "Inverse linearity 1 (double)\n");
outputRealArray(X);
outputComplexArray(x(1: FFT_SIZE + 1));
x = zeros(FFT_SIZE, 1);
x(FFT_SIZE) = 1 + j;
x(32) = -10j;
X = fft(x);
fprintf(file_id, "Forward linearity 2 (normal)\n");
outputComplexArray(x);
outputComplexArray(X);
X = zeros(FFT_SIZE, 1);
X(FFT_SIZE - 20) = -100j;
X(FFT_SIZE - 42) = 200j;
x = ifft(X);
fprintf(file_id, "Inverse linearity 2 (normal)\n");
outputComplexArray(X);
outputComplexArray(x);
x = zeros(FFT_SIZE * 2, 1);
x(3) = 7;
x(22) = -2;
X = fft(x);
fprintf(file_id, "Forward linearity 2 (double)\n");
outputRealArray(x);
outputComplexArray(X(1: FFT_SIZE + 1));
X = zeros(FFT_SIZE * 2, 1);
X((2 * FFT_SIZE) - 1) = -40;
X((2 * FFT_SIZE)) = 42;
x = ifft(X);
fprintf(file_id, "Inverse linearity 2 (double)\n");
outputRealArray(X);
outputComplexArray(x(1: FFT_SIZE + 1));

% Test FFT on sine and cosine data. The frequency of the sines/cosines matches
% one of the FFT frequency bins exactly.
steps_normal = transpose([0:(FFT_SIZE - 1)]);
steps_double = transpose([0:((FFT_SIZE * 2) - 1)]);
x = sin(2 * pi * 17 * steps_normal / FFT_SIZE);
X = fft(x);
fprintf(file_id, "Forward sine on-frequency (normal)\n");
outputComplexArray(x);
outputComplexArray(X);
X = sin(2 * pi * 17 * steps_normal / FFT_SIZE) * 100;
x = ifft(X);
fprintf(file_id, "Inverse sine on-frequency (normal)\n");
outputComplexArray(X);
outputComplexArray(x);
x = sin(2 * pi * 17 * steps_double / (FFT_SIZE * 2));
X = fft(x);
fprintf(file_id, "Forward sine on-frequency (double)\n");
outputRealArray(x);
outputComplexArray(X(1: FFT_SIZE + 1));
X = sin(2 * pi * 17 * steps_double / (FFT_SIZE * 2)) * 100;
x = ifft(X);
fprintf(file_id, "Inverse sine on-frequency (double)\n");
outputRealArray(X);
outputComplexArray(x(1: FFT_SIZE + 1));
x = cos(2 * pi * 17 * steps_normal / FFT_SIZE);
X = fft(x);
fprintf(file_id, "Forward cosine on-frequency (normal)\n");
outputComplexArray(x);
outputComplexArray(X);
X = cos(2 * pi * 17 * steps_normal / FFT_SIZE) * 100;
x = ifft(X);
fprintf(file_id, "Inverse cosine on-frequency (normal)\n");
outputComplexArray(X);
outputComplexArray(x);
x = cos(2 * pi * 17 * steps_double / (FFT_SIZE * 2));
X = fft(x);
fprintf(file_id, "Forward cosine on-frequency (double)\n");
outputRealArray(x);
outputComplexArray(X(1: FFT_SIZE + 1));
X = cos(2 * pi * 17 * steps_double / (FFT_SIZE * 2)) * 100;
x = ifft(X);
fprintf(file_id, "Inverse cosine on-frequency (double)\n");
outputRealArray(X);
outputComplexArray(x(1: FFT_SIZE + 1));

% Test FFT on sine and cosine data with a frequency that doesn't match
% a frequency bin exactly.
x = sin(2 * pi * sqrt(59) * steps_normal / FFT_SIZE);
X = fft(x);
fprintf(file_id, "Forward sine off-frequency (normal)\n");
outputComplexArray(x);
outputComplexArray(X);
X = sin(2 * pi * sqrt(59) * steps_normal / FFT_SIZE) * 100;
x = ifft(X);
fprintf(file_id, "Inverse sine off-frequency (normal)\n");
outputComplexArray(X);
outputComplexArray(x);
x = sin(2 * pi * sqrt(59) * steps_double / (FFT_SIZE * 2));
X = fft(x);
fprintf(file_id, "Forward sine off-frequency (double)\n");
outputRealArray(x);
outputComplexArray(X(1: FFT_SIZE + 1));
X = sin(2 * pi * sqrt(59) * steps_double / (FFT_SIZE * 2)) * 100;
x = ifft(X);
fprintf(file_id, "Inverse sine off-frequency (double)\n");
outputRealArray(X);
outputComplexArray(x(1: FFT_SIZE + 1));
x = cos(2 * pi * sqrt(59) * steps_normal / FFT_SIZE);
X = fft(x);
fprintf(file_id, "Forward cosine off-frequency (normal)\n");
outputComplexArray(x);
outputComplexArray(X);
X = cos(2 * pi * sqrt(59) * steps_normal / FFT_SIZE) * 100;
x = ifft(X);
fprintf(file_id, "Inverse cosine off-frequency (normal)\n");
outputComplexArray(X);
outputComplexArray(x);
x = cos(2 * pi * sqrt(59) * steps_double / (FFT_SIZE * 2));
X = fft(x);
fprintf(file_id, "Forward cosine off-frequency (double)\n");
outputRealArray(x);
outputComplexArray(X(1: FFT_SIZE + 1));
X = cos(2 * pi * sqrt(59) * steps_double / (FFT_SIZE * 2)) * 100;
x = ifft(X);
fprintf(file_id, "Inverse cosine off-frequency (double)\n");
outputRealArray(X);
outputComplexArray(x(1: FFT_SIZE + 1));

% Test FFT on (pseudo-)random data. The pseudo-random data is normally
% distributed. Such data has the same characteristics as what would be
% expected from a noise source.
% The standard deviation of the distribution is varied, to check that the
% FFT works correctly on a wide range of noise source amplitudes.
test_stdev = 0.01;
while (test_stdev < 25)
	x = (randn(FFT_SIZE, 1) + randn(FFT_SIZE, 1) * j) * test_stdev;
	X = fft(x);
	fprintf(file_id, "Forward pseudo-random, stdev = %g (normal)\n", test_stdev);
	outputComplexArray(x);
	outputComplexArray(X);
	fprintf(file_id, "Inverse pseudo-random, stdev = %g (normal)\n", test_stdev);
	outputComplexArray(X);
	outputComplexArray(x);
	x = randn(FFT_SIZE * 2, 1) * test_stdev;
	X = fft(x);
	fprintf(file_id, "Forward pseudo-random, stdev = %g (double)\n", test_stdev);
	outputRealArray(x);
	outputComplexArray(X(1: FFT_SIZE + 1));
	if (test_stdev < 5)
		X = randn(FFT_SIZE * 2, 1) * test_stdev * 50;
	else
		% Don't let X get too large or overflow will occur.
		X = randn(FFT_SIZE * 2, 1) * 250;
	end
	x = ifft(X);
	fprintf(file_id, "Inverse pseudo-random, stdev = %g (double)\n", test_stdev);
	outputRealArray(X);
	outputComplexArray(x(1: FFT_SIZE + 1));
	test_stdev = test_stdev * 1.1;
end

fclose(file_id);

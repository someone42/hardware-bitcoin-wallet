% Calculates FIR low-pass filter coefficients using the window design method.
%
% This is a GNU Octave script file. It will probably work with Matlab as well.
% It has been run successfully on GNU Octave 3.2.2.

% Parameters.
HALF_ORDER = 8;
ORDER = 2 * HALF_ORDER + 1;
CUTOFF_FREQUENCY = 0.2;
FFT_SIZE = 4096;

% Calculate and display filter coefficients (in Q16.16 fixed-point
% representation).
filter_coefficients = sinc(2 * CUTOFF_FREQUENCY * [-HALF_ORDER:HALF_ORDER].') .* hamming(ORDER);
filter_coefficients_sum = sum(filter_coefficients);
filter_coefficients = filter_coefficients / filter_coefficients_sum;
integer_coefficients = round(filter_coefficients * (2 ^ 16));
filter_coefficients = integer_coefficients / (2 ^ 16);
num2str(integer_coefficients, 12)

% Plot frequency response.
filter_response = abs(fft(filter_coefficients, FFT_SIZE)) .^ 2;
filter_response = filter_response(1: FFT_SIZE / 2);
plot([0:(FFT_SIZE / 2) - 1] / FFT_SIZE, log10(filter_response.') * 10);
title(["Low-pass frequency response, cutoff = ", num2str(CUTOFF_FREQUENCY), ", order = ", num2str(ORDER)]);
xlabel("Frequency (normalised to sample rate)");
ylabel("Gain (dB)");
grid("minor");

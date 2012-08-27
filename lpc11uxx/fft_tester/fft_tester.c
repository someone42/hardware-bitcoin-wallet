// ***********************************************************************
// fft_tester.c
// ***********************************************************************
//
// Read test vectors from fft_test_vectors.txt and send them to hardware
// Bitcoin wallet. The firmware should be compiled with the "TEST_FFT"
// preprocessor definition set.
//
// generate_test_vectors.m is a GNU Octave script which can
// be used to generate those test vectors. The test vectors compare the
// results of forward and inverse FFTs done by GNU Octave with FFTs done by
// the code in ../fft.c.
//
// This also shows how much time (in clock cycles) each FFT required; this
// is useful for benchmarking.
//
// This file is licensed as described by the file LICENCE.

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

#include "../fix16.h"
#include "../fft.h" // include for FFT_SIZE

// The total relative error of the FFT result must be less than this in order
// for a test to pass. "Error" is the difference between the actual and
// expected output. Total relative error is the sum of errors for a FFT buffer
// divided by the sum of absolute values of the FFT result.
// This error metric is used because sometimes, if a FFT buffer contains
// a small value within lots of large values, that small value can have a
// large relative error ("transferred" to it from the large values during the
// FFT). This error metric takes into account the surrounding large values.
#define SUM_ERROR_THRESHOLD				0.001

// Every value in the FFT buffer must pass the absolute or relative error
// test (or both). If a single value fails both the absolute and relative
// error tests, then the entire FFT result is considered invalid.

// The absolute error test: the error must be lower than this.
// For Q16.16, this is 200 LSB.
#define ERROR_EPSILON					0.0030517578125
// The relative error test: the error divided by expected value must be
// lower than this. For values close to 0, the relative error can be huge;
// that's why there is also an absolute error test.
#define ERROR_FACTOR					0.02


// The default number of bytes (transmitted or received) in between
// acknowledgments.
#define DEFAULT_ACKNOWLEDGE_INTERVAL	16
// The number of received bytes in between acknowledgments that this program
// will use (doesn't have to be the default).
#define RX_ACKNOWLEDGE_INTERVAL			32

// Remaining number of bytes that can be transmitted before listening for
// acknowledge.
static uint32_t tx_bytes_to_ack;
// Remaining number of bytes that can be received before other side expects an
// acknowledge.
static uint32_t rx_bytes_to_ack;

int fd_serial; // file descriptor for serial port

// Floating-point complex number.
typedef struct Complex_struct
{
	double real;
	double imag;
} Complex;

// Write the 32-bit unsigned integer specified by in into the byte array
// specified by out. This will write the bytes in a little-endian format.
static void writeU32LittleEndian(uint8_t *out, uint32_t in)
{
	out[0] = (uint8_t)in;
	out[1] = (uint8_t)(in >> 8);
	out[2] = (uint8_t)(in >> 16);
	out[3] = (uint8_t)(in >> 24);
}

// Read a 32-bit unsigned integer from the byte array specified by in.
// The bytes will be read in a little-endian format.
static uint32_t readU32LittleEndian(uint8_t *in)
{
	return ((uint32_t)in[0])
		| ((uint32_t)in[1] << 8)
		| ((uint32_t)in[2] << 16)
		| ((uint32_t)in[3] << 24);
}

// From fix16.h
static fix16_t fix16_from_dbl(double a)
{
	double temp = a * fix16_one;
#ifndef FIXMATH_NO_ROUNDING
	temp += (temp >= 0) ? 0.5f : -0.5f;
#endif
	return (fix16_t)temp;
}

// From fix16.h
static double fix16_to_dbl(fix16_t a)
{
	return (double)a / fix16_one;
}

// Get a byte from the serial link, sending an acknowledgement if required.
static uint8_t receiveByte(void)
{
	uint8_t ack_buffer[5];
	uint8_t buffer;

	read(fd_serial, &buffer, 1);
	rx_bytes_to_ack--;
	if (!rx_bytes_to_ack)
	{
		rx_bytes_to_ack = RX_ACKNOWLEDGE_INTERVAL;
		ack_buffer[0] = 0xff;
		writeU32LittleEndian(&(ack_buffer[1]), rx_bytes_to_ack);
		write(fd_serial, ack_buffer, 5);
	}
	return buffer;
}

// Send a byte to the serial link, waiting for acknowledgement if required.
static void sendByte(uint8_t data)
{
	uint8_t ack_buffer[5];
	uint8_t buffer;

	buffer = data;
	write(fd_serial, &buffer, 1);
	tx_bytes_to_ack--;
	if (!tx_bytes_to_ack)
	{
		read(fd_serial, ack_buffer, 5);
		if (ack_buffer[0] != 0xff)
		{
			printf("Unexpected acknowledgement format (%d)\n", (int)ack_buffer[0]);
			printf("Exiting, since the serial link is probably dodgy\n");
			exit(1);
		}
		tx_bytes_to_ack = readU32LittleEndian(&(ack_buffer[1]));
	}
}

// Read an array of double-precision real numbers from a file. Each number
// should be on a separate line.
static void readRealArray(FILE *f, double *array, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
	{
		fscanf(f, "%lg\n", &(array[i]));
	}
}

// Read an array of double-precision complex numbers from a file. Each number
// should be on a separate line. The real components of every complex number
// in the array should be listed, followed by the imaginary components of
// every complex number.
// Why expect complex numbers in this format? Because it makes the GNU
// Octave script simpler.
static void readComplexArray(FILE *f, Complex *array, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
	{
		fscanf(f, "%lg\n", &(array[i].real));
	}
	for (i = 0; i < size; i++)
	{
		fscanf(f, "%lg\n", &(array[i].imag));
	}
}

// Receive real number from serial link. The real number should be in Q16.16
// representation. This is so that the device under test doesn't have to
// do the conversion to floating-point.
static double receiveDouble(void)
{
	uint8_t buffer[4];
	int j;

	for (j = 0; j < 4; j++)
	{
		buffer[j] = receiveByte();
	}
	// The cast from uint32_t to fix16_t isn't platform-independent, because
	// the C99 specification doesn't make any guarantees about conversions
	// to signed integer types (...if the destination type cannot store the
	// source value, which will be the case if the fix16_t is negative).
	// But it should work on nearly every contemporary platform.
	return fix16_to_dbl((fix16_t)readU32LittleEndian(buffer));
}

// Send real number from serial link. The real number should be in Q16.16
// representation.
static void sendDouble(double value)
{
	uint8_t buffer[4];
	int j;

	if ((value > 32767.99998) || (value < -32767.99998))
	{
		printf("Tried to send \"%g\", which is outside the limits of fix16_t.\n", value);
		exit(1);
	}
	else
	{
		writeU32LittleEndian(buffer, (uint32_t)fix16_from_dbl(value));
		for (j = 0; j < 4; j++)
		{
			sendByte(buffer[j]);
		}
	}
}

// Receive complex number array from serial link. The numbers are expected to
// be interleaved: real[0], imaginary[0], real[1], imaginary[1] ...etc.
// This interleaving corresponds to how complex numbers are stored in memory.
static void receiveComplexArray(Complex *array, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
	{
		array[i].real = receiveDouble();
		array[i].imag = receiveDouble();
	}
}

// Checks whether the given complex array represents a FFT error.
// The device under test signals a FFT error by sending an array consisting
// of all fix16_overflow.
static int isComplexArrayError(Complex *array, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
	{
		if ((array[i].real != fix16_to_dbl(fix16_overflow))
			|| (array[i].imag != fix16_to_dbl(fix16_overflow)))
		{
			return 0;
		}
	}
	return 1;
}

// Send real array over serial link.
static void sendRealArray(double *array, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
	{
		sendDouble(array[i]);
	}
}

// Send complex array over serial link, interleaving the real and imaginary
// components (as described above).
static void sendComplexArray(Complex *array, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
	{
		sendDouble(array[i].real);
		sendDouble(array[i].imag);
	}
}

// Performs absolute and relative error tests.
// Returns 1 if at least one test passed, returns 0 if both tests failed.
int equalWithinTolerance(double target, double value)
{
	double difference;

	difference = fabs(target - value);
	if (difference > ERROR_EPSILON)
	{
		if (target != 0.0)
		{
			if ((difference / fabs(target)) > ERROR_FACTOR)
			{
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}
	return 1;
}

// Check whether every value within a complex array matches every value within
// another complex array. This does an absolute and relative error test for
// each value, and also checks the total relative error.
// Returns 1 if all tests pass ("they are equal within error tolerance"), 0 if
// at least one test failed ("they are not equal within error tolerance").
int complexArraysEqualWithinTolerance(Complex *target, Complex *value, uint32_t size)
{
	uint32_t i;
	double error_sum;
	double target_size;

	error_sum = 0;
	target_size = 0;
	for (i = 0; i < size; i++)
	{
		if (!equalWithinTolerance(target[i].real, value[i].real))
		{
			printf("%d.real mismatch ", i);
			return 0;
		}
		if (!equalWithinTolerance(target[i].imag, value[i].imag))
		{
			printf("%d.imag mismatch ", i);
			return 0;
		}
		error_sum += fabs(target[i].real - value[i].real);
		error_sum += fabs(target[i].imag - value[i].imag);
		target_size += fabs(target[i].real);
		target_size += fabs(target[i].imag);
	}
	if (target_size != 0)
	{
		error_sum /= target_size;
	}
	printf("err: %lg ", error_sum);
	if (error_sum > SUM_ERROR_THRESHOLD)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

int main(int argc, char **argv)
{
	int i;
	int j;
	int matches;
	int is_overflow_detection;
	int succeeded;
	int failed;
	char *newline_position;
	char buffer[512];
	uint8_t cycles_buffer[4];
	Complex input_normal[FFT_SIZE]; // input (normal-sized)
	Complex expected_normal[FFT_SIZE]; // expected output (normal-sized)
	Complex output_normal[FFT_SIZE]; // actual output (normal-sized)
	double input_double[FFT_SIZE * 2]; // input (double-sized)
	Complex expected_double[FFT_SIZE + 1]; // expected output (double-sized)
	Complex output_double[FFT_SIZE + 1]; // actual output (double-sized)
	FILE *f_vectors; // file containing test vectors
	struct termios options;
	struct termios old_options;

	if (argc != 2)
	{
		printf("Usage: %s <serial device>\n", argv[0]);
		printf("\n");
		printf("Example: %s /dev/ttyUSB0\n", argv[0]);
		exit(1);
	}

	// Attempt to open serial link.
	fd_serial = open(argv[1], O_RDWR | O_NOCTTY);
	if (fd_serial == -1)
	{
		printf("Could not open device \"%s\"\n", argv[1]);
		printf("Make sure you have permission to open it. In many systems, only\n");
		printf("root can access devices by default.\n");
		exit(1);
	}

	fcntl(fd_serial, F_SETFL, 0); // block on reads
	tcgetattr(fd_serial, &old_options); // save configuration
	memcpy(&options, &old_options, sizeof(options));
	cfsetispeed(&options, B57600); // baud rate 57600
	cfsetospeed(&options, B57600);
	options.c_cflag |= (CLOCAL | CREAD); // enable receiver and set local mode on
	options.c_cflag &= ~PARENB; // no parity
	options.c_cflag &= ~CSTOPB; // 1 stop bit
	options.c_cflag &= ~CSIZE; // character size mask
	options.c_cflag |= CS8; // 8 data bits
	options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG); // raw input
	options.c_lflag &= ~(XCASE | ECHOK | ECHONL | ECHOCTL | ECHOPRT | ECHOKE); // disable more stuff
	options.c_iflag &= ~(IXON | IXOFF | IXANY); // no software flow control
	options.c_iflag &= ~(INPCK | INLCR | IGNCR | ICRNL | IUCLC); // disable more stuff
	options.c_oflag &= ~OPOST; // raw output
	tcsetattr(fd_serial, TCSANOW, &options);
	rx_bytes_to_ack = DEFAULT_ACKNOWLEDGE_INTERVAL;
	tx_bytes_to_ack = DEFAULT_ACKNOWLEDGE_INTERVAL;

	// Attempt to open file containing test vectors.
	f_vectors = fopen("fft_test_vectors.txt", "r");
	if (f_vectors == NULL)
	{
		printf("Could not open \"fft_test_vectors.txt\" for reading\n");
		exit(1);
	}

	succeeded = 0;
	failed = 0;
	while (!feof(f_vectors))
	{
		for (i = 0; i < 4; i++)
		{
			// Read name of test.
			fgets(buffer, sizeof(buffer), f_vectors);
			if (strstr(buffer, "overflow detection") != NULL)
			{
				is_overflow_detection = 1;
			}
			else
			{
				is_overflow_detection = 0;
			}
			// Remove newlines.
			newline_position = strrchr(buffer, '\n');
			if (newline_position != NULL)
			{
				*newline_position = '\0';
			}
			newline_position = strrchr(buffer, '\r');
			if (newline_position != NULL)
			{
				*newline_position = '\0';
			}
			printf("%s:\n    ", buffer);
			if (i < 2)
			{
				// Normal-sized tests.
				readComplexArray(f_vectors, input_normal, FFT_SIZE);
				readComplexArray(f_vectors, expected_normal, FFT_SIZE);
				sendComplexArray(input_normal, FFT_SIZE);
				receiveComplexArray(output_normal, FFT_SIZE);
				if (isComplexArrayError(output_normal, FFT_SIZE))
				{
					printf("FFT ERROR ");
					matches = is_overflow_detection;
				}
				else
				{
					matches = complexArraysEqualWithinTolerance(expected_normal, output_normal, FFT_SIZE);
				}
			}
			else
			{
				// Double-sized tests.
				readRealArray(f_vectors, input_double, FFT_SIZE * 2);
				readComplexArray(f_vectors, expected_double, FFT_SIZE + 1);
				sendRealArray(input_double, FFT_SIZE * 2);
				receiveComplexArray(output_double, FFT_SIZE + 1);
				if (isComplexArrayError(output_double, FFT_SIZE + 1))
				{
					printf("FFT ERROR ");
					matches = is_overflow_detection;
				}
				else
				{
					matches = complexArraysEqualWithinTolerance(expected_double, output_double, FFT_SIZE + 1);
				}
			}
			// Get number of cycles required to do FFT.
			for (j = 0; j < 4; j++)
			{
				cycles_buffer[j] = receiveByte();
			}
			printf("cycles = %u ", readU32LittleEndian(cycles_buffer));
			if (matches)
			{
				printf("[pass]\n");
				succeeded++;
			}
			else
			{
				printf("[fail]\n");
				// Make failure noticable.
				printf("************************\n");
				printf("FAIL FAIL FAIL FAIL FAIL\n");
				printf("************************\n");
				failed++;
			}
		}
	}

	printf("Tests which succeeded: %d\n", succeeded);
	printf("Tests which failed: %d\n", failed);

	fclose(f_vectors);
	tcsetattr(fd_serial, TCSANOW, &old_options); // restore configuration
	close(fd_serial);
	exit(0);
}

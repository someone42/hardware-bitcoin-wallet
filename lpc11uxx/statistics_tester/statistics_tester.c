// ***********************************************************************
// statistics_tester.c
// ***********************************************************************
//
// Read test vectors from statistics_test_vectors.txt and send them to
// hardware Bitcoin wallet. The firmware should be compiled with the
// "TEST_STATISTICS" preprocessor definition set.
//
// generate_test_vectors.m is a GNU Octave script which can
// be used to generate those test vectors.
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
#include "../statistics.h" // include for SAMPLE_COUNT

// Number of real-valued outputs which the device will send.
#define OUTPUTS_TO_CHECK				5

// The absolute error test: the error must be lower than this.
// For Q16.16, this is 4 LSB.
#define ERROR_EPSILON					0.00006103515625
// The relative error test: the error divided by expected value must be
// lower than this. For values close to 0, the relative error can be huge;
// that's why there is also an absolute error test.
#define ERROR_FACTOR					0.0001

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

// Read an array of integers from a file. Each number should be on a separate
// line.
static void readIntegerArray(FILE *f, int *array, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
	{
		fscanf(f, "%d\n", &(array[i]));
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

// Receive real number array from serial link.
static void receiveRealArray(double *array, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
	{
		array[i] = receiveDouble();
	}
}

// Send 16-bit integer array over serial link.
static void sendIntegerArray(int *array, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
	{
		if ((array[i] < 0) || (array[i] > 65535))
		{
			printf("Tried to send \"%d\", which is outside the limits of uint16_t.\n", array[i]);
			exit(1);
		}
		sendByte((uint8_t)array[i]);
		sendByte((uint8_t)(array[i] >> 8));
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

// Check whether every value within a real array matches every value within
// another real array. This does an absolute and relative error test for
// each value.
// Returns 1 if all tests pass ("they are equal within error tolerance"), 0 if
// at least one test failed ("they are not equal within error tolerance").
int realArraysEqualWithinTolerance(double *target, double *value, uint32_t size)
{
	uint32_t i;

	for (i = 0; i < size; i++)
	{
		if (!equalWithinTolerance(target[i], value[i]))
		{
			printf("%d mismatch ", i);
			return 0;
		}
	}
	return 1;
}


int main(int argc, char **argv)
{
	int matches;
	int succeeded;
	int failed;
	char *newline_position;
	char buffer[512];
	int input_array[SAMPLE_COUNT];
	double expected_array[OUTPUTS_TO_CHECK];
	double output_array[OUTPUTS_TO_CHECK];
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
	f_vectors = fopen("statistics_test_vectors.txt", "r");
	if (f_vectors == NULL)
	{
		printf("Could not open \"statistics_test_vectors.txt\" for reading\n");
		exit(1);
	}

	succeeded = 0;
	failed = 0;
	while (!feof(f_vectors))
	{
		// Read name of test.
		fgets(buffer, sizeof(buffer), f_vectors);
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

		readIntegerArray(f_vectors, input_array, SAMPLE_COUNT);
		readRealArray(f_vectors, expected_array, OUTPUTS_TO_CHECK);
		sendIntegerArray(input_array, SAMPLE_COUNT);
		receiveRealArray(output_array, OUTPUTS_TO_CHECK);
		matches = realArraysEqualWithinTolerance(expected_array, output_array, OUTPUTS_TO_CHECK);
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

	printf("Tests which succeeded: %d\n", succeeded);
	printf("Tests which failed: %d\n", failed);

	fclose(f_vectors);
	tcsetattr(fd_serial, TCSANOW, &old_options); // restore configuration
	close(fd_serial);
	exit(0);
}

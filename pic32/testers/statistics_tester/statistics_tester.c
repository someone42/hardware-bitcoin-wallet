// ***********************************************************************
// statistics_tester.c
// ***********************************************************************
//
// Read test vectors from statistics_test_vectors.txt and send them to
// hardware Bitcoin wallet using a CP2110-like USB HID wire protocol.
// The firmware should be compiled with the "TEST_STATISTICS" preprocessor
// definition set. This uses HIDAPI.
//
// generate_test_vectors.m is a GNU Octave script which can
// be used to generate those test vectors.
//
// This also shows how much time (in clock cycles) was required to calculate
// the statistics of a histogram with SAMPLE_COUNT samples. This is useful
// for benchmarking.
//
// This file is licensed as described by the file LICENCE.

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include "hidapi/hidapi.h"

#include "../../../fix16.h"
#include "../../../statistics.h" // include for SAMPLE_COUNT

// Vendor ID of target device. This must match the vendor ID in the
// device's device descriptor.
#define TARGET_VID				0x04f3
// Product ID of target device. This must match the product ID in the
// device's device descriptor.
#define TARGET_PID				0x0210

// Number of real-valued outputs which the device will send.
#define OUTPUTS_TO_CHECK				5

// The absolute error test: the error must be lower than this.
// For Q16.16, this is 64 LSB.
#define ERROR_EPSILON					0.0009765625
// The relative error test: the error divided by expected value must be
// lower than this. For values close to 0, the relative error can be huge;
// that's why there is also an absolute error test.
#define ERROR_FACTOR					0.004

// Handle to HID device, so that it doesn't have to be passed as a parameter
// all the time.
static hid_device *handle;

// Most recently received report. This does include the report ID.
static uint8_t received_report[64];
// Size of most recently received report. This does include the report ID.
static unsigned int received_report_length;
// Next byte to grab from most recently received report.
static unsigned int received_report_index;
// Report to send, which is built up as bytes are sent using sendByte().
// Does not include the report ID.
static uint8_t report_to_send[63];
// Current length of next report to send. Does not include the report ID.
static unsigned int report_to_send_length;

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
static double fix16_to_dbl(fix16_t a)
{
	return (double)a / fix16_one;
}

// Get next byte from the current USB HID report.
static uint8_t receiveByte(void)
{
	int r;
	unsigned int data_size;

	while (received_report_index >= received_report_length)
	{
		// Finished with current report; need to get another report.
		r = hid_read(handle, received_report, sizeof(received_report));
		if (r < 0)
		{
			printf("hid_read() failed, error: %ls\n", hid_error(handle));
			exit(1);
		}
		else if (r == 0)
		{
			printf("Got 0 length report. That doesn't make sense.\n");
			exit(1);
		}
		data_size = received_report[0]; // report ID
		if ((data_size > 63) || (data_size > (unsigned int)(r - 1)))
		{
			printf("Got invalid report ID: %u\n", data_size);
			exit(1);
		}
		received_report_length = data_size + 1;
		received_report_index = 1;
	}
	return received_report[received_report_index++];
}

// Unconditionally send report_to_send over the USB HID link.
// Calling this too often leads to poor throughput.
static void flushReportToSend(void)
{
	uint8_t packet_buffer[64];

	if (report_to_send_length > 0)
	{
		packet_buffer[0] = (uint8_t)report_to_send_length;
		if (report_to_send_length > (sizeof(packet_buffer) - 1))
		{
			printf("Report too big in flushReportToSend()\n");
			exit(1);
		}
		memcpy(&(packet_buffer[1]), report_to_send, report_to_send_length);
		if (hid_write(handle, packet_buffer, report_to_send_length + 1) < 0)
		{
			printf("hid_write() failed, error: %ls\n", hid_error(handle));
			exit(1);
		}
		report_to_send_length = 0;
	}
}

// Queue byte for sending in the next USB HID report.
// This won't necessarily send anything. To flush the queue and actually
// send something, call flushReportToSend().
static void sendByte(uint8_t data)
{
	while (report_to_send_length >= sizeof(report_to_send))
	{
		// Report to send is full; flush it.
		flushReportToSend();
	}
	report_to_send[report_to_send_length++] = data;
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
	flushReportToSend();
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
	double difference;
	double max_difference;

	max_difference = 0;
	for (i = 0; i < size; i++)
	{
		difference = fabs(target[i] - value[i]);
		if (difference > max_difference)
		{
			max_difference = difference;
		}
	}
	printf(" max diff = %g ", max_difference);
	for (i = 0; i < size; i++)
	{
		if (!equalWithinTolerance(target[i], value[i]))
		{
			printf("%d mismatch target = %g value = %g ", i, target[i], value[i]);
			return 0;
		}
	}
	return 1;
}

int main(void)
{
	int i;
	int matches;
	int succeeded;
	int failed;
	char *newline_position;
	char buffer[512];
	int input_array[SAMPLE_COUNT];
	double expected_array[OUTPUTS_TO_CHECK];
	double output_array[OUTPUTS_TO_CHECK];
	FILE *f_vectors; // file containing test vectors
	uint8_t cycles_buffer[4];

	if (hid_init())
	{
		printf("hid_init() failed\n");
		exit(1);
	}

	// Open the device using the VID, PID,
	handle = hid_open(TARGET_VID, TARGET_PID, NULL);
	if (!handle)
	{
		printf("Unable to open target device.\n");
		printf("Are you running this as root?\n");
		printf("Is the device plugged in?\n");
 		exit(1);
	}

	// Attempt to open file containing test vectors.
	f_vectors = fopen("statistics_test_vectors.txt", "r");
	if (f_vectors == NULL)
	{
		printf("Could not open \"statistics_test_vectors.txt\" for reading\n");
		exit(1);
	}

	sendByte(0); // set device testing mode (see testStatistics() in ../hwrng.c)
	flushReportToSend();

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
		printf("%s: ", buffer);

		readIntegerArray(f_vectors, input_array, SAMPLE_COUNT);
		readRealArray(f_vectors, expected_array, OUTPUTS_TO_CHECK);
		sendIntegerArray(input_array, SAMPLE_COUNT);
		receiveRealArray(output_array, OUTPUTS_TO_CHECK);
		matches = realArraysEqualWithinTolerance(expected_array, output_array, OUTPUTS_TO_CHECK);
		// Get number of cycles required to do all tests.
		for (i = 0; i < 4; i++)
		{
			cycles_buffer[i] = receiveByte();
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

	printf("Tests which succeeded: %d\n", succeeded);
	printf("Tests which failed: %d\n", failed);

	fclose(f_vectors);
	hid_close(handle);
	// Free static HIDAPI objects. 
	hid_exit();
	exit(0);
}

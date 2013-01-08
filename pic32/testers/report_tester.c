// report_tester.c
//
// This will use libusb-1.0 to get and send reports to a USB HID device.
// libusb-1.0 is used instead of HIDAPI in order to do lower-level testing.
// This will use both control and interrupt transfers to receive/send reports.
// The format of reports is described in pic32/usb_hid_stream.c.
//
// This file is licensed as described by the file LICENCE.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <libusb.h>

// Vendor ID of target device. This must match the vendor ID in the
// device's device descriptor.
#define TARGET_VID			0x04f3
// Product ID of target device. This must match the product ID in the
// device's device descriptor.
#define TARGET_PID			0x0210

// Request timeout, in millisecond. This is long, so that debugging is easier.
// But it's not much worth in making it > 5 seconds, since sometimes control
// transfers will time out at 5 seconds regardless of this value.
#define TIMEOUT				5000

// Number of fast send tests per pass.
#define SEND_TESTS_FAST		2000
// Number of slow send tests per pass.
#define SEND_TESTS_SLOW		200
// Number of fast receive tests per pass.
#define RECEIVE_TESTS_FAST	2000
// Number of slow receive tests per pass.
#define RECEIVE_TESTS_SLOW	200
// Number of loopback tests per pass.
#define LOOPBACK_TESTS		2000

// Number of seconds to run send/receive benchmarks for.
#define BENCHMARK_TIME		10.0

// Number of tests which failed.
static unsigned int tests_failed;
// Number of tests which succeeded.
static unsigned int tests_succeeded;

// libusb-1.0 device handle of target device, so that it doesn't have to be
// passed around all the time.
libusb_device_handle *device_handle;

// Initialise libusb and attempt to open the target device.
// Returns the device handle on success.
// Returns NULL if the target device was not found.
static libusb_device_handle *init(void)
{
	int r;
	libusb_device **list;
	libusb_device_handle *opened_device_handle;
	struct libusb_device_descriptor device_info;
	ssize_t count;
	ssize_t i;
	int bus_number;
	int address;

   	r = libusb_init(NULL);
	if (r < 0)
	{
		printf("ERROR: Could not initialise libusb, return value = %d\n", r);
		exit(1);
	}

	// Loop through all buses/devices and find the right one.
	count = libusb_get_device_list(NULL, &list);
	for (i = 0; i < count; i++)
	{
		if (libusb_get_device_descriptor(list[i], &device_info) == 0)
		{
			if ((device_info.idVendor == TARGET_VID)
				&& (device_info.idProduct == TARGET_PID))
			{
				bus_number = libusb_get_bus_number(list[i]);
				address = libusb_get_device_address(list[i]);
				printf("Found device on bus %d, address = %d\n", bus_number, address);
				r = libusb_open(list[i], &opened_device_handle);
				if (r != 0)
				{
					printf("ERROR: Could not open device, %s\n", libusb_error_name(r));
					printf("Maybe you need to run this program as root.\n");
					printf("If using Windows, have you installed the WinUSB driver?\n");
					exit(1);
				}
				libusb_free_device_list(list, 1);
				// Just in case, detach kernel driver from interface.
				libusb_detach_kernel_driver(opened_device_handle, 0);
				libusb_detach_kernel_driver(opened_device_handle, 1);
				return opened_device_handle;
			}
		}
	}
	libusb_free_device_list(list, 1);
	return NULL;
}

// Eat up stdin until the beginning of the next line.
static void eatUpRestOfLine(void)
{
	do
	{
		// do nothing else
	} while (getchar() != '\n');
}

// Delay for a few seconds.
static void delay(void)
{
	time_t start_time;

	start_time = time(NULL);
	while (difftime(time(NULL), start_time) < 3.0)
	{
		// do nothing
	}
}

// Send a number of bytes to the control or interrupt out endpoint.
// This is persistent: it will keep trying even if a timeout occurs.
//
// buffer: bytes to send.
// data_length: number of bytes to send.
// send_to_control: non-zero = send to control endpoint, zero = send to
// interrupt out endpoint.
// Return values: non-negative = success, negative = failure.
static int sendBytes(uint8_t *buffer, int data_length, unsigned int send_to_control)
{
	uint8_t report_id;
	uint16_t wValue;
	int actual_length;
	int report_length;
	int r;
	uint8_t packet_buffer[64];

	do
	{
		report_id = (uint8_t)(data_length);
		packet_buffer[0] = report_id;
		memcpy(&(packet_buffer[1]), buffer, data_length);
		report_length = data_length + 1;
		if (send_to_control)
		{
			// Send to control endpoint using "Set Report" request.
			wValue = (uint16_t)(0x0200 | report_id);
			r = libusb_control_transfer(device_handle, 0x21,
				0x09, wValue, 0, packet_buffer, (uint16_t)report_length, TIMEOUT);
			if (r >= 0)
			{
				actual_length = r;
			}
			else
			{
				actual_length = 0;
			}
		}
		else
		{
			// Send to interrupt out endpoint.
			r = libusb_interrupt_transfer(device_handle, 0x02,
				packet_buffer, report_length, &actual_length, TIMEOUT);
		}
		if ((r >= 0) && (actual_length != report_length))
		{
			printf("Send length mismatch: desired: %d, actual: %d\n", data_length, actual_length);
			r = LIBUSB_ERROR_OTHER;
		}
	} while (r == LIBUSB_ERROR_TIMEOUT);

	return r;
}

// Receive a set number of bytes from the control or interrupt in endpoint.
// The bytes may be spread out over many packets.
// This is persistent: it will keep trying even if a timeout occurs.
//
// buffer: upon success, this will be filled with the received bytes.
// data_length: desired number of bytes to receive.
// actual_length: number of bytes received will be written here.
// one_packet: non-zero = receive one packet only (up to the size specified
// by data_length), zero = fill up buffer fully and complain if the number of
// received bytes does not exactly match the desired number of bytes.
// receive_from_control: non-zero = receive from control endpoint,
// zero = receive from interrupt in endpoint.
// Return values: non-negative = success, negative = failure.
static int receiveBytes(uint8_t *buffer, int data_length, int *actual_length, unsigned int one_packet, unsigned int receive_from_control)
{
	int r;
	int report_data_length;
	int total_received;
	int single_packet_length;
	uint16_t wValue;
	uint8_t packet_buffer[64];

	total_received = 0;
	r = 0;
	*actual_length = 0;
	while ((total_received < data_length) && ((r >= 0) || (r == LIBUSB_ERROR_TIMEOUT)))
	{
		if (receive_from_control)
		{
			if (one_packet)
			{
				printf("ERROR: This should never happen\n");
				exit(1);
			}
			// Receive from control endpoint using "Get Report" request.
			wValue = (uint16_t)(0x0100 | (uint8_t)data_length);
			// Note: the "+ 1" below is for the report ID byte.
			r = libusb_control_transfer(device_handle, 0xa1,
				0x01, wValue, 0, packet_buffer, (uint16_t)(data_length + 1), TIMEOUT);
			if (r >= 0)
			{
				single_packet_length = r;
				// Check that length matches desired length.
				if (single_packet_length != (data_length + 1))
				{
					printf("Got an unexpected report from control endpoint\n");
					printf("  expected length = %d, actual length = %d\n", data_length, single_packet_length);
					return LIBUSB_ERROR_OTHER;
				}
			}
			else
			{
				single_packet_length = 0;
			}
		}
		else
		{
			r = libusb_interrupt_transfer(device_handle, 0x81,
				packet_buffer, sizeof(packet_buffer), &single_packet_length, TIMEOUT);
		}
		if (r >= 0)
		{
			report_data_length = single_packet_length - 1;
			if (single_packet_length < 1)
			{
				printf("Report is too small\n");
				return LIBUSB_ERROR_OTHER;
			}
			else if ((int)packet_buffer[0] != report_data_length)
			{
				printf("Report ID doesn't match report length.\n");
				return LIBUSB_ERROR_OTHER;
			}
			else if ((total_received + report_data_length) > data_length)
			{
				printf("Report data will overrun buffer.\n");
				return LIBUSB_ERROR_OTHER;
			}
			else
			{
				// Fill up buffer with report contents.
				memcpy(&(buffer[total_received]), &(packet_buffer[1]), report_data_length);
				total_received += report_data_length;
				*actual_length = total_received;
			}
			if (one_packet)
			{
				break;
			}
		} // end if (r >= 0)
	}
	return r;
}

// Tests which send data to the device, expecting the device to return
// that data back at us.
// num_tests: number of test packets to send per pass.
static void loopbackTests(int num_tests)
{
	uint8_t loopback_data[64];
	uint8_t packet_buffer[64];
	int data_length;
	int actual_length;
	unsigned int pass;
	unsigned int send_to_control;
	unsigned int receive_from_control;
	int r;
	int i;
	int j;
	int abort;

	for (pass = 0; pass < 5; pass++)
	{
		for (i = 1; i < num_tests; i++)
		{
			// First exhaust all combinations of sending/receiving via.
			// control endpoint/interrupt endpoint. For the last pass,
			// randomly choose combinations, checking that the device reacts
			// to the changes appropriately.
			if (pass < 4)
			{
				send_to_control = pass & 1;
				receive_from_control = (pass & 2) >> 1;
			}
			else
			{
				send_to_control = (unsigned int)rand() & 1;
				receive_from_control = (unsigned int)rand() & 1;
			}
			// First group of tests exhausts all possible report IDs. After that,
			// just use random report IDs. Using random report IDs reflects
			// real world usage more accurately.
			if (i <= 63)
			{
				data_length = (uint8_t)i;
			}
			else
			{
				data_length = (uint8_t)((rand() % 63) + 1);
			}
			abort = 0;
			for (j = 0; j < data_length; j++)
			{
				loopback_data[j] = (uint8_t)rand();
			}
			memcpy(packet_buffer, loopback_data, data_length);

			// Send report.
			r = sendBytes(packet_buffer, data_length, send_to_control);
			if (r < 0)
			{
				printf("Send fail, pass = %d, i = %d, r = %s\n", pass, i, libusb_error_name(r));
				tests_failed++;
				abort = 1;
			}

			if (!abort)
			{
				// Receive report.
				r = receiveBytes(&(packet_buffer[1]), data_length, &actual_length, 0, receive_from_control);
				if (r < 0)
				{
					printf("Receive fail, pass = %d, i = %d, r = %s\n", pass, i, libusb_error_name(r));
					tests_failed++;
					abort = 1;
				}
			}

			if (!abort)
			{
				// Compare bytes.
				if (memcmp(&(packet_buffer[1]), loopback_data, data_length))
				{
					printf("Loopback data mismatch, pass = %d, i = %d\n", pass, i);
					tests_failed++;
				}
				else
				{
					tests_succeeded++;
				}
			}

		} // end for (i = 1; i < num_tests; i++)
	} // end for (pass = 0; pass < 5; pass++)
}

// Tests which unilaterally send data to the device.
// num_tests: number of test packets to send per pass.
// do_benchmark: non-zero means do throughput test, zero means don't do
// throughput test.
static void sendTests(int num_tests, int do_benchmark)
{
	uint8_t packet_buffer[64];
	uint8_t data_length;
	uint8_t counter;
	int r;
	int i;
	int j;
	unsigned int send_to_control;
	unsigned int total_bytes_sent;
	time_t start_time;

	printf("Warning: because these tests do not involve receives, it is difficult to\n");
	printf("determine whether a test succeeded or failed. Check the device for a red LED:\n");
	printf("if it is on, a test failed. Usually, after a test fails, all subsequent tests\n");
	printf("will also fail.\n");

	// Unlike with the loopback tests, it is not a good idea to rapidly switch
	// between control/interrupt endpoints, since scheduling of USB
	// transactions is not under our control. Thus rapid switching could result
	// in data arriving out of order.
	counter = 0;
	for (send_to_control = 0; send_to_control < 2; send_to_control++)
	{
		for (i = 1; i < num_tests; i++)
		{
			// First group of tests exhausts all possible report IDs. After that,
			// just use random report IDs. Using random report IDs reflects
			// real world usage more accurately.
			if (i <= 63)
			{
				data_length = (uint8_t)i;
			}
			else
			{
				data_length = (uint8_t)((rand() % 63) + 1);
			}
			packet_buffer[0] = data_length;
			for (j = 0; j < data_length; j++)
			{
				// The device will expect all reports to contain an
				// incrementing sequence. This checks that the order of
				// reports is well-defined.
				packet_buffer[j] = counter++;
			}
			r = sendBytes(packet_buffer, data_length, send_to_control);
			if (r < 0)
			{
				printf("Send fail, send_to_control = %u, i = %d, r = %s\n", send_to_control, i, libusb_error_name(r));
				tests_failed++;
			}
			else
			{
				tests_succeeded++;
			}
		} // end for (i = 1; i < num_tests; i++)

		if (do_benchmark)
		{
			delay();
			// Send maximum size packets as fast as possible.
			data_length = 63;
			total_bytes_sent = 0;
			start_time = time(NULL);
			do
			{
				for (j = 0; j < data_length; j++)
				{
					// The device will expect all reports to contain an
					// incrementing sequence. This checks that the order of
					// reports is well-defined.
					packet_buffer[j] = counter++;
				}
				r = sendBytes(packet_buffer, data_length, send_to_control);
				if (r < 0)
				{
					printf("Error during send throughput test, send_to_control = %u, r = %s\n", send_to_control, libusb_error_name(r));
					break;
				}
				total_bytes_sent += (unsigned int)data_length;
			} while (difftime(time(NULL), start_time) < BENCHMARK_TIME);
			printf("Send throughput for send_to_control = %u: %g bytes/sec\n", send_to_control, (double)total_bytes_sent / BENCHMARK_TIME);
		}

		if (send_to_control == 0)
		{
			// Need a delay in between modes, to avoid rapid switching between
			// endpoints (which could confuse the device).
			delay();
		}
	} // end for (send_to_control = 0; send_to_control < 2; send_to_control++)
}

// Tests which unilaterally receive data from the device.
// num_tests: number of test packets to receive per pass.
// do_benchmark: non-zero means do throughput test, zero means don't do
// throughput test.
static void receiveTests(int num_tests, int do_benchmark)
{
	uint8_t packet_buffer[64];
	uint8_t compare_buffer[64];
	uint8_t data_length;
	int actual_length;
	uint8_t counter;
	int r;
	int i;
	int j;
	unsigned int pass;
	unsigned int receive_from_control;
	unsigned int total_bytes_received;
	time_t start_time;

	counter = 0;
	for (pass = 0; pass < 3; pass++)
	{
		for (i = 1; i < num_tests; i++)
		{
			// The first 2 passes exclusively test the use of interrupt and
			// control endpoints. The last pass switches between them in an
			// attempt to trigger some race conditions.
			if (pass < 2)
			{
				receive_from_control = pass;
			}
			else
			{
				receive_from_control = (unsigned int)rand() & 1;
			}
			// First group of tests exhausts all possible report IDs. After that,
			// just use random report IDs. Using random report IDs reflects
			// real world usage more accurately.
			if (i <= 63)
			{
				data_length = (uint8_t)i;
			}
			else
			{
				data_length = (uint8_t)((rand() % 63) + 1);
			}
			if (receive_from_control)
			{
				r = receiveBytes(packet_buffer, data_length, &actual_length, 0, receive_from_control);
			}
			else
			{
				// For interrupt in endpoints, the device is allowed to choose
				// the number of bytes to send. Thus these tests can't mandate
				// any particular report.
				r = receiveBytes(packet_buffer, sizeof(packet_buffer), &actual_length, 1, receive_from_control);
			}
			if (r < 0)
			{
				printf("Receive fail, receive_from_control = %u, pass = %d, i = %d, r = %s\n", receive_from_control, pass, i, libusb_error_name(r));
				tests_failed++;
			}
			else
			{
				// Check that received bytes are in order.
				for (j = 0; j < actual_length; j++)
				{
					compare_buffer[j] = counter++;
				}
				if (memcmp(packet_buffer, compare_buffer, actual_length))
				{
					printf("Out of order data in receive, pass = %d, i = %d\n", pass, i);
					tests_failed++;
				}
				else
				{
					tests_succeeded++;
				}
			}
		} // end for (i = 1; i < num_tests; i++)

		if (do_benchmark && (pass < 2))
		{
			delay();
			// Receive maximum size packets as fast as possible.
			data_length = 63;
			total_bytes_received = 0;
			start_time = time(NULL);
			receive_from_control = pass;
			do
			{
				if (receive_from_control)
				{
					r = receiveBytes(packet_buffer, data_length, &actual_length, 0, receive_from_control);
				}
				else
				{
					r = receiveBytes(packet_buffer, data_length, &actual_length, 1, receive_from_control);
				}
				for (j = 0; j < actual_length; j++)
				{
					compare_buffer[j] = counter++;
				}
				if (memcmp(packet_buffer, compare_buffer, actual_length))
				{
					printf("Out of order data during receive throughput test, receive_from_control = %u\n", receive_from_control);
					break;
				}
				if (r < 0)
				{
					printf("Error during receive throughput test, receive_from_control = %u, r = %s\n", receive_from_control, libusb_error_name(r));
					break;
				}
				total_bytes_received += (unsigned int)actual_length;
			} while (difftime(time(NULL), start_time) < BENCHMARK_TIME);
			printf("Receive throughput for receive_from_control = %u: %g bytes/sec\n", receive_from_control, (double)total_bytes_received / BENCHMARK_TIME);
		}
	} // end for (pass = 0; pass < 3; pass++)
}

int main(void)
{
	int r;
	int actual_length;
	uint8_t buffer[2];
	int mode;

	srand(42);

	printf("Select test mode below. Ensure that device is reset before beginning test.\n");
	printf("  r: stream loopback\n");
	printf("  g: send bytes to device\n");
	printf("  i: send bytes to device slowly\n");
	printf("  j: send bytes to device very slowly\n");
	printf("  p: get bytes from device\n");
	printf("  t: get bytes from device slowly\n");
	printf("  x: get bytes from device very slowly\n");
	printf("Note that tests marked \"very slowly\" will run very slowly!\n");
	printf("?:");
	mode = getchar();
	eatUpRestOfLine();

	device_handle = init();
	if (device_handle == NULL)
	{
		printf("ERROR: Could not find appropriate device\n");
		exit(1);
	}

	tests_succeeded = 0;
	tests_failed = 0;

	// Set test mode.
	libusb_set_configuration(device_handle, 1);
	libusb_claim_interface(device_handle, 0);
	buffer[0] = 1;
	buffer[1] = (uint8_t)mode;
	r = libusb_interrupt_transfer(device_handle, 0x02, buffer, sizeof(buffer), &actual_length, TIMEOUT);
	if ((r != 0) || (actual_length != sizeof(buffer)))
	{
		printf("ERROR: Could not set test mode (r = %s)\n", libusb_error_name(r));
		libusb_close(device_handle);
		libusb_exit(NULL);
		exit(1);
	}

	if (mode == 'r')
	{
		loopbackTests(LOOPBACK_TESTS);
	}
	else if (mode == 'g')
	{
		sendTests(SEND_TESTS_FAST, 1);
	}
	else if ((mode == 'i') || (mode == 'j'))
	{
		sendTests(SEND_TESTS_SLOW, 0);
	}
	else if (mode == 'p')
	{
		receiveTests(RECEIVE_TESTS_FAST, 1);
	}
	else if ((mode == 't') || (mode == 'x'))
	{
		receiveTests(RECEIVE_TESTS_SLOW, 0);
	}
	else
	{
		printf("ERROR: Invalid test mode\n");
		libusb_close(device_handle);
		libusb_exit(NULL);
		exit(1);
	}

	printf("Tests which failed: %u\n", tests_failed);
	printf("Tests which succeeded: %u\n", tests_succeeded);

	libusb_close(device_handle);
	libusb_exit(NULL);

	exit(0);
}

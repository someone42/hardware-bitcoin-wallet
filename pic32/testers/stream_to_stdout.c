// ***********************************************************************
// stream_to_stdout.c
// ***********************************************************************
//
// Send something them to hardware Bitcoin wallet using a CP2110-like USB HID
// wire protocol and then write all received bytes to stdout.
// This uses HIDAPI.
//
// This file is licensed as described by the file LICENCE.

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hidapi/hidapi.h"

// Vendor ID of target device. This must match the vendor ID in the
// device's device descriptor.
#define TARGET_VID				0x04f3
// Product ID of target device. This must match the product ID in the
// device's device descriptor.
#define TARGET_PID				0x0210

int main(int argc, char **argv)
{
	int r;
	unsigned int i;
	size_t data_size;
	uint8_t packet_buffer[64];
	hid_device *handle;

	if (argc != 2)
	{
		printf("Usage: %s <string to send>\n", argv[0]);
		exit(1);
	}

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

	// Place data to send into HID report and send it.
	data_size = strlen(argv[1]);
	if ((data_size < 1) || (data_size > (sizeof(packet_buffer) - 1)))
	{
		printf("String to send \"%s\" is too short or too long\n", argv[1]);
		exit(1);
	}
	packet_buffer[0] = (uint8_t)data_size; // report ID
	memcpy(&(packet_buffer[1]), argv[1], data_size);
	if (hid_write(handle, packet_buffer, data_size + 1) < 0)
	{
		printf("hid_write() failed, error: %ls\n", hid_error(handle));
		exit(1);
	}

	// Dump received reports to stdout.
	while(1)
	{
		r = hid_read(handle, packet_buffer, sizeof(packet_buffer));
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
		data_size = packet_buffer[0]; // report ID
		if ((data_size > 63) || (data_size > (unsigned int)(r - 1)))
		{
			printf("Got invalid report ID: %u\n", data_size);
			exit(1);
		}
		for (i = 0; i < data_size; i++)
		{
			putchar(packet_buffer[i + 1]);
		}
	}

	hid_close(handle);
	// Free static HIDAPI objects. 
	hid_exit();
	exit(0);
}

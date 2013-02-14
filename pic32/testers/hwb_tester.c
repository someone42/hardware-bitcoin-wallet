// ***********************************************************************
// hwb_tester.c
// ***********************************************************************
//
// Tester which sends and receives packets (for the hardware bitcoin wallet)
// using a stream-based USB HID protocol. The contents of the packets are
// also displayed.
// This uses HIDAPI.
//
// This file is licensed as described by the file LICENCE.

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "hidapi/hidapi.h"

// Vendor ID of target device. This must match the vendor ID in the
// device's device descriptor.
#define TARGET_VID				0x04f3
// Product ID of target device. This must match the product ID in the
// device's device descriptor.
#define TARGET_PID				0x0210
// Maximum packet length to accept before program suspects the packet is
// garbled.
#define PACKET_LENGTH_LIMIT		1000000

// Handle to HID device, so that it doesn't have to be passed as a parameter
// all the time.
static hid_device *handle;

// Read a 32-bit unsigned integer from the byte array specified by in.
// The bytes will be read in a little-endian format.
static uint32_t readU32LittleEndian(uint8_t *in)
{
	return ((uint32_t)in[0])
		| ((uint32_t)in[1] << 8)
		| ((uint32_t)in[2] << 16)
		| ((uint32_t)in[3] << 24);
}

// Convert command number into text string
static char *packetCommandToText(int command)
{
	switch (command)
	{
	case 0x00:
		return "ping";
	case 0x02:
		return "return success";
	case 0x03:
		return "return failure";
	case 0x04:
		return "create new wallet";
	case 0x05:
		return "create new address in wallet";
	case 0x06:
		return "get number of addresses";
	case 0x09:
		return "get address and public key";
	case 0x0a:
		return "sign transaction";
	case 0x0b:
		return "load wallet";
	case 0x0c:
		return "unload wallet";
	case 0x0d:
		return "format storage";
	case 0x0e:
		return "change encryption key";
	case 0x0f:
		return "change name";
	case 0x10:
		return "list wallets";
	case 0x11:
		return "backup wallet";
	case 0x12:
		return "restore wallet";
	case 0x13:
		return "get device UUID";
	case 0x14:
		return "get entropy";
	case 0x15:
		return "get master public key";
	default:
		return "unknown";
	}
}

// Display packet contents on screen
static void displayPacket(uint8_t *packet_data, uint32_t buffer_length)
{
	uint8_t command;
	uint8_t one_byte;
	uint32_t length;
	uint32_t i;

	command = packet_data[0];
	length = readU32LittleEndian(&(packet_data[1]));
	printf("command 0x%02x (%s)\n", command, packetCommandToText(command));
	printf("Payload length: %d\n", length);

	// display hex bytes
	for (i = 0; i < length; i++)
	{
		if (i && !(i & 15))
		{
			printf("\n");
		}
		one_byte = packet_data[i + 5];
		printf(" %02x", one_byte);
		if ((i + 5) >= buffer_length)
		{
			printf(" ***unexpected end of packet***");
			break;
		}
	}
	printf("\n");
	// display ASCII
	for (i = 0; i < length; i++)
	{
		if (i && !(i & 15))
		{
			printf("\n");
		}
		one_byte = packet_data[i + 5];
		if ((one_byte < 32) || (one_byte > 126))
		{
			printf(".");
		}
		else
		{
			printf("%c", packet_data[i + 5]);
		}
		if ((i + 5) >= buffer_length)
		{
			break;
		}
	}
	printf("\n");
}

// Send the byte array specified by buffer (which is length bytes long) by
// splitting it into HID reports and sending those reports.
static void sendBytes(uint8_t *buffer, unsigned int length)
{
	uint8_t packet_buffer[64];
	unsigned int data_size;
	unsigned int i;

	while (length > 0)
	{
		data_size = length;
		if (data_size > 63)
		{
			data_size = 63;
		}
		packet_buffer[0] = (uint8_t)data_size; // report ID
		for (i = 1; i <= data_size; i++)
		{
			packet_buffer[i] = *buffer++;
		}
		if (hid_write(handle, packet_buffer, data_size + 1) < 0)
		{
			printf("hid_write() failed, error: %ls\n", hid_error(handle));
			exit(1);
		}
		length -= data_size;
	}
}

// Receive a packet, copying it into a memory buffer and returning the buffer.
static uint8_t *receivePacket(void)
{
	uint8_t packet_buffer[64];
	unsigned int data_size;
	uint8_t *return_buffer;
	uint32_t received_bytes;
	uint32_t target_length;

	received_bytes = 0;
	target_length = PACKET_LENGTH_LIMIT;
	return_buffer = NULL;
	while (received_bytes < target_length)
	{
		if (hid_read(handle, packet_buffer, sizeof(packet_buffer)) < 0)
		{
			printf("hid_read() failed, error: %ls\n", hid_error(handle));
			exit(1);
		}
		data_size = packet_buffer[0]; // report ID
		if (data_size > 63)
		{
			printf("Got invalid report ID: %u\n", data_size);
			exit(1);
		}
		if (data_size > target_length)
		{
			printf("Report will overflow buffer, report ID = %u\n", data_size);
			exit(1);
		}
		// Add newly received bytes to return buffer.
		return_buffer = realloc(return_buffer, received_bytes + data_size);
		memcpy(&(return_buffer[received_bytes]), &(packet_buffer[1]), data_size);
		received_bytes += data_size;
		// Get target length from return buffer.
		if (received_bytes >= 5)
		{
			target_length = readU32LittleEndian(&(return_buffer[1]));
			if (target_length > PACKET_LENGTH_LIMIT)
			{
				printf("Got absurdly large packet length of %u\n", target_length);
				printf("Exiting, since the packet is probably garbled\n");
				exit(1);
			}
		}
	}

	return return_buffer;
}

int main(void)
{
	char filename[256];
	char *newline;
	int abort;
	FILE *file_to_send;
	uint8_t *buffer;
	long int size;

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

	abort = 0;
	do
	{
		// Get filename from user.
		printf("Enter file to send (blank to quit): ");
		fgets(filename, sizeof(filename), stdin);
		newline = strrchr(filename, '\r');
		if (newline != NULL)
		{
			*newline = '\0';
		}
		newline = strrchr(filename, '\n');
		if (newline != NULL)
		{
			*newline = '\0';
		}
		if (strcmp(filename, ""))
		{
			file_to_send = fopen(filename, "rb");
			if (file_to_send == NULL)
			{
				printf("Couldn't open file \"%s\"\n", filename);
			}
			else
			{
				// Get file length then read entire contents of file.
				fseek(file_to_send, 0, SEEK_END);
				size = ftell(file_to_send);
				fseek(file_to_send, 0, SEEK_SET);
				buffer = malloc(size);
				fread(buffer, size, 1, file_to_send);
				fclose(file_to_send);
				printf("Sending packet: ");
				displayPacket(buffer, size);
				// Send the packet.
				sendBytes(buffer, size);
				free(buffer);
				// Get and display response packet.
				buffer = receivePacket();
				size = 5 + readU32LittleEndian(&(buffer[1]));
				printf("Received packet: ");
				displayPacket(buffer, size);
				free(buffer);
			}
		}
		else
		{
			abort = 1;
		}
	} while (!abort);

	hid_close(handle);
	// Free static HIDAPI objects. 
	hid_exit();
	exit(0);
}


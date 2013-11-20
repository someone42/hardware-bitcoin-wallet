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
// The bytes will be read in a big-endian format.
static uint32_t readU32BigEndian(uint8_t *in)
{
	return ((uint32_t)in[0] << 24)
		| ((uint32_t)in[1] << 16)
		| ((uint32_t)in[2] << 8)
		| ((uint32_t)in[3]);
}

// Convert command number into text string
static char *packetCommandToText(int command)
{
	switch (command)
	{
	case 0x00:
		return "Ping";
	case 0x04:
		return "NewWallet";
	case 0x05:
		return "NewAddress";
	case 0x06:
		return "GetNumberOfAddresses";
	case 0x09:
		return "GetAddressAndPublicKey";
	case 0x0a:
		return "SignTransaction";
	case 0x0b:
		return "LoadWallet";
	case 0x0d:
		return "FormatWalletArea";
	case 0x0e:
		return "ChangeEncryptionKey";
	case 0x0f:
		return "ChangeWalletName";
	case 0x10:
		return "ListWallets";
	case 0x11:
		return "BackupWallet";
	case 0x12:
		return "RestoreWallet";
	case 0x13:
		return "GetDeviceUUID";
	case 0x14:
		return "GetEntropy";
	case 0x15:
		return "GetMasterPublicKey";
	case 0x16:
		return "DeleteWallet";
	case 0x17:
		return "Initialize";
	case 0x30:
		return "Address";
	case 0x31:
		return "NumberOfAddresses";
	case 0x32:
		return "Wallets";
	case 0x33:
		return "PingResponse";
	case 0x34:
		return "Success";
	case 0x35:
		return "Failure";
	case 0x36:
		return "DeviceUUID";
	case 0x37:
		return "Entropy";
	case 0x38:
		return "MasterPublicKey";
	case 0x39:
		return "Signature";
	case 0x3a:
		return "Features";
	case 0x50:
		return "ButtonRequest";
	case 0x51:
		return "ButtonAck";
	case 0x52:
		return "ButtonCancel";
	case 0x53:
		return "PinRequest";
	case 0x54:
		return "PinAck";
	case 0x55:
		return "PinCancel";
	case 0x56:
		return "OtpRequest";
	case 0x57:
		return "OtpAck";
	case 0x58:
		return "OtpCancel";
	default:
		return "unknown";
	}
}

// Display packet contents on screen
static void displayPacket(uint8_t *packet_data, uint32_t buffer_length)
{
	uint16_t command;
	uint8_t one_byte;
	uint32_t length;
	uint32_t i;

	command = (uint16_t)(((uint16_t)packet_data[2] << 8) | ((uint16_t)packet_data[3]));
	length = readU32BigEndian(&(packet_data[4]));
	printf("command 0x%04x (%s)\n", (unsigned int)command, packetCommandToText(command));
	printf("Payload length: %u\n", length);

	// display hex bytes
	for (i = 0; i < length; i++)
	{
		if (i && !(i & 15))
		{
			printf("\n");
		}
		one_byte = packet_data[i + 8];
		printf(" %02x", one_byte);
		if ((i + 8) >= buffer_length)
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
		one_byte = packet_data[i + 8];
		if ((one_byte < 32) || (one_byte > 126))
		{
			printf(".");
		}
		else
		{
			printf("%c", packet_data[i + 8]);
		}
		if ((i + 8) >= buffer_length)
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
		if ((received_bytes + data_size) > target_length)
		{
			printf("Report will overflow buffer, report ID = %u\n", data_size);
			exit(1);
		}
		// Add newly received bytes to return buffer.
		return_buffer = realloc(return_buffer, received_bytes + data_size);
		memcpy(&(return_buffer[received_bytes]), &(packet_buffer[1]), data_size);
		received_bytes += data_size;
		// Get target length from return buffer.
		if (received_bytes >= 8)
		{
			if ((return_buffer[0] != '#') || (return_buffer[1] != '#'))
			{
				printf("Got bad magic bytes: %02x%02x\n", return_buffer[0], return_buffer[1]);
				printf("Exiting, since the packet is probably garbled\n");
				exit(1);
			}
			target_length = readU32BigEndian(&(return_buffer[4])) + 8;
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
				size = 8 + readU32BigEndian(&(buffer[4]));
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


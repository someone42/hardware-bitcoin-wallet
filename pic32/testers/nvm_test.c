// nvm_test.c
//
// This will use hidapi to test non-volatile memory access on the PIC32 port
// of the hardware Bitcoin wallet firmware. It tests the non-volatile memory
// interface, not the non-volatile memory itself.
//
// The tests will take about half an hour and will stress the flash with on
// the order of 1000 erase-program cycles.
//
// Based on hidtest.cpp by Alan Ott (Signal 11 Software).
//
// This file is licensed as described by the file LICENCE.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "hidapi/hidapi.h"

// Vendor ID of target device. This must match the vendor ID in the
// device's device descriptor.
#define TARGET_VID			0x04f3
// Product ID of target device. This must match the product ID in the
// device's device descriptor.
#define TARGET_PID			0x0210
// Area in non-volatile storage to test. This is lower than the actual size
// so that testing is faster.
#define NV_MEMORY_SIZE		131072
// Maximum length of any read/write.
#define MAX_LENGTH			16384

// Handle to HID device, so that it doesn't have to be passed as a parameter
// all the time.
static hid_device *handle;

// What this program thinks are the contents of non-volatile memory.
static uint8_t nv_mem_contents[NV_MEMORY_SIZE];

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

// Receive bytes into the byte array specified by buffer (which is length
// bytes long) by accumulating HID reports.
static void receiveBytes(uint8_t *buffer, unsigned int length)
{
	uint8_t packet_buffer[64];
	unsigned int data_size;
	unsigned int i;

	while (length > 0)
	{
		if (hid_read(handle, packet_buffer, sizeof(packet_buffer)) < 0)
		{
			printf("hid_read() failed, error: %ls\n", hid_error(handle));
			exit(1);
		}
		data_size = packet_buffer[0];
		if (data_size > 63)
		{
			printf("Got invalid report ID: %u\n", data_size);
			exit(1);
		}
		if (data_size > length)
		{
			printf("Report will overflow buffer, report ID = %u\n", data_size);
			exit(1);
		}
		for (i = 1; i <= data_size; i++)
		{
			*buffer++ = packet_buffer[i];
		}
		length -= data_size;
	}
}

// Write 32 bit unsigned integer into a byte array in little-endian format.
static void writeU32LittleEndian(uint8_t *out, uint32_t in)
{
	out[0] = (uint8_t)in;
	out[1] = (uint8_t)(in >> 8);
	out[2] = (uint8_t)(in >> 16);
	out[3] = (uint8_t)(in >> 24);
}

// Tell DUT to call nonVolatileWrite().
static void nonVolatileWrite(uint8_t *data, uint32_t address, uint32_t length)
{
	uint8_t buffer[4];

	buffer[0] = 0x01; // write
	writeU32LittleEndian(&(buffer[1]), address);
	writeU32LittleEndian(&(buffer[5]), length);
	sendBytes(buffer, 9);
	sendBytes(data, length);
}

// Tell DUT to call nonVolatileRead().
static void nonVolatileRead(uint8_t *data, uint32_t address, uint32_t length)
{
	uint8_t buffer[4];

	buffer[0] = 0x00; // read
	writeU32LittleEndian(&(buffer[1]), address);
	writeU32LittleEndian(&(buffer[5]), length);
	sendBytes(buffer, 9);
	receiveBytes(data, length);
}

// Tell DUT to call nonVolatileFlush().
static void nonVolatileFlush(void)
{
	uint8_t buffer[1];

	buffer[0] = 0x02; // flush
	sendBytes(buffer, 1);
}

// Write specified area with random test data, updating nv_mem_contents
// as well.
static void testNonVolatileWrite(uint32_t address, uint32_t length)
{
	uint8_t data[MAX_LENGTH];
	unsigned int i;

	if (length > sizeof(data))
	{
		printf("Length too big in testNonVolatileWrite()\n");
		exit(1);
	}
	for (i = 0; i < length; i++)
	{
		data[i] = (uint8_t)rand();
	}
	nonVolatileWrite(data, address, length);
	memcpy(&(nv_mem_contents[address]), data, length);
}

// Read specified area, checking contents match nv_mem_contents.
static void testNonVolatileRead(uint32_t address, uint32_t length)
{
	uint8_t data[MAX_LENGTH];

	if (length > sizeof(data))
	{
		printf("Length too big in testNonVolatileRead()\n");
		exit(1);
	}
	nonVolatileRead(data, address, length);
	if (memcmp(&(nv_mem_contents[address]), data, length))
	{
		printf("Memory contents mismatch, address = %u, length = %u", address, length);
	}
}

// Go through write/read cycle, without and with flush.
// This tests read, write and flush for the specified address/length.
static void writeAndReadCycle(uint32_t address, uint32_t length)
{
	testNonVolatileWrite(address, length);
	testNonVolatileRead(address, length);
	testNonVolatileWrite(address, length);
	nonVolatileFlush();
	testNonVolatileRead(address, length);
}

int main(void)
{
	uint8_t buffer[1];
	unsigned int i;
	int mode;
	uint32_t address;
	uint32_t length;

	srand(42);
	if (hid_init())
	{
		printf("hid_init() failed\n");
		exit(1);
	}

	// Open the device using the VID, PID,
	handle = hid_open(TARGET_VID, TARGET_PID, NULL);
	if (!handle)
	{
		printf("Unable to open target device\n");
 		exit(1);
	}

	// Set non-volatile test mode.
	buffer[0] = 'n';
	sendBytes(buffer, 1);

	// Synchronise nv_mem_contents with actual contents.
	printf("Reading contents of non-volatile memory...");
	for (i = 0; i < NV_MEMORY_SIZE; i += 4096)
	{
		nonVolatileRead(&(nv_mem_contents[i]), i, 4096);
	}
	printf("done\n");

	printf("Running tests...\n");

	// Basic test: write/read 16 bytes from within a sector, with and without
	// flushing.
	// Why 16? It's the AES-128 block size.
	writeAndReadCycle(0, 16);
	// Test address != 0.
	writeAndReadCycle(64, 16);
	// Test length not a power of 2.
	writeAndReadCycle(64, 63);
	// Test address not a power of 2.
	writeAndReadCycle(31, 16);
	// Test address and length not a power of 2.
	writeAndReadCycle(31, 15);

	// These tests examine behaviour at and across sector boundaries.
	writeAndReadCycle(4095, 1);
	writeAndReadCycle(4096, 1);
	writeAndReadCycle(4090, 6);
	writeAndReadCycle(4090, 7);
	writeAndReadCycle(4095, 15);
	writeAndReadCycle(4096, 4096);
	writeAndReadCycle(4096, 4097);
	writeAndReadCycle(4095, 4098);
	writeAndReadCycle(0, 4095);
	writeAndReadCycle(1, 4095);
	writeAndReadCycle(1, 5000);

	// 0 length (it's valid!) tests.
	writeAndReadCycle(4096, 0);
	writeAndReadCycle(1, 0);
	writeAndReadCycle(0, 0);

	// Maximum length tests.
	writeAndReadCycle(4096, MAX_LENGTH);
	writeAndReadCycle(0, MAX_LENGTH);
	writeAndReadCycle(1, MAX_LENGTH);

	// Monte Carlo tests. These are supposed to expose any issues related
	// to write/read cycles which don't use the same address/length. The
	// use of non-volatile memory here also reflects real-world usage more
	// accurately: reads, writes and flushes are not in any particular order.
	for (i = 0; i < 2000; i++)
	{
		mode = rand() % 3;
		do
		{
			address = rand() % NV_MEMORY_SIZE;
			length = (rand() % MAX_LENGTH) + 1;
		} while ((address + length) > NV_MEMORY_SIZE);
		if (mode == 0)
		{
			testNonVolatileRead(address, length);
		}
		else if (mode == 1)
		{
			testNonVolatileWrite(address, length);
		}
		else
		{
			nonVolatileFlush();
		}
	}

	printf("Tests done\n");

	hid_close(handle);

	// Free static HIDAPI objects. 
	hid_exit();

	exit(1);
}

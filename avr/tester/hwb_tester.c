// ***********************************************************************
// hwb_tester.c
// ***********************************************************************
//
// Tester which sends and receives packets (for the hardware bitcoin wallet)
// over a serial link. The contents of the packets are also displayed.
//
// This file is licensed as described by the file LICENCE.

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>

// Maximum packet length to accept before program suspects the packet is
// garbled.
#define PACKET_LENGTH_LIMIT				1000000
// The default number of bytes (transmitted or received) in between
// acknowledgments
#define DEFAULT_ACKNOWLEDGE_INTERVAL	16
// The number of received bytes in between acknowledgments that this program
// will use (doesn't have to be the default)
#define RX_ACKNOWLEDGE_INTERVAL			32

// Remaining number of bytes that can be transmitted before listening for
// acknowledge
static uint32_t tx_bytes_to_ack;
// Remaining number of bytes that can be received before other side expects an
// acknowledge
static uint32_t rx_bytes_to_ack;

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

// Convert command number into text string
static char *packetCommandToText(int command)
{
	switch (command)
	{
	case 0x00:
		return "ping";
	case 0x01:
		return "acknowledge ping";
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

// Get a byte from the serial link, sending an acknowledgement if required
static uint8_t receiveByte(int fd)
{
	uint8_t ack_buffer[5];
	uint8_t buffer;

	read(fd, &buffer, 1);
	rx_bytes_to_ack--;
	if (!rx_bytes_to_ack)
	{
		rx_bytes_to_ack = RX_ACKNOWLEDGE_INTERVAL;
		ack_buffer[0] = 0xff;
		writeU32LittleEndian(&(ack_buffer[1]), rx_bytes_to_ack);
		write(fd, ack_buffer, 5);
	}
	return buffer;
}

// Receive a packet, copying it into a memory buffer and returning the buffer
static uint8_t *receivePacket(int fd)
{
	uint8_t packet_header[5];
	uint8_t *packet_buffer;
	uint32_t length;
	uint32_t i;

	for (i = 0; i < 5; i++)
	{
		packet_header[i] = receiveByte(fd);
	}
	length = readU32LittleEndian(&(packet_header[1]));
	if (length > PACKET_LENGTH_LIMIT)
	{
		printf("Got absurdly large packet length of %d\n", length);
		printf("Exiting, since the packet is probably garbled\n");
		exit(1);
	}
	packet_buffer = malloc(length + 5);
	memcpy(packet_buffer, packet_header, 5);
	for (i = 0; i < length; i++)
	{
		packet_buffer[i + 5] = receiveByte(fd);
	}
	return packet_buffer;
}

// Send a byte to the serial link, waiting for acknowledgement if required
static void sendByte(uint8_t data, int fd)
{
	uint8_t ack_buffer[5];
	uint8_t buffer;

	buffer = data;
	write(fd, &buffer, 1);
	tx_bytes_to_ack--;
	if (!tx_bytes_to_ack)
	{
		read(fd, ack_buffer, 5);
		if (ack_buffer[0] != 0xff)
		{
			printf("Unexpected acknowledgement format (%d)\n", (int)ack_buffer[0]);
			printf("Exiting, since the serial link is probably dodgy\n");
			exit(1);
		}
		tx_bytes_to_ack = readU32LittleEndian(&(ack_buffer[1]));
	}
}

int main(int argc, char **argv)
{
	char filename[256];
	char *newline;
	int abort;
	FILE *file_to_send;
	int fd_serial;
	uint8_t *packet_buffer;
	long int size;
	long int i;
	struct termios options;
	struct termios old_options;

	if (argc != 2)
	{
		printf("Hardware BitCoin wallet tester\n");
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

	tx_bytes_to_ack = DEFAULT_ACKNOWLEDGE_INTERVAL;
	rx_bytes_to_ack = DEFAULT_ACKNOWLEDGE_INTERVAL;
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
				packet_buffer = malloc(size);
				fread(packet_buffer, size, 1, file_to_send);
				fclose(file_to_send);
				printf("Sending packet: ");
				displayPacket(packet_buffer, size);
				// Send the packet.
				for (i = 0; i < size; i++)
				{
					sendByte(packet_buffer[i], fd_serial);
				}
				free(packet_buffer);
				// Get and display response packet.
				packet_buffer = receivePacket(fd_serial);
				size = 5 + readU32LittleEndian(&(packet_buffer[1]));
				printf("Received packet: ");
				displayPacket(packet_buffer, size);
				free(packet_buffer);
			}
		}
		else
		{
			abort = 1;
		}
	} while (!abort);

	tcsetattr(fd_serial, TCSANOW, &old_options); // restore configuration
	close(fd_serial);

	exit(0);
}


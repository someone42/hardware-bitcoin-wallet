/** \file usb_hal.h
  *
  * \brief Describes functions, types and constants exported by usb_hal.c
  *
  * All references to the "USB specification" refer to revision 2.0, obtained
  * from http://www.usb.org/developers/docs/usb_20_110512.zip (see usb_20.pdf)
  * on 26 March 2012.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef PIC32_USB_HAL_H
#define	PIC32_USB_HAL_H

#include <stdint.h>

/** Maximum packet size, in bytes, which this implementation can handle. */
#define MAX_PACKET_SIZE				64

/** Total number of endpoints supported by USB module.
  * \warning This must be a power of 2, because it is used to generate an
  *          AND mask.
  */
#define NUM_ENDPOINTS				16

/** Endpoint types, to pass to enableEndpoint(). */
typedef enum EndpointTypeEnum
{
	/** Bidirectional control endpoint. */
	CONTROL_ENDPOINT	= 21,
	/** Endpoint for transmitting data to host. */
	IN_ENDPOINT			= 24,
	/** Endpoint for receiving data from host. */
	OUT_ENDPOINT		= 27
} EndpointType;

/** Structure which holds per-endpoint state. Such a state is needed because
  * packets can be received and transmitted asynchronously. */
typedef struct EndpointStateStruct
{
	/** Buffer for received packets. It needs to be persistent because packets
	  * can be received at any time. */
	uint8_t receive_buffer[MAX_PACKET_SIZE];
	/** Callback which is called whenever a packet is received.
	  * \param packet_buffer The contents of the packet are placed here.
	  * \param length The length (in bytes) of the received packet.
	  * \param is_setup Will be non-zero if a SETUP token was received, will
	  *                 be zero if a OUT or IN token was received. For
	  *                 anything which isn't a control transfer, this should
	  *                 always be 0.
	  * \warning After return from the callback, the contents of packet_buffer
	  *          are undefined.
	  * \warning The usbQueueReceivePacket() function must be called to tell
	  *          the USB module that it can accept another packet. If you
	  *          forget to call it, the USB module will NAK packets forever!
	  */
	void (*receiveCallback)(uint8_t *packet_buffer, uint32_t length, unsigned int is_setup);
	/** Callback which is called whenever a packet is transmitted. For
	  * extended packets, this will only be called after the last packet is
	  * successfully transmitted. */
	void (*transmitCallback)(void);
	/** Current value of the data toggle synchronisation counter. This should
	  * be 0 or 1 and is used to handle cases where ACKs are dropped. See
	  * section  8.6 of the USB specification for more details of the
	  * mechanism. Note that this is separate to the PIC32 USB
	  * module's "ping-pong buffering" feature.
	  */
	unsigned int data_sequence;
	/** Non-zero if currently in an extended transmit, zero if not in an
	  * extended transmit. An extended transmit is a transmission which is
	  * as large as or larger than #MAX_PACKET_SIZE. Such large transmit
	  * requests are split up into multiple packets, as described in section
	  * 5.5.3 of the USB specification. */
	unsigned int is_extended_transmit;
	/** The number of bytes remaining in a transmit, including any currently
	  * queued packet. */
	uint32_t transmit_remaining;
	/** Pointer to the beginning of the most recently transmitted packet. */
	const uint8_t *transmit_buffer;
} EndpointState;

extern void usbInit(void);
extern void usbConnect(void);
extern void usbDisconnect(void);
extern void usbDisableEndpoint(unsigned int endpoint);
extern void usbEnableEndpoint(unsigned int endpoint, EndpointType type, EndpointState *state);
extern unsigned int usbEndpointEnabled(unsigned int endpoint);
extern void usbQueueReceivePacket(unsigned int endpoint);
extern void usbQueueTransmitPacket(const uint8_t *packet_buffer, uint32_t length, unsigned int endpoint, unsigned int is_extended);
extern void usbCancelTransmit(unsigned int endpoint);
extern void usbStallEndpoint(unsigned int endpoint);
extern void usbUnstallEndpoint(unsigned int endpoint);
extern unsigned int usbGetStallStatus(unsigned int endpoint);
extern void usbSetDeviceAddress(unsigned int address);
extern void usbOverrideDataSequence(unsigned int endpoint, unsigned int new_data_sequence);

#endif	// #ifndef PIC32_USB_HAL_H

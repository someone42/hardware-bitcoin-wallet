/** \file usb_defs.h
  *
  * \brief Defines USB related constants and types.
  *
  * The USB specification defines a lot of constants. To improve the
  * readability of code, most of those constants are defined in here.
  *
  * All references to the "USB specification" refer to revision 2.0, obtained
  * from http://www.usb.org/developers/docs/usb_20_110512.zip (see usb_20.pdf)
  * on 26 March 2012. All references to the "HID specification" refer to
  * revision 1.1, obtained
  * from http://www.usb.org/developers/devclass_docs/HID1_11.pdf
  * on 25 November 2012.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef USB_DEFS_H_INCLUDED
#define USB_DEFS_H_INCLUDED

/** Every USB packet has a packet identifier (PID). The PID determines the
  * format and semantics of the packet. There are 3 relevant classes of
  * PIDs: token, data and handshake. For more information, see Table 8-1
  * in the USB specification.
  */
typedef enum USBPIDEnum
{
	/** Token: packet contains address and endpoint number for
	  * host to device transfer. */
	USBPID_OUT		= 0b0001,
	/** Token: packet contains address and endpoint number for
	  * device to host transfer. */
	USBPID_IN		= 0b1001,
	/** Token: packet is a start-of-frame marker and contains frame
	  * number. */
	USBPID_SOF		= 0b0101,
	/** Token: this is just like #USBPID_OUT, but it is special because
	  * it will begin a new control transfer if sent to the control endpoint
	  * (endpoint 0). */
	USBPID_SETUP	= 0b1101,
	/** Data: packet contains data, data sequence toggle bit is clear. */
	USBPID_DATA0	= 0b0011,
	/** Data: packet contains data, data sequence toggle bit is set. */
	USBPID_DATA1	= 0b1011,
	/** Handshake: basically, everything was fine. */
	USBPID_ACK		= 0b0010,
	/** Handshake: receiver not ready to accept data, try again later. */
	USBPID_NAK		= 0b1010,
	/** Handshake: basically, an error happened. */
	USBPID_STALL	= 0b1110
} USBPID;

/** Values for the bRequest field of standard device requests. They are used
  * to identify the standard request. These were obtained from Table 9-4 of
  * the USB specification and from page 51 of the HID specification. Below,
  * in parantheses, are references to the USB specification or HID
  * specification section number of each request.
  */
typedef enum DeviceRequestEnum
{
	// Standard USB requests:
	GET_STATUS			= 0,	/**< Get Status request (USB 9.4.5). */
	CLEAR_FEATURE		= 1,	/**< Clear Feature request (USB 9.4.1). */
	SET_FEATURE			= 3,	/**< Set Feature request (USB 9.4.9). */
	SET_ADDRESS			= 5,	/**< Set Address request (USB 9.4.6). */
	GET_DESCRIPTOR		= 6,	/**< Get Descriptor request (USB 9.4.3). */
	SET_DESCRIPTOR		= 7,	/**< Set Descriptor request (USB 9.4.8). */
	GET_CONFIGURATION	= 8,	/**< Get Configuration request (USB 9.4.2). */
	SET_CONFIGURATION	= 9,	/**< Set Configuration request (USB 9.4.7). */
	GET_INTERFACE		= 10,	/**< Get Interface request (USB 9.4.4). */
	SET_INTERFACE		= 11,	/**< Set Interface request (USB 9.4.10). */
	SYNCH_FRAME			= 12,	/**< Synch Frame request (USB 9.4.11). */
	// HID-specific requests:
	GET_REPORT			= 0x01,	/**< Get Report request (HID 7.2.1). */
	GET_IDLE			= 0x02,	/**< Get Idle request (HID 7.2.3). */
	GET_PROTOCOL		= 0x03,	/**< Get Protocol request (HID 7.2.5). */
	SET_REPORT			= 0x09,	/**< Set Report request (HID 7.2.2). */
	SET_IDLE			= 0x0a,	/**< Set Idle request (HID 7.2.4). */
	SET_PROTOCOL		= 0x0b	/**< Set Protocol request (HID 7.2.6). */
} DeviceRequest;

/** Descriptor types. These were obtained from Table 9-5 of USB specification
  * and from page 49 of the HID specification. Below, in parantheses, are
  * references to the USB specification or HID specification section number
  * of each request.
  */
typedef enum DescriptorTypesEnum
{
	// Standard USB descriptor types:
	DESCRIPTOR_DEVICE			= 1,	/**< Device descriptor (USB 9.6.1) */
	DESCRIPTOR_CONFIGURATION	= 2,	/**< Configuration descriptor (USB 9.6.3) */
	DESCRIPTOR_STRING			= 3,	/**< String descriptor (USB 9.6.7) */
	DESCRIPTOR_INTERFACE		= 4,	/**< Interface descriptor (USB 9.6.5) */
	DESCRIPTOR_ENDPOINT			= 5,	/**< Endpoint descriptor (USB 9.6.6) */
	// HID-specific descriptor types:
	DESCRIPTOR_HID				= 0x21,	/**< HID descriptor (HID 6.2.1) */
	DESCRIPTOR_REPORT			= 0x22,	/**< Report descriptor (HID 6.2.2) */
	DESCRIPTOR_PHYSICAL			= 0x23	/**< Physical descriptor (HID 6.2.3) */
} DescriptorTypes;

/** Report types. These were obtained from page 51 of the HID
  * specification. These values are only used in certain HID class-specific
  * requests. */
typedef enum ReportTypesEnum
{
	/** Input report. Should match format of reports received from the
	  * Interrupt IN pipe. */
	REPORT_TYPE_INPUT			= 1,
	/** Output report. Should match format of reports sent to the Interrupt
	  * OUT pipe. */
	REPORT_TYPE_OUTPUT			= 2,
	/** Feature report. Used to set Feature items. */
	REPORT_TYPE_FEATURE			= 3
} ReportTypes;

#endif // #ifndef USB_DEFS_H_INCLUDED

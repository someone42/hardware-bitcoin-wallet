/** \file usb_standard_requests.c
  *
  * \brief Handles standard USB requests directed to the control endpoint.
  *
  * A USB device is required to handle standard requests sent as control
  * transfers to endpoint 0 (the "control endpoint"). These standard requests
  * facilitate device enumeration and are described in chapter 9 of the
  * USB specification. This file handles those standard requests. It handles
  * a next-to-minimal set of requests: Clear Feature (endpoint halt only),
  * Get Configuration, Get Descriptor, Get Status, Set Address,
  * Set Configuration and Set Feature (endpoint halt only).
  *
  * Some notes about the implemented requests:
  * - Set/Get Configuration, Get Descriptor and Set Address are essential
  *   for device enumeration and configuration. When you plug in a USB device,
  *   it will likely receive the Get Descriptor, Set Address and
  *   Set Configuration requests.
  * - The set is next-to-minimal because as part of the Get Descriptor request,
  *   string descriptors are implemented (they're not strictly necessary).
  *   String descriptors are implemented to make device identification easier.
  * - Clear Feature, Set Feature and Get Status are required to implement
  *   the "endpoint halt" feature, which is required for interrupt
  *   endpoints (see section 9.4.5 of the USB specification).
  * - Only a single configuration (with configuration value = 1) and a single
  *   interface is supported.
  *
  * All references to the "USB specification" refer to revision 2.0, obtained
  * from http://www.usb.org/developers/docs/usb_20_110512.zip (see usb_20.pdf)
  * on 26 March 2012.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
#include "usb_hal.h"
#include "usb_defs.h"
#include "usb_callbacks.h"
#include "usb_standard_requests.h"
#include "../common.h"

/** Suppress definition of report descriptor when including the descriptors
  * in usb_descriptors.h. */
#define DONT_INCLUDE_REPORT_DESCRIPTOR
#include "usb_descriptors.h"

/** A control transfer proceeds through 3 distinct stages. These are the
  * three possible stages. */
typedef enum ControlTransferStageEnum
{
	/** Setup stage of control transfer. The request will be received from
	  * the host in this stage. */
	STAGE_SETUP		= 0,
	/** Data stage of control transfer. Any data associated with a request
	  * will be sent or received from the host in this stage. */
	STAGE_DATA		= 1,
	/** Data stage of control transfer. During this stage, the device will
	  * report success or failure back to the host. */
	STAGE_STATUS	= 2
} ControlTransferStage;

/** Persistent endpoint state for the control endpoint (endpoint 0). */
static EndpointState control_state;

/** The current stage in a control transfer. Normally, to transition to the
  * next stage, use the nextStage() function. This should only be updated
  * directly in exceptional cases. */
static ControlTransferStage current_stage;

/** Transmit packet buffer to use when sending 0 length packets. It's probably
  * okay to use NULL, but it's safer to always point the transmit buffer at
  * something. */
static const uint8_t null_packet[4];

/** Transmit buffer for sending the results of a "Get status" request (see
  * getStatus()). Note that the "status" here is different to the
  * "Status stage" of the control transfer. */
static uint8_t status_packet[2];

/** If this is non-zero, then the device address will be switched
  * to #new_address upon the completion of the next Status stage. */
static unsigned int do_set_new_address;

/** The device address to switch to upon completion of the next Status
  * stage. */
static unsigned int new_address;

/** The currently set configuration. 0 = not configured and 1 = configured.
  * This value is written to and read by the "Set Configuration"
  * and "Get Configuration" standard requests, respectively. */
static uint8_t current_configuration_value;

/** If this is non-zero, then the next receive queue for the control endpoint
  * will be suppressed. See usbSuppressControlReceive() for more details on why
  * this may be a good idea. */
static unsigned int do_suppress_next_control_receive;

/** Discard the current control transfer and prepare to deal with a new
  * one. */
static void abortControlTransfer(void)
{
	usbClassAbortControlTransfer();
	current_stage = STAGE_SETUP;
	do_set_new_address = 0;
	new_address = 0;
	do_suppress_next_control_receive = 0;
}

/** This will be called whenever a USB reset is seen. */
void usbResetSeen(void)
{
	abortControlTransfer();
	current_configuration_value = 0;
	usbClassResetSeen();
}

/** Issue a protocol stall to tell the host that there was a problem with a
  * control transfer. See section 8.5.3.4 of the USB specification for more
  * details. */
void usbControlProtocolStall(void)
{
	abortControlTransfer();
	usbStallEndpoint(CONTROL_ENDPOINT_NUMBER);
}

/** Transition to the next stage of a control transfer. */
void usbControlNextStage(void)
{
	if (current_stage == STAGE_SETUP)
	{
		// Setup -> Data.
		current_stage = STAGE_DATA;
	}
	else if (current_stage == STAGE_DATA)
	{
		// Data -> Status.
		// Section 8.5.3 of the USB specification says that the Status stage
		// of a control transfer always uses a data sequence value of 1,
		// regardless of the previous value.
		usbOverrideDataSequence(CONTROL_ENDPOINT_NUMBER, 1);
		current_stage = STAGE_STATUS;
	}
	else
	{
		// Status -> Setup.
		if (do_set_new_address)
		{
			usbSetDeviceAddress(new_address);
			do_set_new_address = 0;
		}
		current_stage = STAGE_SETUP;
	}
}

/** "Get Descriptor" request, as defined in section 9.4.3 of the USB
  * specification. This allows the host to retrieve information about a
  * USB device.
  * \param type Descriptor type. Should be one of #DescriptorTypes.
  * \param index Descriptor index, used to select a specific descriptor.
  * \param lang_id Language identifier, only used for string descriptors (must
  *                be zero for everything else).
  * \param request_length Maximum number of bytes of descriptor to send.
  */
static void getDescriptor(uint8_t type, uint8_t index, uint16_t lang_id, uint16_t request_length)
{
	unsigned int valid; // set this only after packet_buffer/length are set
	const uint8_t *packet_buffer;
	uint32_t packet_length;

	packet_buffer = null_packet;
	packet_length = 0;
	valid = 0;
	if ((type == DESCRIPTOR_DEVICE) && (index == 0) && (lang_id == 0))
	{
		packet_buffer = device_descriptor;
		packet_length = sizeof(device_descriptor);
		valid = 1;
	}
	else if ((type == DESCRIPTOR_CONFIGURATION) && (index == 0) && (lang_id == 0))
	{
		packet_buffer = configuration_descriptor;
		packet_length = sizeof(configuration_descriptor);
		valid = 1;
	}
	else if (type == DESCRIPTOR_STRING)
	{
		if (index == 0)
		{
			packet_buffer = lang_id_list;
			packet_length = sizeof(lang_id_list);
			valid = 1;
		}
		else
		{
			// Check that primary language identifier is correct.
			// The least significant 10 bits of lang_id are the primary
			// language ID.
			if ((lang_id & 0x3ff) == PRIMARY_LANGUAGE_ID)
			{
				if (index == MANUFACTURER_STRING_INDEX)
				{
					packet_buffer = manufacturer_string;
					packet_length = sizeof(manufacturer_string);
					valid = 1;
				}
				else if (index == PRODUCT_STRING_INDEX)
				{
					packet_buffer = product_string;
					packet_length = sizeof(product_string);
					valid = 1;
				}
				else if (index == SERIAL_NO_STRING_INDEX)
				{
					packet_buffer = serial_no_string;
					packet_length = sizeof(serial_no_string);
					valid = 1;
				}
			} // end if ((lang_id & 0x3ff) == PRIMARY_LANGUAGE_ID)
		} // end else clause of if (index == 0)
	}

	if (valid)
	{
		packet_length = MIN(packet_length, request_length);
		usbControlNextStage();
		if (packet_length == 0)
		{
			usbControlProtocolStall();
		}
		else
		{
			usbQueueTransmitPacket(packet_buffer, packet_length, CONTROL_ENDPOINT_NUMBER, 1);
		}
	}
	else
	{
		// Unknown or invalid descriptor specified.
		usbControlProtocolStall();
	}
}

/** "Set Address" request, as defined in section 9.4.6 of the USB
  * specification. The host uses this to assign an address to a USB device, so
  * that it can coexist with other USB devices sharing the same bus. Note that
  * unlike every other standard request, the effect of this request is delayed
  * (as prescribed in the USB specification) until the completion of the Status
  * stage.
  * \param address The new device address.
  */
static void setAddress(uint16_t address)
{
    if (address > 127)
	{
		usbControlProtocolStall();
	}
	else
	{
		new_address = address;
		do_set_new_address = 1;
		usbControlNextStage(); // no Data stage for this request
		usbControlNextStage();
		// Send success packet.
		usbQueueTransmitPacket(null_packet, 0, CONTROL_ENDPOINT_NUMBER, 0);
	}
}

/** "Set Configuration" request, as defined in section 9.4.7 of the USB
  * specification. This request allows the host to configure or unconfigure
  * a device. Note that only 1 configuration is supported.
  * \param new_configuration_value 0 means unconfigure device, 1 means
  *                                configure device.
  */
static void setConfiguration(uint16_t new_configuration_value)
{
	unsigned int i;

	if (new_configuration_value > 1)
	{
		usbControlProtocolStall();
	}
	else
	{
		current_configuration_value = (uint8_t)new_configuration_value;
		usbClassSetConfiguration(current_configuration_value);
		// From section 9.4.5 of the USB specification, set configuration
		// always clears the halt feature of all endpoints.
		for (i = 0; i < NUM_ENDPOINTS; i++)
		{
			if (usbEndpointEnabled(i))
			{
				usbUnstallEndpoint(i);
			}
		}
		usbControlNextStage(); // no Data stage for this request
		usbControlNextStage();
		// Send success packet.
		usbQueueTransmitPacket(null_packet, 0, CONTROL_ENDPOINT_NUMBER, 0);
	}
}

/** "Get Configuration" request, as defined in section 9.4.2 of the USB
  * specification. The host can use this to determine whether the device is
  * configured (the device will send 0x01) or not (the device will send 0x00).
  */
static void getConfiguration(void)
{
	usbControlNextStage();
	usbQueueTransmitPacket(&current_configuration_value, 1, CONTROL_ENDPOINT_NUMBER, 0);
}

/** This implements the endpoint halt feature, which is controlled by the
  * "Clear Feature" (see section 9.4.1 of the USB specification) and
  * "Set Feature" (see section 9.4.9 of the USB specification) requests.
  * The host can use the endpoint halt feature to intentionally stall (set)
  * or unstall (clear) an endpoint.
  * \param endpoint The endpoint number to stall or unstall.
  * \param do_set Non-zero means set halt (stall), zero means clear halt
  *               (unstall).
  */
static void clearOrSetEndpointHalt(uint16_t endpoint, unsigned int do_set)
{
	endpoint &= 0x7f; // clear endpoint direction bit
	if (endpoint >= NUM_ENDPOINTS)
	{
		usbControlProtocolStall();
	}
	else
	{
		if (!usbEndpointEnabled(endpoint))
		{
			usbControlProtocolStall();
		}
		else
		{
			if (do_set)
			{
				usbStallEndpoint(endpoint);
			}
			else
			{
				usbUnstallEndpoint(endpoint);
				// From section 9.4.5 of the USB specification, clearing the
				// halt feature always resets the data toggle bit for that
				// endpoint.
				usbOverrideDataSequence(endpoint, 0);
			}
			usbControlNextStage(); // no Data stage for this request
			usbControlNextStage();
			// Send success packet.
			usbQueueTransmitPacket(null_packet, 0, CONTROL_ENDPOINT_NUMBER, 0);
		} // end if (!usbEndpointEnabled(endpoint))
	} // end if (endpoint >= NUM_ENDPOINTS)
}

/** "Get Status" request, as defined in section 9.4.5 of the USB
  * specification. While the "Set Feature" and "Clear Feature" requests
  * write the device's state, this request allows the host to read the
  * device's state.
  * \param bmRequestType Characteristics of request, used to determine whether
  *                      to query the device, interface or endpoint. See
  *                      section 9.3.1 of the USB specification.
  * \param endpoint If querying the status of an endpoint, this specifies the
  *                 endpoint number of the endpoint to query. For device or
  *                 interface queries, this is ignored.
  */
static void getStatus(uint8_t bmRequestType, uint16_t endpoint)
{
	unsigned int valid;

	valid = 0;
	if ((bmRequestType == 0x80) || (bmRequestType == 0x81))
	{
		// Device or interface status. There's nothing interesting to report.
		status_packet[0] = 0;
		status_packet[1] = 0;
		valid = 1;
	}
	else if (bmRequestType == 0x82)
	{
		// Endpoint status.
		endpoint &= 0x7f; // clear endpoint direction bit
		if (endpoint < NUM_ENDPOINTS)
		{
			if (usbEndpointEnabled(endpoint))
			{
				if (usbGetStallStatus(endpoint))
				{
					status_packet[0] = 1;
				}
				else
				{
					status_packet[0] = 0;
				}
				status_packet[1] = 0;
				valid = 1;
			}
		}
	}

	if (valid)
	{
		usbControlNextStage();
		usbQueueTransmitPacket(status_packet, 2, CONTROL_ENDPOINT_NUMBER, 0);
	}
	else
	{
		// Unknown request type.
		usbControlProtocolStall();
	}
}

/** Examine the control transfer setup parameters and perform the appropriate
  * action if the parameters match a supported standard request. The full list
  * of standard requests is given in section 9.4 of the USB specification.
  * Not all standard requests are supported.
  * \param bmRequestType Characteristics of request.
  * \param bRequest Specifies which request to perform.
  * \param wValue Request-dependent parameter.
  * \param wIndex Request-dependent parameter.
  * \param wLength Maximum number of bytes to transfer during the Data stage.
  *                This is allowed to be zero. If it is zero, then there is
  *                no Data stage.
  * \return Zero if the request was handled, non-zero if the request was not
  *         handled (i.e. the request did not match any supported standard
  *         request).
  */
static unsigned int handleControlSetup(uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint16_t wLength)
{
	if ((bmRequestType == 0x02) && (bRequest == CLEAR_FEATURE)
		&& (wValue == 0) && (wLength == 0))
	{
		clearOrSetEndpointHalt(wIndex, 0);
	}
	else if ((bmRequestType == 0x80) && (bRequest == GET_CONFIGURATION)
		&& (wValue == 0) && (wIndex == 0) && (wLength == 1))
	{
		getConfiguration();
	}
	else if ((bmRequestType == 0x80) && (bRequest == GET_DESCRIPTOR))
	{
		getDescriptor((uint8_t)(wValue >> 8), (uint8_t)wValue, wIndex, wLength);
	}
	else if ((bmRequestType >= 0x80) && (bmRequestType <= 0x82)
		&& (bRequest == GET_STATUS) && (wValue == 0)
		&& (wLength == 2))
	{
		getStatus(bmRequestType, wIndex);
	}
	else if ((bmRequestType == 0x00) && (bRequest == SET_ADDRESS)
		&& (wIndex == 0) && (wLength == 0))
	{
		setAddress(wValue);
	}
	else if ((bmRequestType == 0x00) && (bRequest == SET_CONFIGURATION)
		&& (wIndex == 0) && (wLength == 0))
	{
		setConfiguration(wValue);
	}
	else if ((bmRequestType == 0x02) && (bRequest == SET_FEATURE)
		&& (wValue == 0) && (wLength == 0))
	{
		clearOrSetEndpointHalt(wIndex, 1);
	}
	else
	{
		return 1; // unknown or unsupported request.
	}
	return 0; // success
}

/** Callback that is called whenever the control endpoint receives a packet.
  * It is this function which handles the USB device standard requests.
  * \param packet_buffer The contents of the received packet.
  * \param length The length, in bytes, of the received packet.
  * \param is_setup Will be non-zero if a SETUP token was received, will
  *                 be zero if a OUT or IN token was received.
  */
void controlReceiveCallback(uint8_t *packet_buffer, uint32_t length, unsigned int is_setup)
{
	uint8_t bmRequestType;
	uint8_t bRequest;
	uint16_t wValue;
	uint16_t wIndex;
	uint16_t wLength;

	if (is_setup)
	{
		// If the host aborts a control transfer (for example, due to
		// transmission errors), then from the device's perspective, the
		// next control transfer will appear prematurely. See section 5.5.5
		// of the USB specification for more information on this.
		abortControlTransfer(); // will reset current stage back to Setup stage
	}
	if (current_stage == STAGE_SETUP)
	{
		if (length != 8)
		{
			// Every request packet should have 8 bytes, so something has
			// gone very wrong.
			usbFatalError();
		}
		else
		{
			// Extract request parameters from packet.
			bmRequestType = packet_buffer[0];
			bRequest = packet_buffer[1];
			wValue = (uint16_t)(packet_buffer[2] | (packet_buffer[3] << 8));
			wIndex = (uint16_t)(packet_buffer[4] | (packet_buffer[5] << 8));
			wLength = (uint16_t)(packet_buffer[6] | (packet_buffer[7] << 8));
			if (handleControlSetup(bmRequestType, bRequest, wValue, wIndex, wLength))
			{
				// Not a standard request. Check to see if class request
				// handler can deal with it.
				if (usbClassHandleControlSetup(bmRequestType, bRequest, wValue, wIndex, wLength))
				{
					// No-one was able to handle the request.
					usbControlProtocolStall();
				}
			}
		} // end if (length != 8)
	} // end if (current_stage == STAGE_SETUP)
	else if (current_stage == STAGE_DATA)
	{
		// None of the supported standard requests require the reception of
		// any data. But there might be a class-specific request which does
		// accept data.
		if (usbClassHandleControlData(packet_buffer, length))
		{
			// No-one was able to handle the data.
			usbControlProtocolStall();
		}
	}
	else
	{
		// Status stage.
		// If flow reaches here, it means the status was sent successfully (as
		// a handshake to the packet that was just received).
		// Thus it is appropriate to move on to the next stage.
		usbControlNextStage();
	}
	if (do_suppress_next_control_receive)
	{
		do_suppress_next_control_receive = 0;
	}
	else
	{
		usbQueueReceivePacket(CONTROL_ENDPOINT_NUMBER);
	}
}

/** Callback that is called whenever the control endpoint transmits a
  * packet. */
void controlTransmitCallback(void)
{
	if (current_stage == STAGE_SETUP)
	{
		// This should never happen.
		usbFatalError();
	}
	else
	{
		// Data or Status stage.
		// Advance to the next stage. This is correct if the current stage
		// is STAGE_DATA (if flow reaches here, it means the data was sent
		// successfully) and STAGE_STATUS (if flow reaches here, it means
		// the status was sent successfully).
		usbControlNextStage();
	}
}

/** Initialise endpoint state for control endpoint (endpoint 0). This must be
  * called before USB connection, since the first thing the USB host will
  * probably do after connection is send requests to the control endpoint.
  */
void usbSetupControlEndpoint(void)
{
	control_state.receiveCallback = &controlReceiveCallback;
	control_state.transmitCallback = &controlTransmitCallback;
	abortControlTransfer(); // will reset state
	usbEnableEndpoint(CONTROL_ENDPOINT_NUMBER, CONTROL_ENDPOINT, &control_state);
}

/** Suppress the next receive for the control endpoint (endpoint 0). This will
  * cause subsequent host-to-device control transactions to be NAKed. This
  * is useful for flow control. For example, if the device sees a request
  * it cannot handle yet, it can suppress receives until it can handle the
  * request. */
void usbSuppressControlReceive(void)
{
	do_suppress_next_control_receive = 1;
}

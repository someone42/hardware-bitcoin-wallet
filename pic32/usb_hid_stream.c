/** \file usb_hid_stream.c
  *
  * \brief USB HID class driver which transfers data as a stream.
  *
  * This file implements a device-side USB HID class driver which transfers
  * data in a manner similar to the Silicon Labs CP2110. In a nutshell,
  * a data stream is broken up into chunks of maximum size 63 bytes, and those
  * chunks are sent as a bunch of HID reports where the report ID is the
  * chunk size. This is an abuse of the HID specification, but things are
  * done this way to allow "driverless" operation on Windows systems.
  *
  * Here's a high-level overview of what's provided in this file. There is
  * an implementation of streamGetOneByte() and streamPutOneByte(), which
  * read from or write to FIFOs. The interface to USB happens mainly through
  * callbacks, because USB is fundamentally asynchronous from a device's point
  * of view. The nature of asynchronous I/O means that care must be taken to
  * only queue (i.e. schedule) transfers if the appropriate FIFO is empty
  * or full enough. Things are complicated by the fact that the host can
  * get and send reports through both the Interrupt endpoints and the control
  * endpoint.
  *
  * Some additional notes:
  * - Care must be taken to avoid race conditions, since many of the callbacks
  *   can occur in an interrupt context. The assumption is made that there
  *   is only one interrupt context (i.e. USB interrupts cannot interrupt
  *   USB interrupts).
  * - If the host decides to get/send reports through an Interrupt endpoint
  *   and the control endpoint simultaneously, the order of reports is
  *   undefined (so don't do that!).
  * - It is necessary to support the "Set Report" control request
  *   (see setReport()) because the hidraw driver on Linux kernels
  *   earlier than 2.6.35 use it, even if the device provides a perfectly
  *   working Interrupt OUT endpoint.
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

#include <stdint.h>
#include "usb_hal.h"
#include "usb_callbacks.h"
#include "usb_defs.h"
#include "usb_standard_requests.h"
#include "../common.h"
#include "serial_fifo.h"
#include "pic32_system.h"

/** Only include the report descriptor when including the descriptors
  * in usb_descriptors.h. */
#define ONLY_INCLUDE_REPORT_DESCRIPTOR
#include "usb_descriptors.h"

/** The endpoint number for transmission (Interrupt IN). It's IN because
  * from the host's perspective, data is flowing into it. */
#define TRANSMIT_ENDPOINT_NUMBER	1
/** The endpoint number for reception (Interrupt OUT). It's OUT because
  * from the host's perspective, data is flowing out of it. */
#define RECEIVE_ENDPOINT_NUMBER		2

/** Size of transmit FIFO buffer, in number of bytes. There isn't much to be
  * gained from making this significantly larger.
  * \warning This must be a power of 2.
  */
#define TRANSMIT_FIFO_SIZE			64
/** Size of receive FIFO buffer, in number of bytes. There isn't much to be
  * gained from making this significantly larger.
  * \warning This must be a power of 2.
  * \warning This must be >= #RECEIVE_HEADROOM, to handle the (unlikely)
  *          cases where the host does simultaneous writes to the
  *          Interrupt OUT endpoint and control endpoint.
  */
#define RECEIVE_FIFO_SIZE			256

/** Minimum number of bytes which must be available (free) in the receive
  * FIFO before a receive will be queued. This is not just #MAX_PACKET_SIZE
  * because the host may do simultaneous writes to the Interrupt OUT endpoint
  * and control endpoint, in which case two packets will be received in
  * quick succession. */
#define RECEIVE_HEADROOM			(2 * MAX_PACKET_SIZE)

/** The transmit FIFO buffer. */
volatile CircularBuffer transmit_fifo;
/** The receive FIFO buffer. */
volatile CircularBuffer receive_fifo;

/** Storage for the transmit FIFO buffer. */
static volatile uint8_t transmit_fifo_storage[TRANSMIT_FIFO_SIZE];
/** Storage for the receive FIFO buffer. */
static volatile uint8_t receive_fifo_storage[RECEIVE_FIFO_SIZE];

/** Flag (non-zero = set, zero = clear) which when set, indicates that a
  * packet has been queued for transmission on the Interrupt IN endpoint. */
static volatile int interrupt_transmit_queued;
/** Flag (non-zero = set, zero = clear) which when set, indicates that a
  * packet has been queued for reception on the Interrupt OUT endpoint. */
static volatile int interrupt_receive_queued;

/** Persistent packet buffer for packets sent from the Interrupt IN endpoint
  * (see #TRANSMIT_ENDPOINT_NUMBER). */
static uint8_t interrupt_packet_buffer[MAX_PACKET_SIZE];
/** Persistent packet buffer for packets sent from the control endpoint. This
  * needs to be separate from #interrupt_packet_buffer because both the
  * Interrupt IN endpoint and control endpoint can be transmitting
  * simultaneously. */
static uint8_t get_report_packet_buffer[MAX_PACKET_SIZE];

/** Persistent endpoint state for the transmit endpoint (with endpoint
  * number #TRANSMIT_ENDPOINT_NUMBER. */
static EndpointState transmit_endpoint_state;
/** Persistent endpoint state for the receive endpoint (with endpoint
  * number #RECEIVE_ENDPOINT_NUMBER. */
static EndpointState receive_endpoint_state;

/** Transmit packet buffer to use when sending 0 length packets. It's probably
  * okay to use NULL, but it's safer to always point the transmit buffer at
  * something. */
static const uint8_t null_packet[4];

/** Previous configuration value passed to usbClassSetConfiguration(). This
  * is used to detect configuration changes. */
static uint8_t old_configuration_value;

/** Flag (non-zero = set, zero = clear) which, when set, indicates that
  * streamGetOneByte() should queue a receive for the control endpoint instead
  * of the Interrupt OUT endpoint. This is used to handle the "Set Report"
  * request. */
static volatile int do_control_receive_queue;
/** Flag (non-zero = set, zero = clear) which, when set, indicates that
  * the next control transfer Data stage will contain an output report. This
  * is used to handle the "Set Report" request. */
static volatile int expect_control_report;
/** Expected report ID of a report received through the control endpoint. This
  * is only valid when #expect_control_report is set. */
static uint8_t expected_control_report_id;

/** Flag (non-zero = set, zero = clear) which, when set, indicates that
  * streamPutOneByte() should redirect bytes into #get_report_packet_buffer,
  * where they will be transmitted through the control endpoint (instead of
  * the Interrupt IN endpoint). This is used to handle the "Get Report"
  * request. */
static volatile int do_build_transmit_report;
/** Desired size (as given in the "Get Report" request), in bytes, of the
  * report to send through the control endpoint. This includes the report ID
  * byte. This is only valid when #do_build_transmit_report is set. */
static uint32_t desired_transmit_report_length;
/** Current size, in bytes, of the report which will be sent through the
  * control endpoint. This includes the report ID byte. This is only valid
  * when #do_build_transmit_report is set. */
static uint32_t current_transmit_report_length;

/** Fill up transmit packet buffer with bytes obtained from the transmit
  * FIFO buffer, then queue the packet for transmission, if necessary.
  */
static void fillTransmitPacketBufferAndTransmit(void)
{
	uint32_t status;
	uint32_t count;
	uint32_t i;

	// Put everything in a critical section so that bytes are either in
	// the transmit FIFO or in interrupt_packet_buffer.
	status = disableInterrupts();
	i = 1;
	while ((i < sizeof(interrupt_packet_buffer)) && !isCircularBufferEmpty(&transmit_fifo))
	{
		// Note that is_irq is set because interrupts are disabled; that's
		// equivalent to an interrupt request handler context.
		interrupt_packet_buffer[i] = circularBufferRead(&transmit_fifo, 1);
		i++;
	}
	count = i - 1;
	interrupt_packet_buffer[0] = (uint8_t)count;
	if (count > 0)
	{
		// Set transmit_queued before queueing transmit to avoid race
		// condition where packet is transmitted just after
		// usbQueueTransmitPacket() call.
		interrupt_transmit_queued = 1;
		usbQueueTransmitPacket(interrupt_packet_buffer, count + 1, TRANSMIT_ENDPOINT_NUMBER, 0);
	}
	else
	{
		interrupt_transmit_queued = 0;
	}
	restoreInterrupts(status);
}

/** Transfer bytes from a receive buffer into receive FIFO.
  * \warning This assumes there is enough space (if not, usbFatalError() will
  *          be called). There should always be enough space, since a receive
  *          is never queued unless there is enough space.
  */
static void transferIntoReceiveFIFO(uint8_t *buffer, uint32_t length)
{
	uint32_t i;

	if (circularBufferSpaceRemaining(&receive_fifo) < length)
	{
		// This should never happen.
		usbFatalError();
	}
	for (i = 0; i < length; i++)
	{
		circularBufferWrite(&receive_fifo, buffer[i], 1);
	}
}

/** Remove a byte from the existing queued packet which was intended to be
  * sent out the Interrupt IN endpoint.
  *
  * This is a hack necessary to have the "Get Report" request work
  * intuitively. Bytes sent using streamPutOneByte() will, by default, end up
  * being queued for transmission via. the Interrupt IN endpoint. But if the
  * host exclusively uses "Get Report" requests (which use the control
  * endpoint), it will never see bytes queued for transmission via. the
  * Interrupt IN endpoint. Therefore, there needs to be some way to obtain
  * bytes from a queued Interrupt IN transmission.
  * \return The byte that was removed.
  * \warning This should only be called if there is actually a queued packet.
  */
static uint8_t stealByteFromInterruptReport(void)
{
	uint8_t one_byte;
	uint32_t count;
	uint32_t i;

	// Unqueue current transmit request.
	if (interrupt_transmit_queued == 0)
	{
		// This should never happen.
		usbFatalError();
	}
	usbCancelTransmit(TRANSMIT_ENDPOINT_NUMBER);
	interrupt_transmit_queued = 0;
	// Remove first report data byte from packet, shifting the rest of the
	// data to fill the space.
	count = interrupt_packet_buffer[0];
	if ((count < 1) || (count > (sizeof(interrupt_packet_buffer) - 1)))
	{
		// Bad packet ID; this should never happen.
		usbFatalError();
	}
	one_byte = interrupt_packet_buffer[1];
	for (i = 1; i < count; i++)
	{
		interrupt_packet_buffer[i] = interrupt_packet_buffer[i + 1];
	}
	count--;
	interrupt_packet_buffer[0] = (uint8_t)count;
	// Queue updated transmit packet (if necessary).
	if (count > 0)
	{
		interrupt_transmit_queued = 1;
		usbQueueTransmitPacket(interrupt_packet_buffer, count + 1, TRANSMIT_ENDPOINT_NUMBER, 0);
	}
	return one_byte;
}

/** Incrementally build a report to send via. the control endpoint. This is
  * used to handle the "Get Report" request. If the added byte completes
  * the report, it will be transmitted; #do_build_transmit_report will be
  * cleared if that happens.
  * \param one_byte The byte to add to the report.
  */
static void buildTransmitReport(uint8_t one_byte)
{
	if ((current_transmit_report_length >= desired_transmit_report_length)
		|| (current_transmit_report_length >= sizeof(get_report_packet_buffer))
		|| (do_build_transmit_report == 0))
	{
		// This should never happen.
		usbFatalError();
	}
	get_report_packet_buffer[current_transmit_report_length] = one_byte;
	current_transmit_report_length++;
	if (current_transmit_report_length == desired_transmit_report_length)
	{
		// Got desired size, send it.
		usbQueueTransmitPacket(get_report_packet_buffer, desired_transmit_report_length, CONTROL_ENDPOINT_NUMBER, 0);
		do_build_transmit_report = 0;
	}
}

/** Callback which is called whenever a packet is received on the Interrupt
  * IN endpoint (endpoint number #TRANSMIT_ENDPOINT_NUMBER).
  * \param packet_buffer The contents of the packet.
  * \param length The length (in bytes) of the received packet.
  * \param is_setup Will be non-zero if a SETUP token was received, will
  *                 be zero if a OUT or IN token was received.
  */
void ep1ReceiveCallback(uint8_t *packet_buffer, uint32_t length, unsigned int is_setup)
{
	// Since this is an IN endpoint, this callback should never be called.
	usbFatalError();
}

/** Callback which is called whenever a packet is transmitted on the Interrupt
  * IN endpoint (endpoint number #TRANSMIT_ENDPOINT_NUMBER). */
void ep1TransmitCallback(void)
{
	fillTransmitPacketBufferAndTransmit();
}

/** Callback which is called whenever a packet is received on the Interrupt
  * OUT endpoint (endpoint number #RECEIVE_ENDPOINT_NUMBER).
  * \param packet_buffer The contents of the packet.
  * \param length The length (in bytes) of the received packet.
  * \param is_setup Will be non-zero if a SETUP token was received, will
  *                 be zero if a OUT or IN token was received.
  * \warning This assumes that there is enough space in the receive FIFO for
  *          the received packet. There should always be enough space, since
  *          a receive is never queued unless there is enough space.
  */
void ep2ReceiveCallback(uint8_t *packet_buffer, uint32_t length, unsigned int is_setup)
{
	// Check that the packet length (provided by the USB module) matches
	// the length given in the first byte.
	if (length < 1)
	{
		// Packet too small.
		usbFatalError();
	}
	else if (packet_buffer[0] != (length - 1))
	{
		usbFatalError();
	}
	else
	{
		transferIntoReceiveFIFO(&(packet_buffer[1]), length - 1);
		// What happens if there isn't enough space in the receive buffer?
		// Then a receive isn't queued up. This will cause subsequent OUT
		// transactions to be NAKed, blocking the host. Each
		// streamGetOneByte() call frees up space in the receive FIFO,
		// until eventually there is enough space to queue a receive.
		if (circularBufferSpaceRemaining(&receive_fifo) >= RECEIVE_HEADROOM)
		{
			interrupt_receive_queued = 1;
			usbQueueReceivePacket(RECEIVE_ENDPOINT_NUMBER);
		}
		else
		{
			interrupt_receive_queued = 0;
		}
	}
}

/** Callback which is called whenever a packet is transmitted on the Interrupt
  * OUT endpoint (endpoint number #RECEIVE_ENDPOINT_NUMBER). */
void ep2TransmitCallback(void)
{
	// Since this is the OUT endpoint, this callback should never be called.
	usbFatalError();
}

/** HID class-specific "Get Descriptor" request, as defined in section 7.1.1
  * of the HID specification. This allows the host to retrieve HID
  * class-specific information about a USB device.
  * \param type Descriptor type. Should be one of #DescriptorTypes.
  * \param index Descriptor index, used to select a specific descriptor.
  * \param lang_id Language identifier, only used for string descriptors (must
  *                be zero for everything else).
  * \param request_length Maximum number of bytes of descriptor to send.
  */
static void getDescriptor(uint8_t type, uint8_t index, uint16_t lang_id, uint16_t request_length)
{
	uint32_t packet_length;

	if ((type == DESCRIPTOR_REPORT) && (index == 0) && (lang_id == 0))
	{
		packet_length = MIN(sizeof(report_descriptor), request_length);
		usbControlNextStage();
		if (packet_length == 0)
		{
			usbControlProtocolStall();
		}
		else
		{
			usbQueueTransmitPacket(report_descriptor, packet_length, CONTROL_ENDPOINT_NUMBER, 1);
		}
	}
	else
	{
		// Unknown or invalid descriptor specified.
		usbControlProtocolStall();
	}
}

/** HID class-specific "Get Report" request, as defined in section 7.2.1
  * of the HID specification. This is an alternative way for the host to
  * receive reports from a device, as opposed to the usual method of polling
  * the Interrupt IN endpoint.
  * \param report_id Report ID of the desired report. For this driver, this
  *                  means the number of data bytes in the report.
  * \param length Length, in bytes, of the report.
  */
static void getReport(uint8_t report_id, uint16_t length)
{
	usbControlNextStage();
	if ((length < 1) || (length > MAX_PACKET_SIZE))
	{
		// Bad length.
		// Reports must have at least one byte for the report ID. Reports
		// must also be able to fit in one packet.
		usbControlProtocolStall();
	}
	else if (report_id != (length - 1))
	{
		// Report ID does not match request length.
		usbControlProtocolStall();
	}
	else
	{
		// Build a report and send it.
		do_build_transmit_report = 1;
		current_transmit_report_length = 0;
		desired_transmit_report_length = length;
		buildTransmitReport(report_id);
		// Two ways this loop can end:
		// 1. The report length reaches the desired length, in which case the
		//    report is sent and do_build_transmit_report is set to 0.
		// 2. The transmit interrupt report buffer is emptied, in which
		//    case interrupt_transmit_queued will be set to 0. Further bytes
		//    will have to come from somewhere else.
		while (interrupt_transmit_queued && do_build_transmit_report)
		{
			buildTransmitReport(stealByteFromInterruptReport());
		}
		// Two ways this loop can end:
		// 1. The report length reaches the desired length, in which case the
		//    report is sent and do_build_transmit_report is set to 0.
		// 2. The transmit FIFO is emptied before the report reaches the
		//    desired size, so nothing is sent and do_build_transmit_report
		//    remains set. streamPutOneByte() will handle the rest.
		while (!isCircularBufferEmpty(&transmit_fifo) && do_build_transmit_report)
		{
			buildTransmitReport(circularBufferRead(&transmit_fifo, 1));
		}
		// If the control request ate up the entire interrupt transmit
		// report but left the transmit FIFO full, streamPutOneByte() will
		// deadlock. This is because it waits for the transmit FIFO to become
		// not full, yet there is no interrupt transmit queued to consume
		// the transmit FIFO. Thus to avoid this deadlock, queue an interrupt
		// transmit if there is anything in the transmit FIFO.
		if (!interrupt_transmit_queued)
		{
			fillTransmitPacketBufferAndTransmit();
		}
	}
}

/** HID class-specific "Set Report" request, as defined in section 7.2.2
  * of the HID specification. This is an alternative way for the host to
  * send reports to a device, as opposed to the usual method writing to
  * the Interrupt OUT endpoint.
  * \param report_id Report ID of the report to send. For this driver, this
  *                  means the number of data bytes in the report.
  * \param length Length, in bytes, of the report.
  */
static void setReport(uint8_t report_id, uint16_t length)
{
	if ((length < 1) || (length > MAX_PACKET_SIZE))
	{
		// Bad length.
		// Reports must have at least one byte for the report ID. Reports
		// must also be able to fit in one packet.
		usbControlProtocolStall();
	}
	else if (report_id != (length - 1))
	{
		// Report ID does not match request length.
		usbControlProtocolStall();
	}
	else
	{
		usbControlNextStage();
		expected_control_report_id = report_id;
		expect_control_report = 1;
		if (circularBufferSpaceRemaining(&receive_fifo) < RECEIVE_HEADROOM)
		{
			// Not enough space in receive FIFO to handle request.
			usbSuppressControlReceive(); // do not immediately proceed to Data stage
			// Redirect streamGetOneByte() to queue receives on the control
			// endpoint instead of the Interrupt OUT endpoint.
			do_control_receive_queue = 1;
		}
	}
}

/** All standard requests (as described in chapter 9 of the USB specification)
  * are issued to the control endpoint (endpoint 0). However, sometimes
  * class-specific requests are sent to the control endpoint. This callback
  * gives class drivers the opportunity to handle those class-specific
  * requests.
  * Class drivers should examine the control transfer setup parameters and
  * perform an appropriate action if the parameters match a supported
  * class-specific request.
  * \param bmRequestType Characteristics of request.
  * \param bRequest Specifies which request to perform.
  * \param wValue Request-dependent parameter.
  * \param wIndex Request-dependent parameter.
  * \param wLength Maximum number of bytes to transfer during the Data stage.
  *                This is allowed to be zero. If it is zero, then there is
  *                no Data stage.
  * \return Zero if the request was handled, non-zero if the request was not
  *         handled (i.e. the request did not match any supported
  *         class-specific request).
  */
unsigned int usbClassHandleControlSetup(uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint16_t wLength)
{
	if ((bmRequestType == 0x81) && (bRequest == GET_DESCRIPTOR))
	{
		getDescriptor((uint8_t)(wValue >> 8), (uint8_t)wValue, wIndex, wLength);
	}
	else if ((bmRequestType == 0xa1) && (bRequest == GET_REPORT)
			&& ((uint8_t)(wValue >> 8) == REPORT_TYPE_INPUT) && (wIndex == 0))
	{
		getReport((uint8_t)wValue, wLength);
	}
	else if ((bmRequestType == 0x21) && (bRequest == SET_REPORT)
			&& ((uint8_t)(wValue >> 8) == REPORT_TYPE_OUTPUT) && (wIndex == 0))
	{
		setReport((uint8_t)wValue, wLength);
	}
	else
	{
		return 1; // unknown or unsupported request.
	}
	return 0; // success
}

/** This callback will be called if the control endpoint (endpoint 0)
  * receives data during the Data stage of a class-specific request. This
  * callback gives class drivers the opportunity to handle data sent to the
  * control endpoint.
  * \param packet_buffer The contents of the data packet are placed here.
  * \param length The length (in bytes) of the received data packet.
  * \return Zero if the data was accepted, non-zero if the data was not
  *         handled (i.e. the class driver did not expect any data).
  */
unsigned int usbClassHandleControlData(uint8_t *packet_buffer, uint32_t length)
{
	if (expect_control_report)
	{
		// Check that the packet length (provided by the USB module) matches
		// the report ID.
		if (length >= 1)
		{
			if ((packet_buffer[0] != (length - 1))
				|| (expected_control_report_id != packet_buffer[0]))
			{
				// Report ID doesn't match request length.
				usbControlProtocolStall();
			}
			else
			{
				usbControlNextStage();
				transferIntoReceiveFIFO(&(packet_buffer[1]), length - 1);
				// Send success packet.
				usbQueueTransmitPacket(null_packet, 0, CONTROL_ENDPOINT_NUMBER, 0);
			}
		}
		else
		{
			// Packet too small.
			usbControlProtocolStall();
		}
		return 0;
	}
	else
	{
		return 1; // did not expect any data
	}
}

/** This will be called whenever a control transfer needs to be aborted (for
  * any reason, including reset). This allows class drivers to reset their
  * control transfer-specific state. */
void usbClassAbortControlTransfer(void)
{
	do_control_receive_queue = 0;
	expect_control_report = 0;
	do_build_transmit_report = 0;
}

/** Callback which will be called whenever a successful "Set Configuration"
  * request (see section 9.4.7 of the USB specification) is encountered. This
  * gives the class driver an opportunity to configure or unconfigure
  * endpoints, buffers, state etc.
  * \param new_configuration_value 0 means unconfigure device, 1 means
  *                                configure device.
  */
void usbClassSetConfiguration(uint8_t new_configuration_value)
{
	if ((old_configuration_value == 0) && (new_configuration_value != 0))
	{
		// Transition from unconfigured to configured.
		interrupt_transmit_queued = 0;
		interrupt_receive_queued = 1;
		usbEnableEndpoint(TRANSMIT_ENDPOINT_NUMBER, IN_ENDPOINT, &transmit_endpoint_state);
		usbEnableEndpoint(RECEIVE_ENDPOINT_NUMBER, OUT_ENDPOINT, &receive_endpoint_state);
	}
	else if ((old_configuration_value != 0) && (new_configuration_value == 0))
	{
		// Transition from configured to unconfigured.
		usbDisableEndpoint(TRANSMIT_ENDPOINT_NUMBER);
		usbDisableEndpoint(RECEIVE_ENDPOINT_NUMBER);
		interrupt_transmit_queued = 0;
		interrupt_receive_queued = 0;
		usbClassAbortControlTransfer(); // will reset state
	}
	old_configuration_value = new_configuration_value;
}

/** This will be called whenever a USB reset is seen. This callback gives
  * class drivers the opportunity to reset their state. */
void usbClassResetSeen(void)
{
	usbClassSetConfiguration(0);
}

/** Initialise HID stream driver. This must be called before connecting the
  * USB device (usbConnect()) or calling streamGetOneByte() and
  * streamPutOneByte(), otherwise race conditions with the FIFOs could
  * occur. */
void usbHIDStreamInit(void)
{
	old_configuration_value = 0;
	usbClassAbortControlTransfer(); // will reset state
	initCircularBuffer(&transmit_fifo, transmit_fifo_storage, TRANSMIT_FIFO_SIZE);
	initCircularBuffer(&receive_fifo, receive_fifo_storage, RECEIVE_FIFO_SIZE);
	transmit_endpoint_state.receiveCallback = &ep1ReceiveCallback;
	transmit_endpoint_state.transmitCallback = &ep1TransmitCallback;
	receive_endpoint_state.receiveCallback = &ep2ReceiveCallback;
	receive_endpoint_state.transmitCallback = &ep2TransmitCallback;
}

/** Grab one byte from the communication stream. There is no way for this
  * function to indicate a read error. This is intentional; it
  * makes program flow simpler (no need to put checks everywhere). As a
  * consequence, this function should only return if the received byte is
  * free of read errors.
  *
  * Previously, if a read or write error occurred, processPacket() would
  * return, an error message would be displayed and execution would halt.
  * There is no reason why this couldn't be done inside streamGetOneByte()
  * or streamPutOneByte(). So nothing was lost by omitting the ability to
  * indicate read or write errors.
  *
  * Perhaps the argument can be made that if this function indicated read
  * errors, the caller could attempt some sort of recovery. Perhaps
  * processPacket() could send something to request the retransmission of
  * a packet. But retransmission requests are something which can be dealt
  * with by the implementation of the stream. Thus a caller of
  * streamGetOneByte() will assume that the implementation handles things
  * like automatic repeat request, flow control and error detection and that
  * if a true "stream read error" occurs, the communication link is shot to
  * bits and nothing the caller can do will fix that.
  * \return The received byte.
  */
uint8_t streamGetOneByte(void)
{
	uint32_t status;
	uint8_t one_byte;

	one_byte = circularBufferRead(&receive_fifo, 0);
	// It's probably safe to leave interrupts enabled, but just to be sure,
	// disable them so that no race conditions can occur.
	status = disableInterrupts();
	// Control transfers take precedence over interrupt transfers, because
	// a control transfer will block all subsequent control transfers, which
	// would make device reconfiguration difficult.
	if (do_control_receive_queue)
	{
		if (circularBufferSpaceRemaining(&receive_fifo) >= RECEIVE_HEADROOM)
		{
			do_control_receive_queue = 0;
			usbQueueReceivePacket(CONTROL_ENDPOINT_NUMBER);
		}
	}
	else if (!interrupt_receive_queued)
	{
		if (circularBufferSpaceRemaining(&receive_fifo) >= RECEIVE_HEADROOM)
		{
			interrupt_receive_queued = 1;
			usbQueueReceivePacket(RECEIVE_ENDPOINT_NUMBER);
		}
	}
	restoreInterrupts(status);
	return one_byte;
}

/** Send one byte to the communication stream. There is no way for this
  * function to indicate a write error. This is intentional; it
  * makes program flow simpler (no need to put checks everywhere). As a
  * consequence, this function should only return if the byte was sent
  * free of write errors.
  *
  * See streamGetOneByte() for some justification about why write errors
  * aren't indicated by a return value.
  * \param one_byte The byte to send.
  */
void streamPutOneByte(uint8_t one_byte)
{
	uint32_t status;

	// Ensure that there is space in the transmit FIFO so that the call to
	// circularBufferWrite() below cannot fail.
	while (isCircularBufferFull(&transmit_fifo))
	{
		enterIdleMode();
	}
	// Everything below is in a critical section to avoid race conditions
	// with the "Get Report" request.
	status = disableInterrupts();
	if (do_build_transmit_report)
	{
		// Keep adding bytes to the transmit report until it reaches the
		// desired length.
		buildTransmitReport(one_byte);
	}
	else
	{
		// Since transmitted bytes are fed to this function one-at-a-time,
		// there's no way to determine whether there are bytes after this one
		// or not. So this function will just transmit the first byte in a
		// packet all by itself (which isn't very efficient). If there are
		// bytes immediately after this one, they will queue up in the transmit
		// FIFO, where they will be efficiently grouped into a packet by
		// ep1TransmitCallback().
		// Note that is_irq is set because interrupts are disabled; that's
		// equivalent to an interrupt request handler context.
		circularBufferWrite(&transmit_fifo, one_byte, 1);
	}
	if (!interrupt_transmit_queued)
	{
		fillTransmitPacketBufferAndTransmit();
	}
	restoreInterrupts(status);
}

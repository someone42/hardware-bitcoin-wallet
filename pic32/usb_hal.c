/** \file usb_hal.c
  *
  * \brief Hardware abstraction layer for PIC32 USB module.
  *
  * This file provides an abstract interface for USB operations on the PIC32
  * USB module. It is quite simple and doesn't support many features.
  * The PIC32 USB module supports "ping-pong buffering" (double buffering),
  * but this implementation does not use this feature, as throughput is not
  * expected to be a concern. Furthermore, this doesn't support USB suspend or
  * resume.
  *
  * From a device's perspective, USB transactions are asynchronous. That is
  * because the host tells the device when it can transmit or receive.
  * Therefore, transmission and reception functions are implemented through
  * an asynchronous interface involving per-endpoint callback functions defined
  * in the #EndpointState structure.
  *
  * All references to the "USB specification" refer to revision 2.0, obtained
  * from http://www.usb.org/developers/docs/usb_20_110512.zip (see usb_20.pdf)
  * on 26 March 2012. All references to the "PIC32 Family Reference Manual"
  * refer to section 27, revision F, obtained from
  * http://ww1.microchip.com/downloads/en/DeviceDoc/61126F.pdf
  * on 6 November 2012.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include <stdint.h>
#include <string.h>
#include <p32xxxx.h>
#include "usb_hal.h"
#include "usb_defs.h"
#include "usb_callbacks.h"
#include "usb_standard_requests.h" // for usbResetSeen() callback
#include "pic32_system.h"

/** Virtual addresses are addresses used internally by the CPU to access
  * memory and peripherals. When passing addresses from the CPU to
  * peripherals (eg. for DMA), these virtual addresses need to be converted
  * to physical addresses by setting the most significant 3 bits to 0. */
#define VIRTUAL_TO_PHYSICAL(x)		(((uint32_t)(x)) & 0x1fffffff)
/** Each endpoint has 4 buffer descriptor entries: even receive, odd receive,
  * even transmit and odd transmit. The even/odd buffers allow for double
  * buffering. This macro generates a readable index into #bdt_table. For
  * dir, use #BDT_RX or #BDT_TX. For pp, use #BDT_EVEN or #BDT_ODD. */
#define BDT_IDX(endpoint, dir, pp)	((((endpoint) & 15) << 2) \
									| (((dir) & 1) << 1) \
									| ((pp) & 1))
/** Value for dir parameter of #BDT_IDX macro which is used to access the
  * receive descriptors. */
#define BDT_RX						0
/** Value for dir parameter of #BDT_IDX macro which is used to access the
  * transmit descriptors. */
#define BDT_TX						1
/** Value for pp parameter of #BDT_IDX macro which is used to access the
  * even descriptors. */
#define BDT_EVEN					0
/** Value for pp parameter of #BDT_IDX macro which is used to access the
  * odd descriptors. */
#define BDT_ODD						1

/** Because stdlib.h might not be included, NULL might be undefined. NULL
  * is used in #endpoint_states to signify that no state structure has
  * been supplied. */
#ifndef NULL
#define NULL ((void *)0)
#endif // #ifndef NULL

/** USB module buffer descriptor format, as described in section 27.3.5.3.4
  * ("Buffer Descriptor Format") of the PIC32 family reference manual. */
typedef union __attribute__((__packed__)) USBBufferDescriptorStruct
{
	/** Interpretation when handing descriptor to USB module. */
	struct __attribute__((__packed__))
	{
		unsigned int reserved1	: 2;
		/** Set to 1 to issue stall handshake when buffer is used. */
		unsigned int BSTALL		: 1;
		/** Set to 1 to enable checking of data toggle sequence bit. */
		unsigned int DTS		: 1;
		/** Set to 1 to stop DMA from auto-incrementing address. */
		unsigned int NINC		: 1;
		/** Set to 1 to tell USB module to keep the buffer forever. */
		unsigned int KEEP		: 1;
		/** Value of data toggle sequence to use (only if #DTS is 1). */
		unsigned int DATA0_1	: 1;
		/** 0 = owned by CPU, 1 = owned by USB module. */
		unsigned int UOWN		: 1;
		unsigned int reserved2	: 8;
		/** Bytes to send (if transmitting) or maximum number of bytes to
		  * receive (if receiving). */
		unsigned int BYTE_COUNT	: 10;
		unsigned int reserved3	: 6;
		/** Physical address of packet buffer. */
		uint32_t BUFFER_ADDRESS;
	} CTRL;

	/** Interpretation when getting descriptor from USB module. */
	struct __attribute__((__packed__))
	{
		unsigned int reserved1	: 2;
		/** Packet identifier of token packet. */
		unsigned int PID		: 4;
		/** Value of data toggle sequence bit of transacted packet. */
		unsigned int DATA0_1	: 1;
		/** 0 = owned by CPU, 1 = owned by USB module. */
		unsigned int UOWN		: 1;
		unsigned int reserved2	: 8;
		/** Actual number of bytes sent or received. */
		unsigned int BYTE_COUNT	: 10;
		unsigned int reserved3	: 6;
		/** Physical address of packet buffer. */
		uint32_t BUFFER_ADDRESS;
	} STATUS;
} USBBufferDescriptor;

/** USB module buffer descriptor table. To calculate an index into this table,
  * use the #BDT_IDX macro.
  * \warning Due to the way the USB module works, this must be aligned to a
  *          multiple of 512 bytes.
  */
static USBBufferDescriptor bdt_table[NUM_ENDPOINTS * 4] __attribute__((aligned(512)));

/** Array of endpoint state pointers. NULL means no state. This is accessed by
  * the interrupt service routine whenever a successful transaction occurs. */
static EndpointState *endpoint_states[NUM_ENDPOINTS];

/** Resets the USB HAL state. This doesn't reset as much as usbInit(), but
  * resets everything appropriate to a USB protocol reset (as defined in
  * section 7.1.7.5 of the USB specification). */
static void usbHALReset(void)
{
	unsigned int endpoint;

	U1ADDRbits.DEVADDR = 0; // default to device address = 0
	// Reset all data sequence bits.
	for (endpoint = 0; endpoint < NUM_ENDPOINTS; endpoint++)
	{
		if (endpoint_states[endpoint] != NULL)
		{
			endpoint_states[endpoint]->data_sequence = 0;
		}
	}
	usbResetSeen();
}

/** Initialise USB module. */
void usbInit(void)
{
	unsigned int i;
	uint32_t bdt_base_address;

	// Initialise buffer descriptor table.
	memset(bdt_table, 0, sizeof(bdt_table));
	// Enable power to module.
	while (U1PWRCbits.USBBUSY != 0)
	{
		// do nothing
	}
	U1PWRCbits.USBPWR = 1;
	// Tell USB module where the buffer descriptor table is.
	// This throws away the lower 9 bits of the base address (that's why the
	// table needs to be aligned to a multiple of 512 bytes).
	bdt_base_address = VIRTUAL_TO_PHYSICAL(bdt_table);
	U1BDTP1bits.BDTPTRL = ((bdt_base_address >> 9) & 0x7f);
	U1BDTP2bits.BDTPTRH = ((bdt_base_address >> 16) & 0xff);
	U1BDTP3bits.BDTPTRU = ((bdt_base_address >> 24) & 0xff);
	// Initialise other features of USB module.
	U1OTGIE = 0; // disable OTG interrupts
	U1OTGIR = 0xfd; // clear all pending OTG interrupts
	U1PWRCbits.USLPGRD = 0; // no sleep guard
	U1PWRCbits.USUSPEND = 0; // disable suspend mode
	U1OTGCON = 0; // disable OTG mode
	U1IE = 0;
	U1IEbits.URSTIE = 1; // enable USB reset interrupt
	U1IEbits.UERRIE = 1; // enable USB error interrupt
	U1IEbits.TRNIE = 1; // enable token processing complete interrupt
	U1IR = 0xff; // clear all pending USB interrupts
	U1EIE = 0xff; // enable all USB error interrupts
	U1EIR = 0xff; // clear all pending USB error interrupts
	U1CONbits.PKTDIS = 0; // enable packet processing
	U1CONbits.HOSTEN = 0; // device mode
	U1CONbits.RESUME = 0; // don't send RESUME signal
	U1CONbits.PPBRST = 1; // reset ping-pong buffer pointers to EVEN
	U1ADDRbits.LSPDEN = 0; // full-speed mode
	U1ADDRbits.DEVADDR = 0; // default to device address = 0
	U1CNFG1 = 0; // disable USB test mode features
	for (i = 0; i < NUM_ENDPOINTS; i++)
	{
		usbDisableEndpoint(i);
	}
	// Configure interrupt controller for USB interrupts.
	IPC11bits.USBIP = 2; // priority level = 2
	IPC11bits.USBIS = 0; // sub-priority level = 0
	IFS1bits.USBIF = 0; // clear interrupt flag
	IEC1bits.USBIE = 1; // enable interrupt
}

/** Signal USB connect to host. */
void usbConnect(void)
{
	U1CONbits.USBEN = 1; // enable module
}

/** Signal USB disconnect to host. */
void usbDisconnect(void)
{
	U1CONbits.USBEN = 0; // disable module
	usbHALReset();
}

/** Handoff receive buffer of the appropriate endpoint state to the USB
  * module, so that it is ready to receive another packet. This must be called
  * after receiving a packet, otherwise subsequent packets will be NAKed.
  * \param endpoint The device endpoint number.
  */
void usbQueueReceivePacket(unsigned int endpoint)
{
	unsigned int index;
	uint8_t *packet_buffer;
	uint32_t length;

	if (endpoint >= NUM_ENDPOINTS)
	{
		// Bad endpoint number.
		usbFatalError();
		return;
	}
	if (endpoint_states[endpoint] == NULL)
	{
		// Attempting to access non-existent state.
		usbFatalError();
		return;
	}
	index = BDT_IDX(endpoint, BDT_RX, BDT_EVEN);
	if (bdt_table[index].CTRL.UOWN != 0)
	{
		// Attempting to overwrite another queued receive.
		usbFatalError();
		return;
	}
	packet_buffer = endpoint_states[endpoint]->receive_buffer;
	length = sizeof(endpoint_states[endpoint]->receive_buffer);
	// Set buffer parameters.
	bdt_table[index].CTRL.BSTALL = 0;
	// Data sequence checking is done in software. This is because SETUP
	// transactions need to be handled specially.
	bdt_table[index].CTRL.DTS = 0;
	bdt_table[index].CTRL.NINC = 0;
	bdt_table[index].CTRL.KEEP = 0;
	bdt_table[index].CTRL.DATA0_1 = endpoint_states[endpoint]->data_sequence;
	bdt_table[index].CTRL.BYTE_COUNT = length;
	bdt_table[index].CTRL.BUFFER_ADDRESS = VIRTUAL_TO_PHYSICAL(packet_buffer);
	// Tell USB module to process buffer.
	bdt_table[index].CTRL.UOWN = 1;
}

/** Interrupt service handler for USB interrupts. */
void __attribute__((vector(_USB_1_VECTOR), interrupt(ipl2), nomips16)) _USBHandler(void)
{
	unsigned int endpoint;
	unsigned int direction;
	unsigned int is_setup;
	unsigned int is_extended;
	EndpointState *state;
	uint32_t index;
	uint32_t length;
	uint32_t transmitted_bytes;

	usbActivityLED();
	U1CONbits.PPBRST = 1; // reset ping-pong buffer pointers to EVEN
	// Determine cause of interrupt.
	if (U1IRbits.TRNIF)
	{
		// Packet transmitted or received.
		// Clearing TRNIF advances the U1STAT FIFO (see Note 1 of Register
		// 27-10 in the PIC32 family reference manual). Therefore U1STAT must
		// be read before clearing TRNIF.
		endpoint = U1STATbits.ENDPT;
		if (endpoint >= NUM_ENDPOINTS)
		{
			// Bad endpoint number.
			usbFatalError();
			return;
		}
		direction = U1STATbits.DIR;
		// TRNIF needs to be cleared before the next transaction, otherwise
		// an interrupt could be missed. Fourtunately, the minimum time for a
		// valid 0-length data transaction is 32 + 3 + 32 + 3 + 16 + 3 bit
		// periods (token + data + handshake), or 267 cycles at 36 MHz. That's
		// plenty of time, however, TRNIF should still be cleared before
		// doing any packet processing.
		U1IRbits.TRNIF = 1; // clear interrupt flag in USB module
		IFS1bits.USBIF = 0; // clear interrupt flag in interrupt controller
		state = endpoint_states[endpoint];
		if (state == NULL)
		{
			// Attempting to access non-existent state.
			usbFatalError();
			return;
		}
		if (direction == 0)
		{
			// Last transaction was receive.
			index = BDT_IDX(endpoint, BDT_RX, BDT_EVEN);
			length = bdt_table[index].STATUS.BYTE_COUNT;
			is_setup = 0;
			if (bdt_table[index].STATUS.PID == USBPID_SETUP)
			{
				is_setup = 1;
				// From section 8.5.3 of the USB specification, SETUP
				// transactions always use DATA0.
				state->data_sequence = 0;
			}
			// From section 8.6.4 of the USB specification, if a receiver
			// sees mismatching data toggle sequence bits, it should ACK
			// the packet but ignore its contents. This will result in
			// the transmitter and receiver re-synchronising.
			if (bdt_table[index].STATUS.DATA0_1 == state->data_sequence)
			{
				state->data_sequence ^= 1;
				state->receiveCallback(state->receive_buffer, length, is_setup);
			}
			else
			{
				usbQueueReceivePacket(endpoint);
			}
			if (is_setup)
			{
				// Whenever the USB module sees a SETUP packet, it sets
				// PKTDIS, halting all subsequent packet processing. This
				// gives us the opportunity to safely cancel transactions.
				// PKTDIS needs to be cleared, after processing the SETUP
				// packet, otherwise there will be no further transactions.
				U1CONbits.PKTDIS = 0;
			}
		}
		else
		{
			// Last transaction was transmit.
			state->data_sequence ^= 1;
			if (state->is_extended_transmit)
			{
				index = BDT_IDX(endpoint, BDT_TX, BDT_EVEN);
				transmitted_bytes = bdt_table[index].STATUS.BYTE_COUNT;
				// Advance transmission by transmitted_bytes bytes.
				if (state->transmit_remaining < transmitted_bytes)
				{
					// This should never happen.
					usbFatalError();
				}
				state->transmit_remaining -= transmitted_bytes;
				state->transmit_buffer += transmitted_bytes;
				length = state->transmit_remaining;
				// The idea here is to have every packet except the last be
				// marked as an extended transmit. That way, after the last
				// packet is successfully transmitted, the transmit callback
				// will be called.
				// Note that the comparison below is "<" instead of "<="
				// because the last packet must not be of
				// size MAX_PACKET_SIZE, otherwise the other end doesn't
				// know whether the transmission has finished or not. In
				// those cases, an extra zero-length packet is transmitted
				// to resolve the ambiguity (see section 8.5.3.2 of the
				// USB specification).
				if (length < MAX_PACKET_SIZE)
				{
					is_extended = 0;
				}
				else
				{
					is_extended = 1;
				}
				usbQueueTransmitPacket(state->transmit_buffer, length, endpoint, is_extended);
			}
			else
			{
				state->transmitCallback();
			}
		}
	}
	else if (U1IRbits.URSTIF)
	{
		// USB reset seen.
		U1IRbits.URSTIF = 1; // clear interrupt flag in USB module
		IFS1bits.USBIF = 0; // clear interrupt flag in interrupt controller
		usbHALReset();
	}
	else if (U1IRbits.UERRIF)
	{
		// USB error.
		U1IRbits.UERRIF = 1; // clear interrupt flag in USB module
		IFS1bits.USBIF = 0; // clear interrupt flag in interrupt controller
		usbFatalError();
	}
	else
	{
		// This should never happen.
		usbFatalError();
	}
}

/** Get the endpoint control register (U1EPx) for the specified endpoint.
  * \param endpoint The device endpoint number.
  * \return Address of the endpoint control register.
  */
static volatile uint32_t *getEndpointControlRegister(unsigned int endpoint)
{
	switch (endpoint)
	{
	case 0:
		return &(U1EP0);
	case 1:
		return &(U1EP1);
	case 2:
		return &(U1EP2);
	case 3:
		return &(U1EP3);
	case 4:
		return &(U1EP4);
	case 5:
		return &(U1EP5);
	case 6:
		return &(U1EP6);
	case 7:
		return &(U1EP7);
	case 8:
		return &(U1EP8);
	case 9:
		return &(U1EP9);
	case 10:
		return &(U1EP10);
	case 11:
		return &(U1EP11);
	case 12:
		return &(U1EP12);
	case 13:
		return &(U1EP13);
	case 14:
		return &(U1EP14);
	case 15:
		return &(U1EP15);
	default:
		// Bad endpoint number.
		usbFatalError();
		return NULL;
	}
}

/** Disable an endpoint. A disabled endpoint cannot receive or transmit
  * packets. This will also clear any pending I/O.
  * \param endpoint The device endpoint number.
  */
void usbDisableEndpoint(unsigned int endpoint)
{
	uint32_t index;
	volatile uint32_t *reg;

	// Disable transmit/receive for the endpoint.
	if (endpoint >= NUM_ENDPOINTS)
	{
		// Bad endpoint number.
		usbFatalError();
		return;
	}
	reg = getEndpointControlRegister(endpoint);
	*reg = 0;
	// In the worst case, the transmission or reception of a packet could
	// have begun just before "*reg = 0;". To account for this, wait for at
	// least 100 microseconds (greater than the worst-case time for a
	// maximum size transaction) before touching endpoint_states or bdt_table.
	delayCycles(8000); // 100 microseconds at PIC32 maximum speed of 80 MHz
	// It's now safe to modify endpoint_states and bdt_table without worrying
	// about screwing up the interrupt service handler.
	endpoint_states[endpoint] = NULL;
	index = BDT_IDX(endpoint, BDT_RX, BDT_EVEN);
	bdt_table[index].CTRL.UOWN = 0;
	index = BDT_IDX(endpoint, BDT_TX, BDT_EVEN);
	bdt_table[index].CTRL.UOWN = 0;
}

/** Enable endpoint, so that it can begin transmitting and/or receiving.
  * This will automatically call usbQueueReceivePacket() for the endpoint,
  * so it is ready to begin receiving. However, don't forget to call
  * usbQueueReceivePacket() again for each received packet so that
  * subsequent packets can be received.
  * \param endpoint The endpoint number to activate.
  * \param type The type of endpoint (IN, OUT or CONTROL; see #EndpointType).
  * \param state Pointer to buffer which holds per-endpoint state.
  * \warning state must actually be persistent (i.e. do not allocate it on
  *          the stack). This is because it will be accessed by the USB
  *          interrupt service handler.
  */
void usbEnableEndpoint(unsigned int endpoint, EndpointType type, EndpointState *state)
{
	volatile uint32_t *reg;

	if ((state->transmitCallback == NULL) || (state->receiveCallback == NULL))
	{
		// This should never happen.
		usbFatalError();
		return;
	}
	if (endpoint >= NUM_ENDPOINTS)
	{
		// Bad endpoint number.
		usbFatalError();
		return;
	}
	endpoint_states[endpoint] = state;
	state->data_sequence = 0;
	usbQueueReceivePacket(endpoint);
	reg = getEndpointControlRegister(endpoint);
	if (type == IN_ENDPOINT)
	{
		*reg = 0b00000101; // enable handshake and transmit
	}
	else if (type == OUT_ENDPOINT)
	{
		*reg = 0b00001001; // enable handshake and receive
	}
	else if (type == CONTROL_ENDPOINT)
	{
		// Bidirectional control endpoint.
		*reg = 0b00001101; // enable handshake, transmit and receive
	}
	else
	{
		usbFatalError();
	}
}

/** Query whether an endpoint is enabled.
  * \return 0 if the endpoint is disabled, non-zero if it is enabled.
  */
unsigned int usbEndpointEnabled(unsigned int endpoint)
{
	if (endpoint >= NUM_ENDPOINTS)
	{
		// Bad endpoint number.
		usbFatalError();
		return 0;
	}
	if (endpoint_states[endpoint] == NULL)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

/** Queue a packet for transmission. This is non-blocking; it will return
  * immediately, probably having not done any actual transmission. When the
  * packet has actually been transmitted, the transmitCallback function of the
  * endpoint state (see #EndpointState) will be called.
  * \param packet_buffer Address of persistent packet data to transmit.
  * \param length Number of bytes to transmit.
  * \param endpoint The endpoint number of the transmission.
  * \param is_extended Whether to do an extended transmission (non-zero) or
  *                    not (zero). A large (>= #MAX_PACKET_SIZE) extended
  *                    transmission may be split up into multiple packets, as
  *                    described in section 5.5.3 of the USB specification.
  *                    If you're confused over whether to do an extended
  *                    transmit or not, ask the question: is this for the Data
  *                    stage of a control transfer? If not, you probably don't
  *                    need to do an extended transmit.
  * \warning Since this is non-blocking, the data specified by packet_buffer
  *          must persist until the transmitCallback function is called.
  */
void usbQueueTransmitPacket(const uint8_t *packet_buffer, uint32_t length, unsigned int endpoint, unsigned int is_extended)
{
	unsigned int index;

	if (endpoint >= NUM_ENDPOINTS)
	{
		// Bad endpoint number.
		usbFatalError();
		return;
	}
	index = BDT_IDX(endpoint, BDT_TX, BDT_EVEN);
	if (bdt_table[index].CTRL.UOWN != 0)
	{
		// Attempting to overwrite another queued transmission.
		usbFatalError();
		return;
	}
	if (endpoint_states[endpoint] == NULL)
	{
		// Attempting to transmit from a disabled endpoint.
		usbFatalError();
		return;
	}
	endpoint_states[endpoint]->transmit_remaining = length;
	endpoint_states[endpoint]->transmit_buffer = packet_buffer;
	if (length < MAX_PACKET_SIZE)
	{
		// Data will fit entirely in one packet (with room to spare), so it
		// is never necessary to do an extended transmit.
		endpoint_states[endpoint]->is_extended_transmit = 0;
	}
	else if (length == MAX_PACKET_SIZE)
	{
		// Data will fit entirely in one packet. However, if this is part of
		// an extended transmit, an extra zero-length packet needs to be sent,
		// in order to notify the other end that there is no more data. See
		// section 8.5.3.2 of the USB specification.
		endpoint_states[endpoint]->is_extended_transmit = is_extended;
	}
	else if (length > MAX_PACKET_SIZE)
	{
		// Data will not fit entirely in one packet.
		if (is_extended)
		{
			// Split packet into MAX_PACKET_SIZE sized chunks.
			endpoint_states[endpoint]->is_extended_transmit = 1;
			length = MAX_PACKET_SIZE;
		}
		else
		{
			// Tried to send a packet which is too big.
			usbFatalError();
		}
	}
	// Set buffer parameters.
	bdt_table[index].CTRL.BSTALL = 0;
	bdt_table[index].CTRL.DTS = 0;
	bdt_table[index].CTRL.NINC = 0;
	bdt_table[index].CTRL.KEEP = 0;
	bdt_table[index].CTRL.DATA0_1 = endpoint_states[endpoint]->data_sequence;
	bdt_table[index].CTRL.BYTE_COUNT = length;
	bdt_table[index].CTRL.BUFFER_ADDRESS = VIRTUAL_TO_PHYSICAL(packet_buffer);
	// Tell USB module to process buffer.
	bdt_table[index].CTRL.UOWN = 1;
}

/** Cancel a queued transmission.
  * \param endpoint The endpoint number of the transmission to cancel.
  * \warning It is almost always unsafe to call this, because the USB module
  *          operates asynchronously and independently of the CPU. There is
  *          only one time when it is safe: during the Setup stage of a
  *          control transfer.
  */
void usbCancelTransmit(unsigned int endpoint)
{
	unsigned int index;

	if (U1CONbits.PKTDIS == 0)
	{
		// Unsafe situation; the transmit could be in progress.
		usbFatalError();
	}
	if (endpoint >= NUM_ENDPOINTS)
	{
		// Bad endpoint number.
		usbFatalError();
		return;
	}
	index = BDT_IDX(endpoint, BDT_TX, BDT_EVEN);
	if (bdt_table[index].CTRL.UOWN == 0)
	{
		// Try to cancel non-existent transmit.
		usbFatalError();
	}
	bdt_table[index].CTRL.UOWN = 0;
}

/** Stall an endpoint. If the host tries to transact with a stalled endpoint,
  * it will get a stall handshake. This is useful for issuing a control
  * transfer protocol stall (see section 8.5.4.3 of the USB specification).
  * Note that SETUP tokens will automatically unstall an endpoint.
  * \param endpoint The endpoint number of the endpoint to stall.
  */
void usbStallEndpoint(unsigned int endpoint)
{
	volatile uint32_t *reg;

	if (endpoint >= NUM_ENDPOINTS)
	{
		// Bad endpoint number.
		usbFatalError();
		return;
	}
	reg = getEndpointControlRegister(endpoint);
	*reg |= 0x02; // set EPSTALL bit
}

/** Unstall an endpoint. This will clear the stall status of an endpoint
  * previously stalled with usbStallEndpoint().
  * \param endpoint The endpoint number of the endpoint to unstall.
  */
void usbUnstallEndpoint(unsigned int endpoint)
{
	volatile uint32_t *reg;

	if (endpoint >= NUM_ENDPOINTS)
	{
		// Bad endpoint number.
		usbFatalError();
		return;
	}
	reg = getEndpointControlRegister(endpoint);
	*reg &= ~0x02; // clear EPSTALL bit
}

/** Check whether an endpoint is stalled or not.
  * \param endpoint The endpoint number of the endpoint to check.
  * \return Non-zero if the endpoint is stalled, zero if it is not stalled.
  */
unsigned int usbGetStallStatus(unsigned int endpoint)
{
	volatile uint32_t *reg;

	if (endpoint >= NUM_ENDPOINTS)
	{
		// Bad endpoint number.
		usbFatalError();
		return 1;
	}
	reg = getEndpointControlRegister(endpoint);
	if ((*reg & 0x02) != 0) // check EPSTALL bit
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

/** Set the device address which the USB module will respond to. Upon return,
  * The USB module will ignore all subsequent transactions which are not
  * directed towards the specified address.
  * \param address The USB device address to use.
  */
void usbSetDeviceAddress(unsigned int address)
{
	U1ADDRbits.DEVADDR = address;
}

/** This function allows drivers to override the next transaction's data
  * sequence toggle bit. For example, section 8.5.3 of the USB specification
  * says that the Status stage of a control transfer always uses a value
  * of 1, regardless of the previous value.
  * \param endpoint The endpoint number of the endpoint to modify.
  * \param new_data_sequence Data toggle sequence bit for next packet to be
  *                          transmitted or received (0 = DATA0, 1 = DATA1).
  */
void usbOverrideDataSequence(unsigned int endpoint, unsigned int new_data_sequence)
{
	if (endpoint >= NUM_ENDPOINTS)
	{
		// Bad endpoint number.
		usbFatalError();
		return;
	}
	if (endpoint_states[endpoint] == NULL)
	{
		// Attempting to override non-existent state.
		usbFatalError();
		return;
	}
	if (new_data_sequence == 0)
	{
		endpoint_states[endpoint]->data_sequence = 0;
	}
	else
	{
		endpoint_states[endpoint]->data_sequence = 1;
	}
}

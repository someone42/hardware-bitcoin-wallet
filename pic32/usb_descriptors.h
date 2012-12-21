/** \file usb_descriptors.h
  *
  * \brief Defines USB device descriptors.
  *
  * During enumeration, a USB host will request information about the
  * properties and configuration of a USB device. This information is contained
  * in USB descriptors. The descriptors have been placed in an isolated file
  * to make them easier to inspect and modify.
  *
  * Checklist when modifying:
  * - Do all length cross-references match (example: total length of all
  *   included descriptors in configuration descriptor)? If they don't, device
  *   enumeration will probably fail.
  * - Are all multi-byte numbers little-endian?
  *
  * All references to the "USB specification" refer to revision 2.0, obtained
  * from http://www.usb.org/developers/docs/usb_20_110512.zip (see usb_20.pdf)
  * on 26 March 2012. All references to the "HID specification" refer to
  * revision 1.1, obtained
  * from http://www.usb.org/developers/devclass_docs/HID1_11.pdf
  * on 25 November 2012.
  * All references to the "USB LANGIDs specification" refer to version 1.00,
  * obtained from http://www.usb.org/developers/docs/USB_LANGIDs.pdf
  * on 9 December 2012.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef USB_DESCRIPTORS_H
#define	USB_DESCRIPTORS_H

#include <stdint.h>
#include "usb_defs.h"

#ifndef ONLY_INCLUDE_REPORT_DESCRIPTOR

/** Index of manufacturer string descriptor. */
#define MANUFACTURER_STRING_INDEX		1
/** Index of product string descriptor. */
#define PRODUCT_STRING_INDEX			2
/** Index of serial number string descriptor. */
#define SERIAL_NO_STRING_INDEX			3

/** Primary language identifier for "English". See the USB LANGIDs
  * specification, page 8. */
#define PRIMARY_LANGUAGE_ID				0x09

/** Device descriptor. This is what will be returned in a "Get Descriptor"
  * request with descriptor type == #DESCRIPTOR_DEVICE. See section 9.6.1
  * of the USB specification for details on the format.
  * \showinitializer
  */
static const uint8_t device_descriptor[] = {
0x12, // length of this descriptor in bytes
DESCRIPTOR_DEVICE, // descriptor type
0x00, 0x02, // USB version number in little-endian BCD (v2.00)
0x00, // device class (0 = refer to interface)
0x00, // device subclass (0 = refer to interface)
0x00, // device protocol (0 = refer to interface)
0x40, // maximum packet size for control endpoint (endpoint 0)
0xf3, 0x04, // vendor ID (little-endian)
0x10, 0x02, // product ID (little-endian)
0x90, 0x22, // device release number in little-endian BCD
MANUFACTURER_STRING_INDEX, // index of string descriptor describing manufacturer
PRODUCT_STRING_INDEX, // index of string descriptor describing product
SERIAL_NO_STRING_INDEX, // index of string descriptor describing serial number
0x01 // number of configurations
};

/** Configuration descriptor. Actually, all the required configuration,
  * interface, class-specific and endpoint descriptors must also be
  * included. This is because the "Get Descriptor" request with descriptor
  * type == #DESCRIPTOR_CONFIGURATION will return this descriptor, and the
  * USB specification (see section 9.4.3) says they should all be
  * concatenated together. See sections 9.6.3, 9.6.5 and 9.6.6
  * of the USB specification for details on the format of configuration,
  * interface and endpoint descriptors (respectively). Also, see section
  * 6.2.1 of the HID specification for details on the format of the HID
  * descriptor. Section 7.1 of the HID specification describes the ordering
  * of descriptors (configuration, then interface, then HID, then endpoint).
  * \showinitializer
  */
static const uint8_t configuration_descriptor[] = {
// Configuration descriptor:
0x09, // length of this descriptor in bytes
DESCRIPTOR_CONFIGURATION, // descriptor type
#ifdef NO_INTERRUPT_OUT
0x22, 0x00, // total length of all included descriptors in bytes (little-endian)
#else
0x29, 0x00, // total length of all included descriptors in bytes (little-endian)
#endif // #ifdef NO_INTERRUPT_OUT
0x01, // number of interfaces supported by this configuration
0x01, // configuration value (must be 1, usb_standard_requests.c assumes this)
0x00, // index of string descriptor describing configuration (0 = none)
0x80, // attributes (0x80 = not self-powered, no remote wakeup)
0x32, // maximum current consumption in 2 mA units (0x32 = 100 mA)
// Interface descriptor:
0x09, // length of this descriptor in bytes
DESCRIPTOR_INTERFACE, // descriptor type
0x00, // number of this interface (0 = first)
0x00, // alternate setting (0 = default)
#ifdef NO_INTERRUPT_OUT
0x01, // number of endpoints used by this interface, not including control endpoint
#else
0x02, // number of endpoints used by this interface, not including control endpoint
#endif // #ifdef NO_INTERRUPT_OUT
0x03, // interface class (3 = HID)
0x00, // interface subclass (0 = no subclass)
0x00, // interface protocol (0 = none)
0x00, // index of string descriptor describing interface (0 = none)
// HID descriptor:
0x09, // length of this descriptor in bytes
DESCRIPTOR_HID, // descriptor type
0x11, 0x01, // HID version number in little-endian BCD (v1.11)
0x00, // country code (0 = not supported)
0x01, // number of report descriptors
DESCRIPTOR_REPORT, // descriptor type of report descriptor
0x03, 0x03, // total size of report descriptors in bytes (little-endian)
// Endpoint 1 descriptor:
0x07, // length of this descriptor in bytes
DESCRIPTOR_ENDPOINT, // descriptor type
0x81, // endpoint number; bit 7 set means IN, endpoint 1
0x03, // attributes (3 = interrupt transfers)
0x40, 0x00, // maximum packet size of this endpoint in bytes (little-endian)
0x0a, // polling interval, in millisecond
#ifndef NO_INTERRUPT_OUT
// Endpoint 2 descriptor:
0x07, // length of this descriptor in bytes
DESCRIPTOR_ENDPOINT, // descriptor type
0x02, // endpoint number; bit 7 clear means OUT, endpoint 2
0x03, // attributes (3 = interrupt transfers)
0x40, 0x00, // maximum packet size of this endpoint in bytes (little-endian)
0x01 // polling interval, in millisecond
#endif // #ifndef NO_INTERRUPT_OUT
};

/** Section 9.6.7 of the USB specification states that if a device returns
  * string descriptors, string descriptor zero should contain a list of
  * supported languages. This list consists of 2 byte language identifiers,
  * which are described in the USB LANGIDs specification. Unfourtunately,
  * there's no way to just say "English" (using 0 for the sub-language
  * identifier doesn't work on Windows), so every "variant" of English is
  * included here to ensure that all operating systems recognise the string
  * descriptors as being in English.
  * \showinitializer
  */
static const uint8_t lang_id_list[] = {
0x1c, // length of this descriptor in bytes
DESCRIPTOR_STRING, // descriptor type
0x09, 0x04, // English (United States)
0x09, 0x08, // English (United Kingdom)
0x09, 0x0c, // English (Australian)
0x09, 0x10, // English (Canadian)
0x09, 0x14, // English (New Zealand)
0x09, 0x18, // English (Ireland)
0x09, 0x1c, // English (South Africa)
0x09, 0x20, // English (Jamaica)
0x09, 0x24, // English (Caribbean)
0x09, 0x28, // English (Belize)
0x09, 0x2c, // English (Trinidad)
0x09, 0x30, // English (Zimbabwe)
0x09, 0x34, // English (Philippines)
};

/** Manufacturer string descriptor. During enumeration, this is sometimes
  * displayed to the user. Contents must be in Unicode.
  * \showinitializer
  */
static const uint8_t manufacturer_string[] = {
0x18, // length of this descriptor in bytes
DESCRIPTOR_STRING,
'H', 0, 'e', 0, 'l', 0, 'l', 0, 'o', 0, ' ', 0, 'w', 0, 'o', 0,
'r', 0, 'l', 0, 'd', 0};

/** Product string descriptor. During enumeration, this is sometimes
  * displayed to the user. Contents must be in Unicode.
  * \showinitializer
  */
static const uint8_t product_string[] = {
0x30, // length of this descriptor in bytes
DESCRIPTOR_STRING,
'H', 0, 'a', 0, 'r', 0, 'd', 0, 'w', 0, 'a', 0, 'r', 0, 'e', 0,
' ', 0, 'B', 0, 'i', 0, 't', 0, 'c', 0, 'o', 0, 'i', 0, 'n', 0,
' ', 0, 'w', 0, 'a', 0, 'l', 0, 'l', 0, 'e', 0, 't', 0};

/** Serial number string descriptor. Contents must be in Unicode.
  * \showinitializer
  */
static const uint8_t serial_no_string[] = {
0x0c, // length of this descriptor in bytes
DESCRIPTOR_STRING,
'1', 0, '2', 0, '3', 0, '4', 0, '5', 0};

#endif // #ifndef ONLY_INCLUDE_REPORT_DESCRIPTOR

#ifndef DONT_INCLUDE_REPORT_DESCRIPTOR

/** USB HID report descriptor. This report descriptor was generated partly
  * using "HID Descriptor Tool" v2.4, which was obtained from
  * http://www.usb.org/developers/hidpage/dt2_4.zip on 17 December 2012.
  * This report descriptor describes a series of reports which carry up to
  * 63 bytes of vendor-defined data, where the report ID is the same as the
  * number of bytes of data. Everything is "vendor-defined" so that no
  * operating system will attempt to interpret the device as some sort of
  * system device (like a keyboard). Mandatory items are provided, as
  * described on page 25 of the USB HID specification. The reports are wrapped
  * up in a (vendor-defined) collection because Windows seems to require this.
  * The "USAGE (Vendor Usage 1)" item appears multiple times because it is
  * a Local Item (see section 6.2.2.8 of the USB HID specification) and thus is
  * consumed by the Main Items: COLLECTION, INPUT and OUTPUT.
  * Note that it is essential to provide a valid description of every report,
  * otherwise Windows will refuse to transfer reports to/from the device.
  *
  * Here's some Python code to generate the repetitive stuff:
\code
for i in range(1, 64):
	print("0x85, {0:#04x},                    //   REPORT_ID ({0})".format(i))
	print("0x95, {0:#04x},                    //   REPORT_COUNT ({0})".format(i))
	print("0x09, 0x01,                    //   USAGE (Vendor Usage 1)")
	print("0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)")
	print("0x09, 0x01,                    //   USAGE (Vendor Usage 1)")
	print("0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)")

\endcode
  * \showinitializer
  */
static const uint8_t report_descriptor[] = {
0x06, 0x00, 0xff,              // USAGE_PAGE (Vendor Defined Page 1)
0x09, 0x01,                    // USAGE (Vendor Usage 1)
0xa1, 0x01,                    // COLLECTION (Application)
0x15, 0x00,                    //   LOGICAL_MINIMUM (0)
0x26, 0xff, 0x00,              //   LOGICAL_MAXIMUM (255)
0x75, 0x08,                    //   REPORT_SIZE (8)
0x85, 0x01,                    //   REPORT_ID (1)
0x95, 0x01,                    //   REPORT_COUNT (1)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x02,                    //   REPORT_ID (2)
0x95, 0x02,                    //   REPORT_COUNT (2)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x03,                    //   REPORT_ID (3)
0x95, 0x03,                    //   REPORT_COUNT (3)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x04,                    //   REPORT_ID (4)
0x95, 0x04,                    //   REPORT_COUNT (4)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x05,                    //   REPORT_ID (5)
0x95, 0x05,                    //   REPORT_COUNT (5)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x06,                    //   REPORT_ID (6)
0x95, 0x06,                    //   REPORT_COUNT (6)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x07,                    //   REPORT_ID (7)
0x95, 0x07,                    //   REPORT_COUNT (7)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x08,                    //   REPORT_ID (8)
0x95, 0x08,                    //   REPORT_COUNT (8)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x09,                    //   REPORT_ID (9)
0x95, 0x09,                    //   REPORT_COUNT (9)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x0a,                    //   REPORT_ID (10)
0x95, 0x0a,                    //   REPORT_COUNT (10)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x0b,                    //   REPORT_ID (11)
0x95, 0x0b,                    //   REPORT_COUNT (11)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x0c,                    //   REPORT_ID (12)
0x95, 0x0c,                    //   REPORT_COUNT (12)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x0d,                    //   REPORT_ID (13)
0x95, 0x0d,                    //   REPORT_COUNT (13)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x0e,                    //   REPORT_ID (14)
0x95, 0x0e,                    //   REPORT_COUNT (14)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x0f,                    //   REPORT_ID (15)
0x95, 0x0f,                    //   REPORT_COUNT (15)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x10,                    //   REPORT_ID (16)
0x95, 0x10,                    //   REPORT_COUNT (16)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x11,                    //   REPORT_ID (17)
0x95, 0x11,                    //   REPORT_COUNT (17)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x12,                    //   REPORT_ID (18)
0x95, 0x12,                    //   REPORT_COUNT (18)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x13,                    //   REPORT_ID (19)
0x95, 0x13,                    //   REPORT_COUNT (19)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x14,                    //   REPORT_ID (20)
0x95, 0x14,                    //   REPORT_COUNT (20)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x15,                    //   REPORT_ID (21)
0x95, 0x15,                    //   REPORT_COUNT (21)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x16,                    //   REPORT_ID (22)
0x95, 0x16,                    //   REPORT_COUNT (22)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x17,                    //   REPORT_ID (23)
0x95, 0x17,                    //   REPORT_COUNT (23)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x18,                    //   REPORT_ID (24)
0x95, 0x18,                    //   REPORT_COUNT (24)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x19,                    //   REPORT_ID (25)
0x95, 0x19,                    //   REPORT_COUNT (25)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x1a,                    //   REPORT_ID (26)
0x95, 0x1a,                    //   REPORT_COUNT (26)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x1b,                    //   REPORT_ID (27)
0x95, 0x1b,                    //   REPORT_COUNT (27)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x1c,                    //   REPORT_ID (28)
0x95, 0x1c,                    //   REPORT_COUNT (28)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x1d,                    //   REPORT_ID (29)
0x95, 0x1d,                    //   REPORT_COUNT (29)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x1e,                    //   REPORT_ID (30)
0x95, 0x1e,                    //   REPORT_COUNT (30)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x1f,                    //   REPORT_ID (31)
0x95, 0x1f,                    //   REPORT_COUNT (31)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x20,                    //   REPORT_ID (32)
0x95, 0x20,                    //   REPORT_COUNT (32)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x21,                    //   REPORT_ID (33)
0x95, 0x21,                    //   REPORT_COUNT (33)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x22,                    //   REPORT_ID (34)
0x95, 0x22,                    //   REPORT_COUNT (34)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x23,                    //   REPORT_ID (35)
0x95, 0x23,                    //   REPORT_COUNT (35)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x24,                    //   REPORT_ID (36)
0x95, 0x24,                    //   REPORT_COUNT (36)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x25,                    //   REPORT_ID (37)
0x95, 0x25,                    //   REPORT_COUNT (37)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x26,                    //   REPORT_ID (38)
0x95, 0x26,                    //   REPORT_COUNT (38)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x27,                    //   REPORT_ID (39)
0x95, 0x27,                    //   REPORT_COUNT (39)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x28,                    //   REPORT_ID (40)
0x95, 0x28,                    //   REPORT_COUNT (40)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x29,                    //   REPORT_ID (41)
0x95, 0x29,                    //   REPORT_COUNT (41)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x2a,                    //   REPORT_ID (42)
0x95, 0x2a,                    //   REPORT_COUNT (42)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x2b,                    //   REPORT_ID (43)
0x95, 0x2b,                    //   REPORT_COUNT (43)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x2c,                    //   REPORT_ID (44)
0x95, 0x2c,                    //   REPORT_COUNT (44)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x2d,                    //   REPORT_ID (45)
0x95, 0x2d,                    //   REPORT_COUNT (45)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x2e,                    //   REPORT_ID (46)
0x95, 0x2e,                    //   REPORT_COUNT (46)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x2f,                    //   REPORT_ID (47)
0x95, 0x2f,                    //   REPORT_COUNT (47)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x30,                    //   REPORT_ID (48)
0x95, 0x30,                    //   REPORT_COUNT (48)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x31,                    //   REPORT_ID (49)
0x95, 0x31,                    //   REPORT_COUNT (49)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x32,                    //   REPORT_ID (50)
0x95, 0x32,                    //   REPORT_COUNT (50)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x33,                    //   REPORT_ID (51)
0x95, 0x33,                    //   REPORT_COUNT (51)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x34,                    //   REPORT_ID (52)
0x95, 0x34,                    //   REPORT_COUNT (52)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x35,                    //   REPORT_ID (53)
0x95, 0x35,                    //   REPORT_COUNT (53)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x36,                    //   REPORT_ID (54)
0x95, 0x36,                    //   REPORT_COUNT (54)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x37,                    //   REPORT_ID (55)
0x95, 0x37,                    //   REPORT_COUNT (55)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x38,                    //   REPORT_ID (56)
0x95, 0x38,                    //   REPORT_COUNT (56)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x39,                    //   REPORT_ID (57)
0x95, 0x39,                    //   REPORT_COUNT (57)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x3a,                    //   REPORT_ID (58)
0x95, 0x3a,                    //   REPORT_COUNT (58)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x3b,                    //   REPORT_ID (59)
0x95, 0x3b,                    //   REPORT_COUNT (59)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x3c,                    //   REPORT_ID (60)
0x95, 0x3c,                    //   REPORT_COUNT (60)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x3d,                    //   REPORT_ID (61)
0x95, 0x3d,                    //   REPORT_COUNT (61)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x3e,                    //   REPORT_ID (62)
0x95, 0x3e,                    //   REPORT_COUNT (62)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0x85, 0x3f,                    //   REPORT_ID (63)
0x95, 0x3f,                    //   REPORT_COUNT (63)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x81, 0x82,                    //   INPUT (Data,Var,Abs,Vol)
0x09, 0x01,                    //   USAGE (Vendor Usage 1)
0x91, 0x82,                    //   OUTPUT (Data,Var,Abs,Vol)
0xc0                           // END_COLLECTION
};

#endif // #ifndef DONT_INCLUDE_REPORT_DESCRIPTOR

#endif	// #ifndef USB_DESCRIPTORS_H

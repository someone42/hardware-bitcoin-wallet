// usb_request_tester.c
//
// This will use libusb-1.0 to investigate how a USB device responds to valid
// and invalid USB standard requests.
// While this should run under any modern OS, it is normal for certain tests
// (related to configurations) to fail when run in Windows, due to an
// apparent OS-level interception of "Set Configuration" requests.
//
// This file is licensed as described by the file LICENCE.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <libusb.h>

// Vendor ID of target device. This must match the vendor ID in the
// device's device descriptor.
#define TARGET_VID		0x04f3
// Product ID of target device. This must match the product ID in the
// device's device descriptor.
#define TARGET_PID		0x0210

// Request timeout, in millisecond. This is long, so that debugging is easier.
// But it's not much worth in making it > 5 seconds, since sometimes control
// transfers will time out at 5 seconds regardless of this value.
#define TIMEOUT			5000

// Number of tests which failed.
static unsigned int tests_failed;
// Number of tests which succeeded.
static unsigned int tests_succeeded;

// libusb-1.0 device handle of target device, so that it doesn't have to be
// passed around all the time.
libusb_device_handle *device_handle;

// Initialise libusb and attempt to open the target device.
// Returns the device handle on success.
// Returns NULL if the target device was not found.
static libusb_device_handle *init(void)
{
	int r;
	libusb_device **list;
	libusb_device_handle *opened_device_handle;
	struct libusb_device_descriptor device_info;
	ssize_t count;
	ssize_t i;
	int bus_number;
	int address;

   	r = libusb_init(NULL);
	if (r < 0)
	{
		printf("ERROR: Could not initialise libusb, return value = %d\n", r);
		exit(1);
	}

	// Loop through all buses/devices and find the right one.
	count = libusb_get_device_list(NULL, &list);
	for (i = 0; i < count; i++)
	{
		if (libusb_get_device_descriptor(list[i], &device_info) == 0)
		{
			if ((device_info.idVendor == TARGET_VID)
				&& (device_info.idProduct == TARGET_PID))
			{
				bus_number = libusb_get_bus_number(list[i]);
				address = libusb_get_device_address(list[i]);
				printf("Found device on bus %d, address = %d\n", bus_number, address);
				r = libusb_open(list[i], &opened_device_handle);
				if (r != 0)
				{
					printf("ERROR: Could not open device, %s\n", libusb_error_name(r));
					printf("Maybe you need to run this program as root.\n");
					printf("If using Windows, have you installed the WinUSB driver?\n");
					exit(1);
				}
				libusb_free_device_list(list, 1);
				// Just in case, detach kernel driver from interface.
				libusb_detach_kernel_driver(opened_device_handle, 0);
				libusb_detach_kernel_driver(opened_device_handle, 1);
				return opened_device_handle;
			}
		}
	}
	libusb_free_device_list(list, 1);
	return NULL;
}

// Tests based on setting and getting device configuration.
// This primarily tests the "Get Configuration" and "Set Configuration"
// requests.
static void configuration_tests(void)
{
	libusb_device *device;
	int i;
	unsigned int config_value;
	int r;
	struct libusb_device_descriptor device_info;
	struct libusb_config_descriptor *config_info;
	uint8_t buffer[64];

	device = libusb_get_device(device_handle);
	if (libusb_get_device_descriptor(device, &device_info) != 0)
	{
		printf("ERROR: Could not get device descriptor\n");
		exit(1);
	}
	// Go through all configs of device. -1 = unconfigured.
	for (i = -1; i < device_info.bNumConfigurations; i++)
	{
		if (i == -1)
		{
			config_value = 0;
		}
		else
		{
			if (libusb_get_config_descriptor(device, (uint8_t)i, &config_info) != 0)
			{
				printf("ERROR: Could not get configuration descriptor\n");
				exit(1);
			}
			config_value = config_info->bConfigurationValue;
			libusb_free_config_descriptor(config_info);
		}
		// Set the configuration to some value, then get it and check that the
		// obtained value matches what was set.
		r = libusb_control_transfer(device_handle, 0x00,
			LIBUSB_REQUEST_SET_CONFIGURATION, config_value, 0, buffer, 0, TIMEOUT);
		if (r < 0)
		{
			printf("Set configuration for config_value = %u failed\n", config_value);
			tests_failed++;
		}
		else
		{
			tests_succeeded++;
		}
		r = libusb_control_transfer(device_handle, 0x80,
			LIBUSB_REQUEST_GET_CONFIGURATION, 0, 0, buffer, 1, TIMEOUT);
		if (r < 0)
		{
			printf("Get configuration for config_value = %u failed\n", config_value);
			tests_failed++;
		}
		else
		{
			tests_succeeded++;
		}
		if (buffer[0] != config_value)
		{
			printf("Get configuration data doesn't match config_value %u\n", config_value);
			tests_failed++;
		}
		else
		{
			tests_succeeded++;
		}
	} // end for (i = -1; i < device_info.bNumConfigurations; i++)

	// Try some invalid configuration values.
	r = libusb_control_transfer(device_handle, 0x00,
		LIBUSB_REQUEST_SET_CONFIGURATION, 0xff, 0, buffer, 0, TIMEOUT);
	if (r >= 0)
	{
		printf("Set configuration for config_value = 0xff succeeded\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	r = libusb_control_transfer(device_handle, 0x00,
		LIBUSB_REQUEST_SET_CONFIGURATION, 0xffff, 0, buffer, 0, TIMEOUT);
	if (r >= 0)
	{
		printf("Set configuration for config_value = 0xffff succeeded\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	// Current configuration should be unchanged.
	r = libusb_control_transfer(device_handle, 0x80,
		LIBUSB_REQUEST_GET_CONFIGURATION, 0, 0, buffer, 1, TIMEOUT);
	if ((r < 0) || (buffer[0] != config_value))
	{
		printf("Invalid set configuration messes with configuration\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
}

// Tests based on USB descriptors.
// This primarily tests the "Get Descriptor" request.
static void descriptor_tests(void)
{
	uint8_t buffer[1024];
	char string_buffer[1024];
	unsigned int i;
	int r;

	// Check that device descriptor is exactly 18 bytes long.
	r = libusb_get_descriptor(device_handle, LIBUSB_DT_DEVICE, 0, buffer, sizeof(buffer));
	if (r != 18)
	{
		printf("Could not get valid device descriptor\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	// Check that a truncated device descriptor can be obtained.
	r = libusb_get_descriptor(device_handle, LIBUSB_DT_DEVICE, 0, buffer, 7);
	if (r != 7)
	{
		printf("Could not get truncated (length = 7) device descriptor\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	// index != 0 is invalid for device descriptors.
	r = libusb_get_descriptor(device_handle, LIBUSB_DT_DEVICE, 0xff, buffer, sizeof(buffer));
	if (r >= 0)
	{
		printf("Get device descriptor succeeds for index != 0\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	// Get first configuration descriptor.
	r = libusb_get_descriptor(device_handle, LIBUSB_DT_CONFIG, 0, buffer, sizeof(buffer));
	if (r < 0)
	{
		printf("Could not get first configuration descriptor\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	// Get all string descriptors.
	for (i = 0; i <= 0xff; i++)
	{
		r = libusb_get_string_descriptor_ascii(device_handle, i, string_buffer, sizeof(string_buffer));
		if (r >= 0)
		{
			printf("String descriptor %u: \"%s\"\n", i, string_buffer);
		}
	}
	// Attempt to get interface and endpoint descriptors. This should fail
	// (those descriptors as supposed to be included only as part of the
	// configuration descriptor).
	r = libusb_get_descriptor(device_handle, LIBUSB_DT_INTERFACE, 0, buffer, sizeof(buffer));
	if (r >= 0)
	{
		printf("Was able to get interface descriptor directly\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	r = libusb_get_descriptor(device_handle, LIBUSB_DT_ENDPOINT, 0, buffer, sizeof(buffer));
	if (r >= 0)
	{
		printf("Was able to get endpoint descriptor directly\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
}

// Tests based on the endpoint halt and status features.
// This primarily tests the "Clear Feature", "Set Feature" and "Get Status"
// requests.
static void halt_and_status_tests(void)
{
	uint8_t buffer[1024];
	int r;

	// Ensure that device is configured and that the OS doesn't own the
	// interface.
	libusb_set_configuration(device_handle, 1);
	libusb_claim_interface(device_handle, 0);

	// Halt endpoint 1, checking that its status is updated accordingly.
	r = libusb_control_transfer(device_handle, 0x02,
		LIBUSB_REQUEST_SET_FEATURE, 0, 0x81, buffer, 0, TIMEOUT);
	if (r < 0)
	{
		printf("Could not halt endpoint 1\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	r = libusb_control_transfer(device_handle, 0x82,
		LIBUSB_REQUEST_GET_STATUS, 0, 0x81, buffer, 2, TIMEOUT);
	if (r != 2)
	{
		printf("Could not get status of endpoint 1\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	if ((buffer[0] != 1) || (buffer[1] != 0))
	{
		printf("Status of endpoint 1 is unexpected\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	// Unhalt endpoint 1, checking that its status is updated accordingly.
	r = libusb_control_transfer(device_handle, 0x02,
		LIBUSB_REQUEST_CLEAR_FEATURE, 0, 0x81, buffer, 0, TIMEOUT);
	if (r < 0)
	{
		printf("Could not unhalt endpoint 1\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	libusb_control_transfer(device_handle, 0x82,
		LIBUSB_REQUEST_GET_STATUS, 0, 0x81, buffer, 2, TIMEOUT);
	if ((buffer[0] != 0) || (buffer[1] != 0))
	{
		printf("Status of endpoint 1 is unexpected 2\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	// Get status of device and interface.
	r = libusb_control_transfer(device_handle, 0x80,
		LIBUSB_REQUEST_GET_STATUS, 0, 0, buffer, 2, TIMEOUT);
	if (r < 0)
	{
		printf("Could not get device status\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	if ((buffer[0] != 0) || (buffer[1] != 0))
	{
		printf("Status of device is unexpected 2\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	r = libusb_control_transfer(device_handle, 0x81,
		LIBUSB_REQUEST_GET_STATUS, 0, 0, buffer, 2, TIMEOUT);
	if (r < 0)
	{
		printf("Could not get interface status\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
	if ((buffer[0] != 0) || (buffer[1] != 0))
	{
		printf("Status of interface is unexpected 2\n");
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
}

// Do a control transfer, expecting it to fail.
static void one_invalid_test(uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint16_t wLength)
{
	int r;
	uint8_t buffer[1024];

	r = libusb_control_transfer(device_handle, bmRequestType,
		bRequest, wValue, wIndex, buffer, wLength, TIMEOUT);
	if (r >= 0)
	{
		printf("Request unexpectedly succeeded\n");
		printf("  bmRequestType = %d, bRequest = %d\n", (int)bmRequestType, (int)bRequest);
		printf("  wValue = %d, wIndex = %d, wLength = %d\n", (int)wValue, (int)wIndex, (int)wLength);
		tests_failed++;
	}
	else
	{
		tests_succeeded++;
	}
}

// Tests based on invalid requests.
// These are not exhaustive.
static void invalid_tests(void)
{
	// Unknown request.
	one_invalid_test(0x00, 42, 0x100, 0, 8);
	// Clear device or interface features (shouldn't be supported).
	one_invalid_test(0x00, LIBUSB_REQUEST_CLEAR_FEATURE, 1, 0, 0);
	one_invalid_test(0x01, LIBUSB_REQUEST_CLEAR_FEATURE, 0, 0, 0);
	// Bad endpoint numbers for clear endpoint features.
	one_invalid_test(0x02, LIBUSB_REQUEST_CLEAR_FEATURE, 0, 0x83, 0);
	one_invalid_test(0x02, LIBUSB_REQUEST_CLEAR_FEATURE, 0, 0x7f, 0);
	// Wrong feature selector in clear feature.
	one_invalid_test(0x02, LIBUSB_REQUEST_CLEAR_FEATURE, 1, 0x81, 0);
	// Length != 0 in clear feature.
	one_invalid_test(0x02, LIBUSB_REQUEST_CLEAR_FEATURE, 0, 0x81, 1);
	// Get configuration with bad request type.
	one_invalid_test(0x00, LIBUSB_REQUEST_GET_CONFIGURATION, 0, 0, 0);
	// Get configuration with bad value.
	one_invalid_test(0x80, LIBUSB_REQUEST_GET_CONFIGURATION, 1, 0, 0);
	// Get configuration with bad index.
	one_invalid_test(0x80, LIBUSB_REQUEST_GET_CONFIGURATION, 0, 0xfe, 0);
	// Get configuration with bad length.
	one_invalid_test(0x80, LIBUSB_REQUEST_GET_CONFIGURATION, 0, 0, 42);
	// Get descriptor with bad request type.
	one_invalid_test(0x00, LIBUSB_REQUEST_GET_DESCRIPTOR, 0x100, 0, 18);
	// Get descriptor with bad descriptor type.
	one_invalid_test(0x80, LIBUSB_REQUEST_GET_DESCRIPTOR, 0xff00, 0, 18);
	// Get device descriptor with descriptor index != 0.
	one_invalid_test(0x80, LIBUSB_REQUEST_GET_DESCRIPTOR, 0x101, 0, 18);
	// Get device descriptor with index != 0.
	one_invalid_test(0x80, LIBUSB_REQUEST_GET_DESCRIPTOR, 0x100, 1, 18);
	// Get status with slightly out-of-range request type.
	one_invalid_test(0x83, LIBUSB_REQUEST_GET_STATUS, 0, 0, 2);
	// Get status with value != 0.
	one_invalid_test(0x82, LIBUSB_REQUEST_GET_STATUS, 42, 0, 2);
	// Get status with length != 2.
	one_invalid_test(0x82, LIBUSB_REQUEST_GET_STATUS, 0, 0, 1);
	// Set address with bad address.
	one_invalid_test(0x00, LIBUSB_REQUEST_SET_ADDRESS, 0xff01, 0, 0);
	// Set address with index != 0.
	one_invalid_test(0x00, LIBUSB_REQUEST_SET_ADDRESS, 0, 1, 0);
	// Set address with length != 0.
	one_invalid_test(0x00, LIBUSB_REQUEST_SET_ADDRESS, 0, 0, 1);
	// Set configuration with bad configuration.
	one_invalid_test(0x00, LIBUSB_REQUEST_SET_CONFIGURATION, 2, 0, 0);
	one_invalid_test(0x00, LIBUSB_REQUEST_SET_CONFIGURATION, 0xff01, 0, 0);
	// Set configuration with index != 0.
	one_invalid_test(0x00, LIBUSB_REQUEST_SET_CONFIGURATION, 1, 1, 0);
	// Set configuration with length != 0.
	one_invalid_test(0x00, LIBUSB_REQUEST_SET_CONFIGURATION, 1, 0, 1);
	// Set device or interface features (shouldn't be supported).
	one_invalid_test(0x00, LIBUSB_REQUEST_SET_FEATURE, 1, 0, 0);
	one_invalid_test(0x01, LIBUSB_REQUEST_SET_FEATURE, 0, 0, 0);
	// Bad endpoint numbers for set endpoint features.
	one_invalid_test(0x02, LIBUSB_REQUEST_SET_FEATURE, 0, 0x83, 0);
	one_invalid_test(0x02, LIBUSB_REQUEST_SET_FEATURE, 0, 0x7f, 0);
	// Wrong feature selector in set feature.
	one_invalid_test(0x02, LIBUSB_REQUEST_SET_FEATURE, 1, 0x81, 0);
	// Length != 0 in set feature.
	one_invalid_test(0x02, LIBUSB_REQUEST_SET_FEATURE, 0, 0x81, 1);
}

int main(void)
{
	uint8_t buffer[64];

	device_handle = init();
	if (device_handle == NULL)
	{
		printf("ERROR: Could not find appropriate device\n");
		exit(1);
	}

	tests_succeeded = 0;
	tests_failed = 0;
	configuration_tests();
	descriptor_tests();
	halt_and_status_tests();
	invalid_tests();

	printf("Tests which failed: %u\n", tests_failed);
	printf("Tests which succeeded: %u\n", tests_succeeded);

	libusb_close(device_handle);
	libusb_exit(NULL);

	exit(0);
}

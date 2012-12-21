/** \file usb_callbacks.h
  *
  * \brief Describes callback functions which must be implemented.
  *
  * All references to the "USB specification" refer to revision 2.0, obtained
  * from http://www.usb.org/developers/docs/usb_20_110512.zip (see usb_20.pdf)
  * on 26 March 2012.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef USB_CALLBACKS_H
#define	USB_CALLBACKS_H

#include <stdint.h>

/** This will be called whenever an unrecoverable error occurs. This should
  * not return. */
extern void usbFatalError(void);
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
extern unsigned int usbClassHandleControlSetup(uint8_t bmRequestType, uint8_t bRequest, uint16_t wValue, uint16_t wIndex, uint16_t wLength);
/** This callback will be called if the control endpoint (endpoint 0)
  * receives data during the Data stage of a class-specific request. This
  * callback gives class drivers the opportunity to handle data sent to the
  * control endpoint.
  * \param packet_buffer The contents of the data packet are placed here.
  * \param length The length (in bytes) of the received data packet.
  * \return Zero if the data was accepted, non-zero if the data was not
  *         handled (i.e. the class driver did not expect any data).
  */
extern unsigned int usbClassHandleControlData(uint8_t *packet_buffer, uint32_t length);
/** This will be called whenever a control transfer needs to be aborted (for
  * any reason, including reset). This allows class drivers to reset their
  * control transfer-specific state. */
extern void usbClassAbortControlTransfer(void);
/** Callback which will be called whenever a successful "Set Configuration"
  * request (see section 9.4.7 of the USB specification) is encountered. This
  * gives the class driver an opportunity to configure or unconfigure
  * endpoints, buffers, state etc.
  * \param new_configuration_value 0 means unconfigure device, 1 means
  *                                configure device.
  */
extern void usbClassSetConfiguration(uint8_t new_configuration_value);
/** This will be called whenever a USB reset is seen. This callback gives
  * class drivers the opportunity to reset their state. */
extern void usbClassResetSeen(void);

#endif	// #ifndef USB_CALLBACKS_H

/** \file usb_standard_requests.h
  *
  * \brief Describes functions and constants exported by usb_standard_requests.c
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef USB_STANDARD_REQUESTS
#define	USB_STANDARD_REQUESTS

/** The endpoint number which receives standard requests. */
#define CONTROL_ENDPOINT_NUMBER		0

extern void usbSetupControlEndpoint(void);
extern void usbResetSeen(void);
extern void usbControlProtocolStall(void);
extern void usbControlNextStage(void);
extern void usbSuppressControlReceive(void);

#endif	// #ifndef USB_STANDARD_REQUESTS

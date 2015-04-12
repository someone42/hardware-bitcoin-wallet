/** \file xex.h
  *
  * \brief Describes functions and constants exported by xex.c.
  *
  * To use these functions, set the encryption key using setEncryptionKey(),
  * then use encryptedNonVolatileWrite() and encryptedNonVolatileRead()
  * just like their non-encrypted bretheren (nonVolatileWrite() and
  * nonVolatileRead()).
  * The key passed to setEncryptionKey() should be secret.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef XEX_H_INCLUDED
#define XEX_H_INCLUDED

#include "common.h"
#include "hwinterface.h"

/** Length, in bytes, of the encryption key that setEncryptionKey() and
  * getEncryptionKey() deal with. */
#define WALLET_ENCRYPTION_KEY_LENGTH		32

extern void xexEncrypt(uint8_t *out, uint8_t *in, uint8_t *n, uint8_t seq);
extern void xexDecrypt(uint8_t *out, uint8_t *in, uint8_t *n, uint8_t seq);
extern void setEncryptionKey(const uint8_t *in);
extern void getEncryptionKey(uint8_t *out);
extern bool isEncryptionKeyNonZero(void);
extern void clearEncryptionKey(void);
extern NonVolatileReturn encryptedNonVolatileWrite(uint8_t *data, NVPartitions partition, uint32_t address, uint32_t length);
extern NonVolatileReturn encryptedNonVolatileRead(uint8_t *data, NVPartitions partition, uint32_t address, uint32_t length);

#endif // #ifndef XEX_H_INCLUDED

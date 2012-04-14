// ***********************************************************************
// xex.h
// ***********************************************************************
//
// This describes functions exported by xex.c
// To use these functions, set the encryption key using setEncryptionKey(),
// then use encryptedNonVolatileWrite() and encryptedNonVolatileRead()
// just like their non-encrypted bretheren.
// The key passed to setEncryptionKey() should be secret.
//
// This file is licensed as described by the file LICENCE.

#ifndef XEX_H_INCLUDED
#define XEX_H_INCLUDED

#include "common.h"
#include "hwinterface.h"

extern void setEncryptionKey(uint8_t *in);
extern void getEncryptionKey(uint8_t *out);
extern uint8_t isEncryptionKeyNonZero(void);
extern void clearEncryptionKey(void);
extern NonVolatileReturn encryptedNonVolatileWrite(uint8_t *data, uint32_t address, uint8_t length);
extern NonVolatileReturn encryptedNonVolatileRead(uint8_t *data, uint32_t address, uint8_t length);

#endif // #ifndef XEX_H_INCLUDED

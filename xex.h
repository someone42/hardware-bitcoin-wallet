// ***********************************************************************
// xex.h
// ***********************************************************************
//
// This describes functions exported by xex.c
// To use these functions, set the encryption keys using setTweakKey() and
// setEncryptionKey(), then use encryptedNonVolatileWrite() and
// encryptedNonVolatileRead() just like their non-encrypted bretheren.
// The keys passed to setTweakKey() and setEncryptionKey() should be
// secret and independent.
//
// This file is licensed as described by the file LICENCE.

#ifndef XEX_H_INCLUDED
#define XEX_H_INCLUDED

#include "common.h"
#include "hwinterface.h"

extern void setTweakKey(uint8_t *in);
extern void setEncryptionKey(uint8_t *in);
extern void getEncryptionKeys(uint8_t *out);
extern uint8_t areEncryptionKeysNonZero(void);
extern void clearEncryptionKeys(void);
extern NonVolatileReturn encryptedNonVolatileWrite(uint8_t *data, uint32_t address, uint8_t length);
extern NonVolatileReturn encryptedNonVolatileRead(uint8_t *data, uint32_t address, uint8_t length);

#endif // #ifndef XEX_H_INCLUDED

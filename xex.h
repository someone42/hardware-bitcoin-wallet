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

extern void setTweakKey(u8 *in);
extern void setEncryptionKey(u8 *in);
extern void getEncryptionKeys(u8 *out);
extern u8 areEncryptionKeysNonZero(void);
extern void clearEncryptionKeys(void);
extern NonVolatileReturn encryptedNonVolatileWrite(u8 *data, u32 address, u8 length);
extern NonVolatileReturn encryptedNonVolatileRead(u8 *data, u32 address, u8 length);

#endif // #ifndef XEX_H_INCLUDED

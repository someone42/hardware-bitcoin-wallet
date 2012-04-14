// ***********************************************************************
// aes.h
// ***********************************************************************
//
// This describes functions exported by aes.c
// To use these functions, take a 16-byte key and use aesExpandKey() to
// expand it into a 176-byte key. Then use the expanded key in aesEncrypt()
// or aesDecrypt(), which turn a 16-byte plaintext into a 16-byte
// ciphertext (or vice versa).
//
// This file is licensed as described by the file LICENCE.

#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include "common.h"

// Size of expanded key, in bytes
#define EXPANDED_KEY_SIZE	176

extern void aesExpandKey(uint8_t *expanded_key, uint8_t *key);
extern void aesEncrypt(uint8_t *out, uint8_t *in, uint8_t *expanded_key);
extern void aesDecrypt(uint8_t *out, uint8_t *in, uint8_t *expanded_key);

#endif // #ifndef AES_H_INCLUDED

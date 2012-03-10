// ***********************************************************************
// aes.h
// ***********************************************************************
//
// This describes functions exported by aes.c
// To use these functions, take a 16-byte key and use aes_expand_key() to
// expand it into a 176-byte key. Then use the expanded key in aes_encrypt()
// or aes_decrypt(), which turn a 16-byte plaintext into a 16-byte
// ciphertext (or vice versa).
//
// This file is licensed as described by the file LICENCE.

#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include "common.h"

// Size of expanded key, in bytes
#define EXPKEY_SIZE	176

extern void aes_expand_key(u8 *expkey, u8 *key);
extern void aes_encrypt(u8 *out, u8 *in, u8 *expkey);
extern void aes_decrypt(u8 *out, u8 *in, u8 *expkey);

#endif // #ifndef AES_H_INCLUDED

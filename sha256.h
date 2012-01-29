// ***********************************************************************
// sha256.h
// ***********************************************************************
//
// This describes functions exported by sha256.c
// To calculate a SHA-256 hash, call sha256_begin(), then call
// sha256_writebyte () for each byte of the message, then call
// sha256_finish(). The hash will be in H[0], H[1], ..., H[7] of the hash
// state.
//
// This file is licensed as described by the file LICENCE.

#ifndef SHA256_H_INCLUDED
#define SHA256_H_INCLUDED

#include "common.h"
#include "hash.h"

extern void sha256_begin(hash_state *hs);
extern void sha256_writebyte(hash_state *hs, u8 byte);
extern void sha256_finish(hash_state *hs);
extern void sha256_finishdouble(hash_state *hs);

#endif // #ifndef SHA256_H_INCLUDED

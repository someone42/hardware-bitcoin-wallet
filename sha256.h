// ***********************************************************************
// sha256.h
// ***********************************************************************
//
// This describes functions exported by sha256.c
// To calculate a SHA-256 hash, call sha256_begin(), then call
// sha256_writebyte () for each byte of the message, then call
// sha256_finish(). The hash will be in h[0], h[1], ..., h[7] of the hash
// state.
//
// This file is licensed as described by the file LICENCE.

#ifndef SHA256_H_INCLUDED
#define SHA256_H_INCLUDED

#include "common.h"
#include "hash.h"

extern void sha256Begin(HashState *hs);
extern void sha256WriteByte(HashState *hs, uint8_t byte);
extern void sha256Finish(HashState *hs);
extern void sha256FinishDouble(HashState *hs);

#endif // #ifndef SHA256_H_INCLUDED

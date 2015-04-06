/** \file sha256.h
  *
  * \brief Describes functions and constants exported by sha256.c.
  *
  * To calculate a SHA-256 hash, call sha256Begin(), then call
  * sha256WriteByte() for each byte of the message, then call
  * sha256Finish() (or sha256FinishDouble(), if you want a double SHA-256
  * hash). The hash will be in HashState#h, but it can also be
  * extracted and placed into to a byte array using writeHashToByteArray().
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef SHA256_H_INCLUDED
#define SHA256_H_INCLUDED

#include "common.h"
#include "hash.h"

/** Length, in bytes, of the output of the SHA-256 hash function. */
#define SHA256_HASH_LENGTH 32

extern void sha256Begin(HashState *hs);
extern void sha256WriteByte(HashState *hs, uint8_t byte);
extern void sha256Finish(HashState *hs);
extern void sha256FinishDouble(HashState *hs);

#endif // #ifndef SHA256_H_INCLUDED

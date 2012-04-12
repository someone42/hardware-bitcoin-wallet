// ***********************************************************************
// hash.h
// ***********************************************************************
//
// This describes functions and types common to both SHA-256 hash calculation
// and RIPEMD-160 hash calculation.
//
// This file is licensed as described by the file LICENCE.

#ifndef HASH_H_INCLUDED
#define HASH_H_INCLUDED

#include "common.h"

// Container for common hash state.
typedef struct HashStateStruct
{
	// Where final hash will be placed. Depending on the size of the hash
	// function's output, not all entries will be filled.
	u32 h[8];
	// Current index into m, ranges from 0 to 15.
	u8 index_m;
	// Current byte within (32-bit) word. For big-endian hash functions,
	// 0 = MSB, 3 = LSB. For little-endian hash functions, 0 = LSB, 3 = MSB.
	u8 byte_position_m;
	// If this is non-zero, each (32-bit) word in the message buffer will be
	// loaded in a big-endian manner. If this is zero, the words will be
	// loaded in a little-endian manner.
	u8 is_big_endian;
	// 512-bit message buffer.
	u32 m[16];
	// Total length of message; updated as bytes are written.
	u32 message_length;
	// Callback to update hash when message buffer is full.
	void (*hashBlock)(struct HashStateStruct *hs2);
} HashState;

extern void clearM(HashState *hs);
extern void hashWriteByte(HashState *hs, u8 byte);
extern void hashFinish(HashState *hs);
extern void writeHashToByteArray(u8 *out, HashState *hs, u8 big_endian);

#endif // #ifndef HASH_H_INCLUDED

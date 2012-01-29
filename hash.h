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
typedef struct hash_state_type
{
	// Where final hash will be placed. Depending on the size of the hash
	// function's output, not all entries will be filled.
	u32 H[8];
	// Current index into M, ranges from 0 to 15.
	u8 indexM;
	// Current byte within (32-bit) word. For big-endian hash functions,
	// 0 = MSB, 3 = LSB. For little-endian hash functions, 0 = LSB, 3 = MSB.
	u8 bytepositionM;
	// If this is non-zero, each (32-bit) word in the message buffer will be
	// loaded in a big-endian manner. If this is zero, the words will be
	// loaded in a little-endian manner.
	u8 isbigendian;
	// 512-bit message buffer.
	u32 M[16];
	// Total length of message; updated as bytes are written.
	u32 messagelength;
	// Callback to update hash when message buffer is full.
	void (*hash_block)(struct hash_state_type *hs2);
} hash_state;

extern void clearM(hash_state *hs);
extern void hash_writebyte(hash_state *hs, u8 byte);
extern void write_u32_littleendian(u8 *out, u32 in);
extern void hash_finish(hash_state *hs);
extern void convertHtobytearray(hash_state *hs, u8 *out, u8 bigendian);

#endif // #ifndef HASH_H_INCLUDED

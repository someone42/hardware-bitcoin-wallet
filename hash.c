// ***********************************************************************
// hash.c
// ***********************************************************************
//
// Containes functions common to both SHA-256 and RIPEMD-160 hash calculation.
//
// This file is licensed as described by the file LICENCE.

#include "common.h"
#include "hash.h"
#include "endian.h"

// Clears m and resets byte_position_m/index_m.
void clearM(HashState *hs)
{
	u8 i;

	hs->index_m = 0;
	hs->byte_position_m = 0;
	for (i = 0; i < 16; i++)
	{
		hs->m[i] = 0;
	}
}

// Send one more byte to be hashed.
// Writes to m and updates byte_position_m/index_m.
// The function hashBlock() will be called if a block is full.
void hashWriteByte(HashState *hs, u8 byte)
{
	u8 pos; // corrected for endianness

	hs->message_length++;
	if (hs->is_big_endian)
	{
		pos = hs->byte_position_m;
	}
	else
	{
		pos = (u8)(3 - hs->byte_position_m);
	}
	switch (pos)
	{
	case 0:
		hs->m[hs->index_m] |= ((u32)byte << 24);
		break;
	case 1:
		hs->m[hs->index_m] |= ((u32)byte << 16);
		break;
	case 2:
		hs->m[hs->index_m] |= ((u32)byte << 8);
		break;
	case 3:
	default:
		hs->m[hs->index_m] |= ((u32)byte);
		break;
	}
	if (hs->byte_position_m == 3)
	{
		hs->index_m++;
	}
	hs->byte_position_m = (u8)((hs->byte_position_m + 1) & 3);
	if (hs->index_m == 16)
	{
		hs->hashBlock(hs);
		clearM(hs);
	}
}

// Finish off hashing message (write padding and length) and calculate
// final hash.
void hashFinish(HashState *hs)
{
	u32 length_bits;
	u8 i;
	u8 buffer[8];

	// Subsequent calls to hashWriteByte() will keep incrementing
	// message_length, so the calculation of length (in bits) must be
	// done before padding.
	length_bits = hs->message_length << 3;

	hashWriteByte(hs, (u8)0x80);
	while ((hs->index_m != 14) || (hs->byte_position_m != 0))
	{
		hashWriteByte(hs, 0);
	}
	for (i = 0; i < 8; i++)
	{
		buffer[i] = 0;
	}
	if (hs->is_big_endian)
	{
		writeU32BigEndian(&(buffer[4]), length_bits);
	}
	else
	{
		writeU32LittleEndian(&(buffer[0]), length_bits);
	}
	for (i = 0; i < 8; i++)
	{
		hashWriteByte(hs, buffer[i]);
	}
	if (!hs->is_big_endian)
	{
		for	(i = 0; i < 8; i++)
		{
			swapEndian(&(hs->h[i]));
		}
	}
}

// Convert h array (where hashes are normally stored) into a byte array,
// respecting endianness. out should have a size of 32 (even if the
// hash function's result is smaller than 256-bits).
// If big_endian is non-zero, then the hash will be written in a
// big-endian way (useful for computing the first hash of a double
// SHA-256 hash). If big_endian is zero, then the hash will be written in
// little-endian way (useful for sending off to a signing function).
void writeHashToByteArray(u8 *out, HashState *hs, u8 big_endian)
{
	u8 i;

	if (big_endian)
	{
		for (i = 0; i < 8; i++)
		{
			writeU32BigEndian(&(out[i * 4]), hs->h[i]);
		}
	}
	else
	{
		for (i = 0; i < 8; i++)
		{
			writeU32LittleEndian(&(out[i * 4]), hs->h[7 - i]);
		}
	}
}


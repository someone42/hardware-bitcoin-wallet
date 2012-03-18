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

// Clears M and resets bytepositionM/indexM
void clearM(hash_state *hs)
{
	u8 i;

	hs->indexM = 0;
	hs->bytepositionM = 0;
	for (i = 0; i < 16; i++)
	{
		hs->M[i] = 0;
	}
}

// Send one more byte to be hashed.
// Writes to M and updates bytepositionM/indexM.
// The function hash_block() will be called if a block is full.
void hash_writebyte(hash_state *hs, u8 byte)
{
	u8 pos; // corrected for endianness

	hs->messagelength++;
	if (hs->isbigendian)
	{
		pos = hs->bytepositionM;
	}
	else
	{
		pos = (u8)(3 - hs->bytepositionM);
	}
	switch (pos)
	{
	case 0:
		hs->M[hs->indexM] |= ((u32)byte << 24);
		break;
	case 1:
		hs->M[hs->indexM] |= ((u32)byte << 16);
		break;
	case 2:
		hs->M[hs->indexM] |= ((u32)byte << 8);
		break;
	case 3:
	default:
		hs->M[hs->indexM] |= ((u32)byte);
		break;
	}
	if (hs->bytepositionM == 3)
	{
		hs->indexM++;
	}
	hs->bytepositionM = (u8)((hs->bytepositionM + 1) & 3);
	if (hs->indexM == 16)
	{
		hs->hash_block(hs);
		clearM(hs);
	}
}

// Finish off hashing message (write padding and length) and calculate
// final hash.
void hash_finish(hash_state *hs)
{
	u32 lengthbits;
	u8 i;
	u8 buffer[8];

	// Subsequent calls to sha256_writebyte() will keep incrementing
	// messagelength, so the calculation of length (in bits) must be
	// done before padding.
	lengthbits = hs->messagelength << 3;

	hash_writebyte(hs, (u8)0x80);
	while ((hs->indexM != 14) || (hs->bytepositionM!= 0))
	{
		hash_writebyte(hs, 0);
	}
	for (i = 0; i < 8; i++)
	{
		buffer[i] = 0;
	}
	if (hs->isbigendian)
	{
		write_u32_bigendian(&(buffer[4]), lengthbits);
	}
	else
	{
		write_u32_littleendian(&(buffer[0]), lengthbits);
	}
	for (i = 0; i < 8; i++)
	{
		hash_writebyte(hs, buffer[i]);
	}
	if (!hs->isbigendian)
	{
		for	(i = 0; i < 8; i++)
		{
			swap_endian(&(hs->H[i]));
		}
	}
}

// Convert H array (where hashes are normally stored) into a byte array,
// respecting endianness. out should have a size of 32 (even if the
// hash function's result is smaller than 256-bits).
// If bigendian is non-zero, then the hash will be written in a
// big-endian way (useful for computing the first hash of a double
// SHA-256 hash). If bigendian is zero, then the hash will be written in
// little-endian way (useful for sending off to a signing function).
void convertHtobytearray(u8 *out, hash_state *hs, u8 bigendian)
{
	u8 i;

	if (bigendian)
	{
		for (i = 0; i < 8; i++)
		{
			write_u32_bigendian(&(out[i * 4]), hs->H[i]);
		}
	}
	else
	{
		for (i = 0; i < 8; i++)
		{
			write_u32_littleendian(&(out[i * 4]), hs->H[7 - i]);
		}
	}
}


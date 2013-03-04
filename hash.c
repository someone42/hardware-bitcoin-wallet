/** \file hash.c
  *
  * \brief Contains functions common to all hash calculations.
  *
  * All the hash calculations used in the hardware Bitcoin wallet involve
  * filling up a message buffer and then performing calculations on the full
  * message buffer. The functions in this file mainly deal with the
  * mangement of that message buffer.
  *
  * This file is licensed as described by the file LICENCE.
  */

#include "common.h"
#include "hash.h"
#include "endian.h"

/** Clear the message buffer.
  * \param hs The hash state to act on.
  */
void clearM(HashState *hs)
{
	hs->index_m = 0;
	hs->byte_position_m = 0;
	memset(hs->m, 0, sizeof(hs->m));
}

/** Add one more byte to the message buffer and call HashState#hashBlock()
  * if the message buffer is full.
  * \param hs The hash state to act on.
  * \param byte The byte to add.
  */
void hashWriteByte(HashState *hs, uint8_t byte)
{
	uint8_t pos; // corrected for endianness

	hs->message_length++;
	if (hs->is_big_endian)
	{
		pos = hs->byte_position_m;
	}
	else
	{
		pos = (uint8_t)(3 - hs->byte_position_m);
	}
	switch (pos)
	{
	case 0:
		hs->m[hs->index_m] |= ((uint32_t)byte << 24);
		break;
	case 1:
		hs->m[hs->index_m] |= ((uint32_t)byte << 16);
		break;
	case 2:
		hs->m[hs->index_m] |= ((uint32_t)byte << 8);
		break;
	case 3:
	default:
		hs->m[hs->index_m] |= ((uint32_t)byte);
		break;
	}
	if (hs->byte_position_m == 3)
	{
		hs->index_m++;
	}
	hs->byte_position_m = (uint8_t)((hs->byte_position_m + 1) & 3);
	if (hs->index_m == 16)
	{
		hs->hashBlock(hs);
		clearM(hs);
	}
}

/** Finalise the hashing of a message by writing appropriate padding and
  * length bytes.
  * \param hs The hash state to act on.
  */
void hashFinish(HashState *hs)
{
	uint32_t length_bits;
	uint8_t i;
	uint8_t buffer[8];

	// Subsequent calls to hashWriteByte() will keep incrementing
	// message_length, so the calculation of length (in bits) must be
	// done before padding.
	length_bits = hs->message_length << 3;

	// Pad using a 1 bit followed by enough 0 bits to get the message buffer
	// to exactly 448 bits full.
	hashWriteByte(hs, (uint8_t)0x80);
	while ((hs->index_m != 14) || (hs->byte_position_m != 0))
	{
		hashWriteByte(hs, 0);
	}
	// Write 64 bit length (in bits).
	memset(buffer, 0, 8);
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
	// Swap endianness if necessary.
	if (!hs->is_big_endian)
	{
		for	(i = 0; i < 8; i++)
		{
			swapEndian(&(hs->h[i]));
		}
	}
}

/** Write the hash value into a byte array, respecting endianness.
  * \param out The byte array which will receive the hash. This byte array
  *            must have space for at least 32 bytes, even if the hash
  *            function's result is smaller than 256 bits.
  * \param hs The hash state to read the hash value from.
  * \param do_write_big_endian Whether the hash should be written in a
  *                            big-endian way (useful for computing the first
  *                            hash of a double SHA-256 hash) instead of a
  *                            little-endian way (useful for sending off to a
  *                            signing function).
  * \warning hashFinish() (or the appropriate hash-specific finish function)
  *          must be called before this function.
  */
void writeHashToByteArray(uint8_t *out, HashState *hs, bool do_write_big_endian)
{
	uint8_t i;

	if (do_write_big_endian)
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


// ***********************************************************************
// endian.c
// ***********************************************************************
//
// Containes functions which perform big and little-endian type conversions.
//
// This file is licensed as described by the file LICENCE.

#include "common.h"
#include "endian.h"

// Write the 32-bit unsigned integer specified by in into the byte array
// specified by out. This will write the bytes in a big-endian format.
void writeU32BigEndian(uint8_t *out, uint32_t in)
{
	out[0] = (uint8_t)(in >> 24);
	out[1] = (uint8_t)(in >> 16);
	out[2] = (uint8_t)(in >> 8);
	out[3] = (uint8_t)in;
}

// Write the 32-bit unsigned integer specified by in into the byte array
// specified by out. This will write the bytes in a little-endian format.
void writeU32LittleEndian(uint8_t *out, uint32_t in)
{
	out[0] = (uint8_t)in;
	out[1] = (uint8_t)(in >> 8);
	out[2] = (uint8_t)(in >> 16);
	out[3] = (uint8_t)(in >> 24);
}

// Read a 32-bit unsigned integer from the byte array specified by in.
// The bytes will be read in a little-endian format.
uint32_t readU32LittleEndian(uint8_t *in)
{
	return ((uint32_t)in[0])
		| ((uint32_t)in[1] << 8)
		| ((uint32_t)in[2] << 16)
		| ((uint32_t)in[3] << 24);
}

// No-one needs readU32BigEndian(), so it is not implemented.

// Swap endianness of a 32-bit unsigned integer.
void swapEndian(uint32_t *v)
{
	uint8_t t;
	uint8_t *r;

	r = (uint8_t *)v;
	t = r[0];
	r[0] = r[3];
	r[3] = t;
	t = r[1];
	r[1] = r[2];
	r[2] = t;
}


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
void writeU32BigEndian(u8 *out, u32 in)
{
	out[0] = (u8)(in >> 24);
	out[1] = (u8)(in >> 16);
	out[2] = (u8)(in >> 8);
	out[3] = (u8)in;
}

// Write the 32-bit unsigned integer specified by in into the byte array
// specified by out. This will write the bytes in a little-endian format.
void writeU32LittleEndian(u8 *out, u32 in)
{
	out[0] = (u8)in;
	out[1] = (u8)(in >> 8);
	out[2] = (u8)(in >> 16);
	out[3] = (u8)(in >> 24);
}

// Read a 32-bit unsigned integer from the byte array specified by in.
// The bytes will be read in a little-endian format.
u32 readU32LittleEndian(u8 *in)
{
	return ((u32)in[0])
		| ((u32)in[1] << 8)
		| ((u32)in[2] << 16)
		| ((u32)in[3] << 24);
}

// No-one needs readU32BigEndian(), so it is not implemented.

// Swap endianness of a 32-bit unsigned integer.
void swapEndian(u32 *v)
{
	u8 t;
	u8 *r;

	r = (u8 *)v;
	t = r[0];
	r[0] = r[3];
	r[3] = t;
	t = r[1];
	r[1] = r[2];
	r[2] = t;
}


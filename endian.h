// ***********************************************************************
// endian.h
// ***********************************************************************
//
// This describes functions exported by endian.c
//
// This file is licensed as described by the file LICENCE.

#ifndef ENDIAN_H_INCLUDED
#define ENDIAN_H_INCLUDED

#include "common.h"

extern void write_u32_bigendian(u8 *out, u32 in);
extern void write_u32_littleendian(u8 *out, u32 in);
extern u32 read_u32_littleendian(u8 *in);
extern void swap_endian(u32 *v);

#endif // #ifndef ENDIAN_H_INCLUDED

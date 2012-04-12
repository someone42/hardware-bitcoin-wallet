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

extern void writeU32BigEndian(u8 *out, u32 in);
extern void writeU32LittleEndian(u8 *out, u32 in);
extern u32 readU32LittleEndian(u8 *in);
extern void swapEndian(u32 *v);

#endif // #ifndef ENDIAN_H_INCLUDED

// ***********************************************************************
// common.h
// ***********************************************************************
//
// This defines things which are common to most of the source distribution.
// If porting to another platform, please check that the typedefs below
// refer to appropriate types.
//
// This file is licensed as described by the file LICENCE.

#ifndef COMMON_H_INCLUDED
#define COMMON_H_INCLUDED

// These typedefs are platform-dependent. Change them if they don't match
// the comments.
// Unsigned 8-bit integer
typedef unsigned char u8;
// Unsigned 16-bit integer
typedef unsigned short u16;
// Unsigned 32-bit integer
typedef unsigned long u32;

#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif // #if defined(__GNUC__)

#endif // #ifndef COMMON_H_INCLUDED

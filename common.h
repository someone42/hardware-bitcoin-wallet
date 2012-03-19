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

// In certain situations, inlining can cause an overall increase in stack
// space. For example, let foo() use 100 bytes of stack space, bar() 104 bytes
// and sno() 50 bytes. If sno() calls foo() and then (after foo() returns)
// calls bar(), the maximum stack space used is 154 bytes. But if an
// enthusiastic compiler decides to inline foo() and bar() into sno(), the
// maximum stack space used is now 254 bytes, because all the functions'
// frames are combined.
// NOINLINE is supposed to tell compilers to not inline the associated
// function. Careful use of NOINLINE can decrease the amount of maximum stack
// space used.
#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#else
#define NOINLINE
#endif // #if defined(__GNUC__)

// On certain platforms, unchanging, read-only data (eg. lookup tables) needs
// to be marked and accessed in a way that is different to read/write data.
// Marking this data with PROGMEM saves valuable RAM space. However, any data
// marked with PROGMEM needs to be accessed using the LOOKUP_BYTE/LOOKUP_DWORD
// macros. The argument for each macro must be the address of the byte or
// dword (4 bytes) to be accessed.
#if defined(AVR) && defined(__GNUC__)
#include <avr/io.h>
#include <avr/pgmspace.h>
#define LOOKUP_DWORD(x)		(pgm_read_dword_near(x))
#define LOOKUP_BYTE(x)		(pgm_read_byte_near(x))
#else
#define PROGMEM
#define LOOKUP_DWORD(x)		(*(x))
#define LOOKUP_BYTE(x)		(*(x))
#endif // #if defined(AVR) && defined(__GNUC__)

#endif // #ifndef COMMON_H_INCLUDED

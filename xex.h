// ***********************************************************************
// xex.h
// ***********************************************************************
//
// This describes functions exported by xex.c
// To use these functions, set the encryption keys using set_tweak_key() and
// set_encryption_key(), then use encrypted_nonvolatile_write() and
// encrypted_nonvolatile_read() just like their non-encrypted bretheren.
// The keys passed to set_tweak_key() and set_encryption_key() should be
// secret and independent.
//
// This file is licensed as described by the file LICENCE.

#ifndef XEX_H_INCLUDED
#define XEX_H_INCLUDED

#include "common.h"
#include "hwinterface.h"

extern void set_tweak_key(u8 *in);
extern void set_encryption_key(u8 *in);
extern void clear_keys(void);
extern nonvolatile_return encrypted_nonvolatile_write(u32 address, u8 *data, u8 length);
extern nonvolatile_return encrypted_nonvolatile_read(u32 address, u8 *data, u8 length);

#endif // #ifndef XEX_H_INCLUDED

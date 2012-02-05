// ***********************************************************************
// prandom.h
// ***********************************************************************
//
// This describes functions exported by prandom.c
//
// This file is licensed as described by the file LICENCE.

#ifndef PRANDOM_H_INCLUDED
#define PRANDOM_H_INCLUDED

#include "common.h"
#include "bignum256.h"

extern void xor16bytes(u8 *r, u8 *op1);
extern void get_random_256(bignum256 n);
extern void generate_deterministic_256(bignum256 out, u8 *seed, u32 num);

#endif // #ifndef PRANDOM_H_INCLUDED

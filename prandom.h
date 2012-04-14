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

extern void xor16Bytes(uint8_t *r, uint8_t *op1);
extern void getRandom256(BigNum256 n);
extern void generateDeterministic256(BigNum256 out, uint8_t *seed, uint32_t num);

#endif // #ifndef PRANDOM_H_INCLUDED

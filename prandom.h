/** \file prandom.h
  *
  * \brief Describes functions exported by prandom.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef PRANDOM_H_INCLUDED
#define PRANDOM_H_INCLUDED

#include "common.h"
#include "bignum256.h"

/** Length, in bytes, of the seed that generateDeterministic256() requires.
  * \warning This must be a multiple of 16 in order for backupWallet() to work
  *          properly.
  */
#define SEED_LENGTH			64

extern void getRandom256(BigNum256 n);
extern void generateDeterministic256(BigNum256 out, uint8_t *seed, uint32_t num);

#endif // #ifndef PRANDOM_H_INCLUDED

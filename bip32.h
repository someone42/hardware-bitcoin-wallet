/** \file bip32.h
  *
  * \brief Describes function and constants exported and used by bip32.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef BIP32_H_INCLUDED
#define BIP32_H_INCLUDED

#include "common.h"
#include "bignum256.h"

/** Length (in number of bytes) of a BIP32 node, a.k.a. extended private
  * key. */
#define NODE_LENGTH		64

extern void bip32SeedToNode(uint8_t *master_node, const uint8_t *seed, const unsigned int seed_length);
extern bool bip32DerivePrivate(BigNum256 out, const uint8_t *master_node, const uint32_t *path, const unsigned int path_length);

#endif // #ifndef BIP32_H_INCLUDED

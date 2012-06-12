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
#include "storage_common.h"

/** Length, in bytes, of the seed that generateDeterministic256() requires.
  * \warning This must be a multiple of 16 in order for backupWallet() to work
  *          properly.
  */
#define SEED_LENGTH				64
/** Length, in bytes, of the persistent entropy pool. This should be at least
  * 32 to ensure that even in the event of complete undetected failure of the
  * HWRNG, the outputs of getRandom256() still have nearly 256 bits of
  * entropy.
  */
#define ENTROPY_POOL_LENGTH		32
/** Length, in bytes, of the persistent entropy pool checksum. This can be
  * less than 32 because the checksum is only used to detect modification to
  * the persistent entropy pool.
  */
#define POOL_CHECKSUM_LENGTH	16

// Some sanity checks.
#if ENTROPY_POOL_LENGTH > (ADDRESS_POOL_CHECKSUM - ADDRESS_ENTROPY_POOL)
#error ENTROPY_POOL_LENGTH is too big
#endif
#if POOL_CHECKSUM_LENGTH > (ADDRESS_WALLET_STAGING - ADDRESS_POOL_CHECKSUM)
#error POOL_CHECKSUM_LENGTH is too big
#endif

extern uint8_t setEntropyPool(uint8_t *in_pool_state);
extern uint8_t getEntropyPool(uint8_t *out_pool_state);
extern uint8_t initialiseEntropyPool(uint8_t *initial_pool_state);
extern uint8_t getRandom256(BigNum256 n);
extern uint8_t getRandom256TemporaryPool(BigNum256 n, uint8_t *pool_state);
extern void generateDeterministic256(BigNum256 out, uint8_t *seed, uint32_t num);
#ifdef TEST
extern void initialiseDefaultEntropyPool(void);
extern void corruptEntropyPool(void);
#endif // #ifdef TEST

#endif // #ifndef PRANDOM_H_INCLUDED

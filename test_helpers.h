/** \file test_helpers.h
  *
  * \brief Describes functions exported by test_helpers.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef TEST_HELPERS_H_INCLUDED
#define TEST_HELPERS_H_INCLUDED

#ifdef TEST

#include <stdio.h>
#include "common.h"
#include "bignum256.h"

extern void skipWhiteSpace(FILE *f);
extern void skipLine(FILE *f);
extern void bigPrintVariableSize(uint8_t *number, uint8_t size, uint8_t big_endian);
extern void printBigEndian16(uint8_t *buffer);
extern void printLittleEndian32(BigNum256 buffer);
extern void reportSuccess(void);
extern void reportFailure(void);
extern void initTests(const char *source_file_name);
extern void finishTests(void);

#endif // #ifdef TEST

#endif // #ifndef TEST_HELPERS_H_INCLUDED

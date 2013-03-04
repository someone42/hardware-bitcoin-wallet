/** \file atsha204.h
  *
  * \brief Describes functions exported by atsha204.c
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef ATSHA204_H_INCLUDED
#define	ATSHA204_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>

extern void initATSHA204(void);
extern bool atsha204Wake(void);
extern void atsha204Sleep(void);
extern bool atsha204Random(uint8_t *random_bytes);

#endif	// #ifndef ATSHA204_H_INCLUDED


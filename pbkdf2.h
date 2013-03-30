/** \file pbkdf2.h
  *
  * \brief Describes functions exported by pbkdf2.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef PBKDF2_H_INCLUDED
#define PBKDF2_H_INCLUDED

#include "common.h"

extern void pbkdf2(uint8_t *out, const uint8_t *password, const unsigned int password_length, const uint8_t *salt, const unsigned int salt_length);

#endif // #ifndef PBKDF2_H_INCLUDED

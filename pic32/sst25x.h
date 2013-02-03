/** \file sst25x.h
  *
  * \brief Describes functions and constants exported by sst25x.c.
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef PIC32_SST25X_H
#define	PIC32_SST25X_H

#include <stdint.h>

/** Number of bytes in a sector. A sector is the smallest amount of data
  * which can be erased in one operation.
  * \warning This must be a power of 2, or some bit masks in sst25x.c will
  *          be invalid.
  */
#define SECTOR_SIZE			4096

extern void initSST25x(void);
extern uint8_t sst25xReadStatusRegister(void);
extern void sst25xWriteStatusRegister(uint8_t sst25x_status_register);
extern void sst25xRead(uint8_t *data, uint32_t address, uint32_t length);
extern void sst25xEraseSector(uint32_t address);
extern void sst25xProgramSector(uint8_t *data, uint32_t address);

#endif	// #ifndef PIC32_SST25X_H

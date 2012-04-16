/** \file stream_comm.h
  *
  * \brief Describes functions and types exported by stream_comm.c.
  *
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef STREAM_COMM_H_INCLUDED
#define STREAM_COMM_H_INCLUDED

#include "common.h"

extern void initStreamComm(void);
extern uint8_t processPacket(void);

#endif // #ifndef STREAM_COMM_H_INCLUDED

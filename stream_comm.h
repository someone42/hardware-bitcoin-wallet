/** \file stream_comm.h
  *
  * \brief Describes functions, types and constants exported by stream_comm.c.
  *
  *
  * This file is licensed as described by the file LICENCE.
  */

#ifndef STREAM_COMM_H_INCLUDED
#define STREAM_COMM_H_INCLUDED

#include "common.h"

/**
 * \defgroup PacketTypes Type values for packets.
 *
 * See the file PROTOCOL for more information about the format of packets
 * and what the payload of packets should be.
 *
 * @{
 */
/** Request a response from the wallet. */
#define PACKET_TYPE_PING				0x00
/** Reply to #PACKET_TYPE_PING. */
#define PACKET_TYPE_PING_REPLY			0x01
/** Packet signifying successful completion of an operation. */
#define PACKET_TYPE_SUCCESS				0x02
/** Packet signifying failure of an operation. */
#define PACKET_TYPE_FAILURE				0x03
/** Create a new wallet. */
#define PACKET_TYPE_NEW_WALLET			0x04
/** Create a new address in a wallet. */
#define PACKET_TYPE_NEW_ADDRESS			0x05
/** Get number of addresses in a wallet. */
#define PACKET_TYPE_GET_NUM_ADDRESSES	0x06
/** Get an address and its associated public key from a wallet. */
#define PACKET_TYPE_GET_ADDRESS_PUBKEY	0x09
/** Sign a transaction. */
#define PACKET_TYPE_SIGN_TRANSACTION	0x0A
/** Load (unlock) a wallet. */
#define PACKET_TYPE_LOAD_WALLET			0x0B
/** Unload (lock) a wallet. */
#define PACKET_TYPE_UNLOAD_WALLET		0x0C
/** Format storage area, erasing everything. */
#define PACKET_TYPE_FORMAT				0x0D
/** Change encryption key of a wallet. */
#define PACKET_TYPE_CHANGE_KEY			0x0E
/** Change name of a wallet. */
#define PACKET_TYPE_CHANGE_NAME			0x0F
/** List all wallets. */
#define PACKET_TYPE_LIST_WALLETS		0x10
/** Backup a wallet. */
#define PACKET_TYPE_BACKUP_WALLET		0x11
/** Restore wallet from a backup. */
#define PACKET_TYPE_RESTORE_WALLET		0x12
/**@}*/

extern void processPacket(void);
#ifdef TEST
extern void setTestInputStream(const uint8_t *buffer, uint32_t length);
extern void setInfiniteZeroInputStream(void);
#endif // #ifdef TEST

#endif // #ifndef STREAM_COMM_H_INCLUDED

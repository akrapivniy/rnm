/**************************************************************
* (C) Copyright 2017
* RTSoft
* Russia
* All rights reserved.
*
* Description: Library of network variables and channels
* Author: Alexander Krapivniy (akrapivny@dev.rtsoft.ru)
***************************************************************/

#ifndef __RNM_TYPES__
#define __RNM_TYPES__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <netinet/in.h>

#define RNM_DEFAULT_SYNC_OFFSET_MS 300
#define RNM_EVENT_MAXIMUM 256
#define RNM_VARIABLE_SIZE_MAXIMUM 0x3ff // using for bit mask, should be 2^n-1
#define RNM_CHANNEL_MESSAGE_SIZE RNM_VARIABLE_SIZE_MAXIMUM
#define RNM_VARIABLE_INFO_SIZE_MAXIMUM 32
#define RNM_CLIENT_MAXIMUM 64
#define RNM_CHANNEL_MAXIMUM 32
#define RNM_EVENT_NAME_SIZE 32
#define RNM_CLIENT_BUFFER_SIZE 8192

	union rnm_id {
		uint64_t i[RNM_EVENT_NAME_SIZE / sizeof(uint64_t)];
		char c[RNM_EVENT_NAME_SIZE];
	} __attribute__((packed));

	typedef union rnm_id rnmid_t;


#define RNM_PACKET_MAGIC ('R')
#define RNM_PACKET_MAGIC_DATA ('D')

#define RNM_VERSION_MAJOR 0
#define RNM_VERSION_MINOR 0

	struct rnm_header {
		uint8_t magic;
		uint32_t type;
		rnmid_t id;
		struct timespec time;
		uint64_t update_counter;
		uint16_t data_size;
		uint8_t magic_data;
	} __attribute__((packed));

	struct rnm_packet {
		struct rnm_header header;
		char buffer[1200];
	} __attribute__((packed));

	struct rnm_event_info {
		rnmid_t id;
		uint32_t type;
		uint8_t short_data[32];
		uint16_t data_size;
		time_t time;
		uint32_t count;
		uint32_t consumers_count;
		uint32_t producers_count;
	} __attribute__((packed));

	struct rnm_client_info {
		rnmid_t id;
		int event_subscribe;
		int event_write;
		int rx_event_count;
		int tx_event_count;
		in_addr_t ip;
	} __attribute__((packed));

	struct rnm_channel_info {
		rnmid_t id;
		int anons_count;
		int request_count;
		in_addr_t ip;
		uint16_t port;
	} __attribute__((packed));

	struct rnm_channel_ticket {
		in_addr_t ip;
		uint16_t port;
		uint32_t flags;
	} __attribute__((packed));

#define RNM_TYPE_EMPTY  (0x00)
#define RNM_TYPE_CLIENT_ID (0x01)
#define RNM_TYPE_EVENT (0x02)
#define RNM_TYPE_WRITE (0x03)
#define RNM_TYPE_READ (0x04)
#define RNM_TYPE_SUBSCRIBE (0x05)
#define RNM_TYPE_UNSUBSCRIBE (0x06)
#define RNM_TYPE_DEFINE (0x07)
#define RNM_TYPE_UNDEFINE (0x08)
#define RNM_TYPE_EVENT_LIST (0x09)
#define RNM_TYPE_CLIENT_LIST (0x0a)
#define RNM_TYPE_ERROR (0x0b)
#define RNM_TYPE_ACK (0x0c)
#define RNM_TYPE_CHANNEL (0x0d)
#define RNM_TYPE_CHANNEL_LIST (0x0e)
#define RNM_TYPE_MSG_MASK (0x0f)

#define RNM_TYPE_SYNC (0x0010)
#define RNM_TYPE_ECHO (0x0020)
#define RNM_TYPE_REDEFINE (0x0040)
#define RNM_TYPE_DONT_CHECK (0x0080)
#define RNM_TYPE_FLAGS_MASK (0x000000f0)

#define RNM_TYPE_VAR_NOT_DEFINED (0x0000)
#define RNM_TYPE_VAR_EMPTY     (0x0100)
#define RNM_TYPE_VAR_INT       (0x0200)
#define RNM_TYPE_VAR_LONG      (0x0300)
#define RNM_TYPE_VAR_FLOAT     (0x0400)
#define RNM_TYPE_VAR_DOUBLE    (0x0500)
#define RNM_TYPE_VAR_STRING    (0x0600)
#define RNM_TYPE_VAR_STRUCTURE (0x0700)
#define RNM_TYPE_VAR_CHAIN (0x0800)
#define RNM_TYPE_VAR_ANY (0x0900)
#define RNM_TYPE_VAR_MASK (0x0f00)

#define RNM_TYPE_CHANNEL_UDP (0x0100)
#define RNM_TYPE_CHANNEL_TCP (0x0200)
#define RNM_TYPE_CHANNEL_MASK (0x0f00)

#define RNM_STATUS_LOST       (0x1000)
#define RNM_STATUS_FLAGS_MASK (0xf000)

#define RNM_CHANNEL_ANONS   (0x10000)
#define RNM_CHANNEL_REQUEST (0x20000)
#define RNM_CHANNEL_TICKET  (0x30000)
#define RNM_CHANNEL_MASK    (0xf0000)

#ifdef __cplusplus
}
#endif



#endif //__RNM_TYPES__
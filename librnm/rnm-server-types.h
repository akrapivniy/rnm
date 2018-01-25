/**************************************************************
* (C) Copyright 2017
* RTSoft
* Russia
* All rights reserved.
*
* Description: Library of network variables and channels
* Author: Alexander Krapivniy (akrapivny@dev.rtsoft.ru)
***************************************************************/

#ifndef __RNM_SERVER_TYPES__
#define __RNM_SERVER_TYPES__

#ifdef __cplusplus
extern "C" {
#endif

#include "rnm-types.h"


struct rnm_epoll_cb {
	void *socket;
	int (*cb)(void *, uint32_t);
};

struct rnm_client {
	rnmid_t id;
	int socketfd;
	struct rnm_epoll_cb epoll_data;
	struct rnm_server *server;
	struct sockaddr_in addr;
	int addr_size;
	int event_subscribe;
	int channel_connect;
	int event_write;
	int rx_event_count;
	int tx_event_count;
	int version;
	uint8_t buffer[RNM_CLIENT_BUFFER_SIZE];
	uint32_t buffer_recv;
	uint64_t send_skipped;
};

struct rnm_event {
	rnmid_t id;
	char data[RNM_VARIABLE_SIZE_MAXIMUM];
	int data_type;
	int data_size;
	int count;
	uint64_t update_counter;
	int consumers_count;
	int producers_count;
	struct rnm_client *consumers[RNM_CLIENT_MAXIMUM];
	struct rnm_client *producer;
	void (*cb)(void *, char *, void *, int);
	void *args;
};

struct rnm_channel {
	rnmid_t id;
	struct rnm_channel_ticket ticket;
	int anons_count;
	int request_count;
	int producers_count;
	struct rnm_client *producer;
};

struct rnm_server {
	rnmid_t id;
	char addr[20];
	int port;
	int socketfd;
	int ssdp_socketfd;
	int epollfd;
	struct rnm_epoll_cb epoll_data;
	struct epoll_event socket_events[RNM_CLIENT_MAXIMUM];
	pthread_t thread;
	pthread_t ssdp_thread;
	struct rnm_event events[RNM_EVENT_MAXIMUM];
	struct rnm_client clients[RNM_CLIENT_MAXIMUM];
	struct rnm_channel channels[RNM_CHANNEL_MAXIMUM];
	int channel_count;
	int event_count;
	int client_count;
	int sync_offset;
	uint64_t update_counter;
};

#ifdef __cplusplus
}
#endif

#endif //__RNM_SERVER_TYPES__
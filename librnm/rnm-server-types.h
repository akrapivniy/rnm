/**************************************************************  
 * Description: Library of network variables and channels
 * Copyright (c) 2022 Alexander Krapivniy (a.krapivniy@gmail.com)
 * 
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
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
	int event_write;
	int rx_event_count;
	int tx_event_count;
        int tx_error;
	int version;
	uint8_t buffer[RNM_CLIENT_BUFFER_SIZE];
	uint32_t buffer_recv;
};

struct rnm_condition_client {
        struct rnm_client *client;
        int mode;
        int value;
        rnmid_t id;
};

struct rnm_event {
	rnmid_t id;
	char data[RNM_VARIABLE_SIZE_MAXIMUM];
	int data_type;
	int data_size;
	int count;
	uint64_t update_counter;
	int consumers_count;
	int rconsumers_count;
	int producers_count;
	struct rnm_client *consumers[RNM_CLIENT_MAXIMUM];
	struct rnm_client *rconsumers[RNM_CLIENT_MAXIMUM];
	struct rnm_condition_client cconsumers[RNM_CLIENT_MAXIMUM];
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
	int epollfd;
	struct rnm_epoll_cb epoll_data;
        struct rnm_epoll_cb epoll_udpdata;
	struct epoll_event socket_events[RNM_CLIENT_MAXIMUM];
	pthread_t thread;
	struct rnm_event events[RNM_EVENT_MAXIMUM];
	struct rnm_client clients[RNM_CLIENT_MAXIMUM];
	struct rnm_channel channels[RNM_CHANNEL_MAXIMUM];
	int channel_count;
	int event_count;
	int client_count;
	int sync_offset;
	uint64_t update_counter;
        
	int usocketfd;
	int uepollfd;
	struct rnm_epoll_cb uepoll_data;
        uint8_t ubuffer[RNM_CLIENT_BUFFER_SIZE];
	int uclient_count;
        
	int ssdp_socketfd;
	pthread_t ssdp_thread;
        int ssdp_beacon;
};

#ifdef __cplusplus
}
#endif

#endif //__RNM_SERVER_TYPES__
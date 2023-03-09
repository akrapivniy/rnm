/**************************************************************
 * (C) Copyright 2017
 * Motherson Innvations
 * Germany
 * All rights reserved.
 *
 * Description: Library of network variables and channels
 * Author: Alexander Krapivniy (alexander.krapivnyy@motherson-innovations.com)
 ***************************************************************/
#ifndef __RNM_CLIENT_TYPES__
#define __RNM_CLIENT_TYPES__

#ifdef __cplusplus
extern "C" {
#endif

#include "rnm-types.h"

	struct rnm_client_event {
		rnmid_t id;
		void (*cb)(void *, char *, void *, int);
		void *args;
		uint64_t update_counter;
		int flags;
	};

	struct rnm_connect_channel {
		rnmid_t id;
                struct rnm_channel_ticket ticket;
	};

	struct rnm_connect {
		rnmid_t id;
		char addr[20];
		int port;
		int socketfd;
		int usocketfd;
		pthread_t thread;
		uint8_t read_data[RNM_VARIABLE_SIZE_MAXIMUM];
		int onexit;
		int ready;
		int connect_wait;
		pthread_mutex_t connect_mutex;
		pthread_cond_t connect_cond;

		int read_size;
		rnmid_t read_id;
		int read_wait;
		pthread_mutex_t read_mutex;
		pthread_cond_t read_cond;
                struct sockaddr_in saddr;
                int saddr_size;

		struct rnm_channel_ticket ticket_data;
		rnmid_t ticket_id;
		int ticket_wait;
		pthread_mutex_t ticket_mutex;
		pthread_cond_t ticket_cond;

		struct rnm_client_event events[RNM_EVENT_MAXIMUM];
		struct rnm_connect_channel channels[RNM_CHANNEL_MAXIMUM];
		struct rnm_event_info *events_info;
		struct rnm_client_info *clients_info;
		struct rnm_channel_info *channels_info;
	
		pthread_t connect_thread;
		int connect_cb_status;
		void (*connect_cb)(void *);
		void *connect_arg;
				
		char eventlist_sequence;
		char eventlist_wait_packet;
		int eventlist_recv;
		int eventlist_wait;
		pthread_mutex_t eventlist_mutex;
		pthread_cond_t eventlist_cond;

		char clientlist_sequence;
		char clientlist_wait_packet;
		int clientlist_recv;
		int clientlist_wait;
		pthread_mutex_t clientlist_mutex;
		pthread_cond_t clientlist_cond;

		char channellist_sequence;
		char channellist_wait_packet;
		int channellist_recv;
		int channellist_wait;
		pthread_mutex_t channellist_mutex;
		pthread_cond_t channellist_cond;
	};




#ifdef __cplusplus
}
#endif



#endif //__RNM_CLIENT_TYPES__
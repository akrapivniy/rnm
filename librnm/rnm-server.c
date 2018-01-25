/**************************************************************
 * (C) Copyright 2017
 * RTSoft
 * Russia
 * All rights reserved.
 *
 * Description: Library of network variables and channels
 * Author: Alexander Krapivniy (akrapivny@dev.rtsoft.ru)
 ***************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/epoll.h>

#include "rn.h"
#include "rnm-common.h"
#include "rnm-server-types.h"

#define MODULE_NAME "rnm-server"
#include <rnm-debug.h>
#undef rtsd_debug
#define rtsd_debug(fmt,args...)

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

struct rnm_client *rnm_get_free_client(struct rnm_server *s)
{
	int i;
	for (i = 0; i < RNM_CLIENT_MAXIMUM; i++)
		if (s->clients[i].socketfd == -1)
			return(&s->clients[i]);
	rtsd_error("havn't space for new client");
	return NULL;
}

void rnm_event_init(struct rnm_event *event, rnmid_t *id)
{
	int i;
	event->args = NULL;
	event->cb = NULL;
	event->count = 0;
	event->data[0] = 0;
	event->data_size = 0;
	event->data_type = 0;
	event->producer = NULL;
	event->update_counter = 0;
	event->consumers_count = 0;
	event->producers_count = 0;

	for (i = 0; i < RNM_CLIENT_MAXIMUM; i++) {
		event->consumers[i] = NULL;
	}
	rnm_idcpy(&event->id, id);
}

void rnm_channel_init(struct rnm_channel *channel, rnmid_t *id)
{
	channel->producer = NULL;
	channel->anons_count = 0;
	channel->producers_count = 0;
	channel->request_count = 0;

	rnm_idcpy(&channel->id, id);
}

struct rnm_channel *rnm_create_channel(struct rnm_server *s, rnmid_t *id)
{
	int i;

	for (i = 0; i < RNM_CHANNEL_MAXIMUM; i++)
		if (s->channels[i].id.i[0] == -1) {
			rnm_channel_init(&s->channels[i], id);
			s->channel_count++;
			return &s->channels[i];
		}
	rtsd_error("havn't space for create channel");
	return NULL;
}

struct rnm_event *rnm_create_event(struct rnm_server *s, rnmid_t *id)
{
	int i;

	for (i = 0; i < RNM_EVENT_MAXIMUM; i++)
		if (s->events[i].id.i[0] == -1) {
			rnm_event_init(&s->events[i], id);
			s->event_count++;
			return &s->events[i];
		}
	rtsd_error("haven't space for create event");
	return NULL;
}

struct rnm_event *rnm_find_event(struct rnm_server *s, rnmid_t *id)
{
	int i;
	for (i = 0; i < RNM_EVENT_MAXIMUM; i++)
		if (rnm_idcmp(&s->events[i].id, id)) {
			return &s->events[i];
		}
	return NULL;
}

struct rnm_channel *rnm_find_channel(struct rnm_server *s, rnmid_t *id)
{
	int i;
	for (i = 0; i < RNM_CHANNEL_MAXIMUM; i++)
		if (rnm_idcmp(&s->channels[i].id, id)) {
			return &s->channels[i];
		}
	return NULL;
}

void rnm_free_event(struct rnm_server *s, rnmid_t *id)
{
	struct rnm_event *event = rnm_find_event(s, id);

	if (event != NULL) {
		event->id.i[0] = -1;
		s->event_count--;
	}

}

void rnm_free_channel(struct rnm_server *s, rnmid_t *id)
{
	struct rnm_channel *channel = rnm_find_channel(s, id);

	if (channel != NULL) {
		channel->id.i[0] = -1;
		s->channel_count--;
	}
}

int rnm_check_and_free_event(struct rnm_event *event)
{
	int i;

	if (event->producer != NULL)
		return -1;

	for (i = 0; i < RNM_CLIENT_MAXIMUM; i++) {
		if (event->consumers[i] != NULL)
			return -1;
	}
	event->id.i[0] = -1;
	return 0;
}

int rnm_add_client_to_event(struct rnm_client *c, struct rnm_event *event)
{
	int i;

	rtsd_debug("add client to event");

	for (i = 0; i < RNM_CLIENT_MAXIMUM; i++) {
		if (event->consumers[i] == c) {
			rtsd_error("already subscribes, skip");
			return 0;
		}
	}
	for (i = 0; i < RNM_CLIENT_MAXIMUM; i++) {
		rtsd_debug("active client %p in %d", event->consumers[i], i);
		if (event->consumers[i] == NULL) {
			rtsd_debug("add client %p in %d", c, i);
			event->consumers[i] = c;
			event->consumers_count++;
			c->event_subscribe++;
			return 0;
		}
	}
	return -1;
}

void rnm_remove_client_from_event(struct rnm_client *c, struct rnm_event *event)
{
	int i;

	rtsd_debug("looking for client %p in event %s", c, event->id.c);
	for (i = 0; i < RNM_CLIENT_MAXIMUM; i++) {
		rtsd_debug("active client %p in %d", event->consumers[i], i);
		if (event->consumers[i] == c) {
			event->consumers[i] = NULL;
			event->consumers_count--;
			c->event_subscribe--;
			return;
		}
	}
	return;
}

void rnm_remove_client_from_events(struct rnm_client *c)
{
	struct rnm_server *s = c->server;
	int i;
	for (i = 0; i < RNM_EVENT_MAXIMUM; i++) {
		if (s->events[i].id.i[0] != -1) {
			rnm_remove_client_from_event(c, &s->events[i]);
		}
	}
}

void rnm_remove_channels_of_client(struct rnm_client *c)
{
	struct rnm_server *s = c->server;
	int i;
	for (i = 0; i < RNM_CHANNEL_MAXIMUM; i++) {
		if (s->channels[i].id.i[0] != -1) {
			if (s->channels[i].producer == c)
				s->channels[i].id.i[0] = -1;
		}
	}
}

int rnm_server_subscribe_event(struct rnm_server *s, int flags, const char *cid, void (*cb)(void *, char *, void *, int), void *args)
{
	rnmid_t id;
	struct rnm_event *event;

	rnm_idstr(&id, cid);
	event = rnm_find_event(s, &id);

	if (event == NULL) {
		if (!(flags & RNM_TYPE_DONT_CHECK)) return -1;
		event = rnm_create_event(s, &id);
		if (event == NULL) return -2;
	}

	event->args = args;
	event->cb = cb;

	return 0;
}

void rnm_server_unsubscribe_event(struct rnm_server *s, const char *cid)
{
	rnmid_t id;
	struct rnm_event *event;

	rnm_idstr(&id, cid);
	event = rnm_find_event(s, &id);

	if (event == NULL) return;

	event->cb = NULL;
	event->args = NULL;
}

void rnm_sync_calculate(int offset_s, int offset_ms, struct timespec *sync_time)
{
	clock_gettime(CLOCK_REALTIME, sync_time);
	sync_time->tv_sec += offset_s;
	sync_time->tv_nsec += offset_ms * 1000000L;
	if (sync_time->tv_nsec > 1000000000L) {
		sync_time->tv_nsec -= 1000000000L;
		sync_time->tv_sec++;
	}
}

int rnm_send_event(struct rnm_server *s, struct rnm_event *event, int flags)
{
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header)+event->data_size;
	struct rnm_client *c;
	int i;

	rnm_idcpy(&packet.header.id, &event->id);
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	memcpy(packet.buffer, event->data, event->data_size);
	packet.header.data_size = event->data_size;

	packet.header.type = RNM_TYPE_EVENT;
	if (flags & RNM_TYPE_SYNC) {
		packet.header.type |= RNM_TYPE_SYNC;
		rnm_sync_calculate(0, s->sync_offset, &packet.header.time);
	}
	for (i = 0; i < RNM_CLIENT_MAXIMUM; i++) {
		if (event->consumers[i] == NULL) continue;
		if (event->consumers[i] == event->producer && !(flags & RNM_TYPE_ECHO)) continue;
		c = event->consumers[i];
		if (c->socketfd != -1) {
			rn_blocking_send(c->socketfd, &packet, size, MSG_NOSIGNAL);
			c->tx_event_count++;
		}
	}
	return 0;
}

int rnm_resend_event(struct rnm_client *c, struct rnm_event *event)
{
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header)+event->data_size;

	rnm_idcpy(&packet.header.id, &event->id);
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	memcpy(packet.buffer, event->data, event->data_size);
	packet.header.data_size = event->data_size;
	packet.header.type = RNM_TYPE_EVENT;
	packet.header.type |= RNM_STATUS_LOST;

	rn_blocking_send(c->socketfd, &packet, size, MSG_NOSIGNAL);
	c->tx_event_count++;

	return 0;
}

int rnm_send_error(struct rnm_client *c, char *error, int code)
{
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header);

	rnm_idstr(&packet.header.id, error);
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.data_size = 0;
	packet.header.type = RNM_TYPE_ERROR;
	packet.header.update_counter = code;

	rn_blocking_send(c->socketfd, &packet, size, MSG_NOSIGNAL);
	c->tx_event_count++;

	return 0;
}

int rnm_server_write(struct rnm_server *s, int flags, const char *cid, void *data, int data_size)
{
	rnmid_t id;
	struct rnm_event *event;

	rnm_idstr(&id, cid);

	rtsd_debug("writing event");

	event = rnm_find_event(s, &id);
	if (event == NULL) {
		rtsd_debug("event not found");
		if (!(flags & RNM_TYPE_DONT_CHECK)) return -1;
		rtsd_debug("create event");
		event = rnm_create_event(s, &id);
		if (event == NULL) return -2;
	}

	if (!data_size)
		data_size = rnm_get_size_by_type(flags);
	memcpy(event->data, data, data_size);
	event->data_size = data_size;

	if (event->producer != NULL) {
		event->producer = NULL;
		event->producers_count++;
	}
	rtsd_debug("send event");
	rnm_send_event(s, event, flags);
	return 0;
}

int rnm_server_setint(struct rnm_server *s, int flags, const char *id, int data)
{
	return rnm_server_write(s, flags | RNM_TYPE_VAR_INT, id, &data, 0);

}

int rnm_server_setlong(struct rnm_server *s, int flags, const char *id, long data)
{
	return rnm_server_write(s, flags | RNM_TYPE_VAR_LONG, id, &data, 0);
}

int rnm_server_setfloat(struct rnm_server *s, int flags, const char *id, float data)
{
	return rnm_server_write(s, flags | RNM_TYPE_VAR_FLOAT, id, &data, 0);
}

int rnm_server_setdouble(struct rnm_server *s, int flags, const char *id, double data)
{
	return rnm_server_write(s, flags | RNM_TYPE_VAR_DOUBLE, id, &data, 0);
}

int rnm_server_setstr(struct rnm_server *s, int flags, const char *id, const char *data)
{
	return rnm_server_write(s, flags | RNM_TYPE_VAR_STRING, id, (void *) data, strlen(data) + 1);
}

int rnm_server_read(struct rnm_server *s, int flags, const char *cid, void *data, int *data_size)
{
	rnmid_t id;
	struct rnm_event *event;

	rnm_idstr(&id, cid);
	event = rnm_find_event(s, &id);

	if (event == NULL)
		return -1;

	if (*data_size > event->data_size)
		*data_size = event->data_size;
	memcpy(data, event->data, *data_size);

	return 0;
}

int rnm_server_getint(struct rnm_server *s, int flags, const char *id, int *data)
{
	int size = sizeof(int);
	return(rnm_server_read(s, flags | RNM_TYPE_VAR_INT, id, data, &size));
}

int rnm_server_getlong(struct rnm_server *s, int flags, const char *id, long *data)
{
	int size = sizeof(long);
	return(rnm_server_read(s, flags | RNM_TYPE_VAR_LONG, id, data, &size));
}

int rnm_server_getfloat(struct rnm_server *s, int flags, const char *id, float *data)
{
	int size = sizeof(float);
	return(rnm_server_read(s, flags | RNM_TYPE_VAR_FLOAT, id, data, &size));
}

int rnm_server_getdouble(struct rnm_server *s, int flags, const char *id, double *data)
{
	int size = sizeof(double);
	return(rnm_server_read(s, flags | RNM_TYPE_VAR_DOUBLE, id, data, &size));
}

int rnm_server_getstr(struct rnm_server *s, int flags, const char *id, char *data, int size)
{
	return(rnm_server_read(s, flags | RNM_TYPE_VAR_STRING, id, data, &size));
}

void rnm_server_cb_event(struct rnm_server *s, rnmid_t *id)
{
	void (*cb)(void *, char *, void *data, int size);
	void *args;
	struct rnm_event *event = rnm_find_event(s, id);

	if (event == NULL) return;

	cb = event->cb;
	args = event->args;
	if (cb != NULL) {
		cb(args, id->c, event->data, event->data_size);
	}
}

void rnm_close_client_socket(struct rnm_client *c)
{
	int socketfd = c->socketfd;

	epoll_ctl(c->server->epollfd, EPOLL_CTL_DEL, socketfd, NULL);

	rnm_remove_client_from_events(c);
	rnm_remove_channels_of_client(c);

	c->socketfd = -1;
	close(socketfd);
	rtsd_debug("client disconnected %d", socketfd);
}

int rnm_client_subscribe(struct rnm_client *c, rnmid_t *id, int flags, uint64_t update_counter)
{
	struct rnm_event *event;

	rtsd_debug("client subscribe");
	event = rnm_find_event(c->server, id);
	if (event == NULL) {
		rtsd_debug("event not found");
		if (!(flags & RNM_TYPE_DONT_CHECK)) return -1;
		event = rnm_create_event(c->server, id);
		if (event == NULL) return -2;
		event->data_type = flags & RNM_TYPE_VAR_MASK;
	}

	rtsd_debug("found event: type [0x%08x:0x%08x] ", flags&RNM_TYPE_VAR_MASK, event->data_type);
	if (((event->data_type & RNM_TYPE_VAR_MASK) == RNM_TYPE_VAR_ANY) || ((flags & RNM_TYPE_VAR_MASK) == RNM_TYPE_VAR_ANY) || ((flags & RNM_TYPE_VAR_MASK) == event->data_type))
		rnm_add_client_to_event(c, event);
	else return -3;

	if (update_counter < event->update_counter)
		rnm_resend_event (c, event);
	return 0;
}

int rnm_client_unsubscribe(struct rnm_client *c, rnmid_t *id)
{
	struct rnm_event *event;

	rtsd_debug("client unsubscribe");
	event = rnm_find_event(c->server, id);
	if (event != NULL) {
		rnm_remove_client_from_event(c, event);
	}
	return 0;
}

int rnm_add_event(struct rnm_server *s, rnmid_t *id, int flags, void *data, int size)
{
	struct rnm_event *event = NULL;

	rtsd_debug("looking for exist event %s", (char *) id);
	event = rnm_find_event(s, id);

	if (event == NULL) {
		event = rnm_create_event(s, id);
		if (event == NULL) return -1;
	} else
		if (!(flags & RNM_TYPE_REDEFINE)) return -2;

	event->data_type = flags & RNM_TYPE_VAR_MASK;
	if ((size > 1) && (size < RNM_VARIABLE_SIZE_MAXIMUM))
		event->data_size = size;
	else event->data_size = rnm_get_size_by_type(flags);
	if (data != NULL)
		memcpy(event->data, data, event->data_size);

	return 0;
}

int rnm_server_define(struct rnm_server *s, const char *cid, int flags, void *data, int size)
{
	rnmid_t id;

	rnm_idstr(&id, cid);
	if (size > RNM_VARIABLE_SIZE_MAXIMUM) {
		rtsd_error("size of variable %s more than maximum %d", cid, RNM_VARIABLE_SIZE_MAXIMUM);
		return -5;
	}
	return(rnm_add_event(s, &id, flags, data, size));
}

int rnm_client_read(struct rnm_client *c, rnmid_t *id)
{
	struct rnm_event *event;
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header);

	rtsd_debug("client wants to read event %s", (char *) id);

	rnm_idcpy(&packet.header.id, id);
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_TYPE_READ;

	event = rnm_find_event(c->server, id);
	if (event != NULL) {
		rtsd_debug("found event %s for read", (char *) id);
		size += event->data_size;
		memcpy(packet.buffer, event->data, event->data_size);
		packet.header.data_size = event->data_size;
		packet.header.type |= (event->data_type & RNM_TYPE_VAR_MASK);
	} else {
		rtsd_debug("no event %s for read", (char *) id);
		packet.header.type |= RNM_TYPE_VAR_NOT_DEFINED;
		packet.header.data_size = 0;
	}
	rn_blocking_send(c->socketfd, &packet, size, MSG_NOSIGNAL);
	c->tx_event_count++;
	return 0;
}

int rnm_client_write(struct rnm_client *c, rnmid_t *id, int flags, char *data, int data_size)
{
	struct rnm_event *event;
	void (*cb)(void *, char *, void *, int);
	void *args;
	struct rnm_server *s = c->server;

	event = rnm_find_event(s, id);
	if (event == NULL) {
		if (!(flags & RNM_TYPE_DONT_CHECK)) return -1;
		event = rnm_create_event(c->server, id);
		if (event == NULL) return -2;
		event->data_type = flags & RNM_TYPE_VAR_MASK;
	}

	if ((flags & RNM_TYPE_VAR_MASK) != event->data_type)
		return -3;

	if (event->producer != c) {
		event->producer = c;
		event->producers_count++;
	}
	event->count++;
	c->event_write++;

	memcpy(event->data, data, data_size);
	event->data_size = data_size;
	event->update_counter = s->update_counter;
	s->update_counter++;	
	rtsd_debug("new data = %d:%d", *(int *) event->data, event->data_size);

	cb = event->cb;
	args = event->args;
	if (cb != NULL) {
		cb(args, id->c, event->data, event->data_size);
	}

	rnm_send_event(s, event, flags & (RNM_TYPE_VAR_MASK | RNM_TYPE_SYNC | RNM_TYPE_ECHO));
	return 0;
}

int rnm_server_undefine(struct rnm_server *s, const char *cid)
{
	rnmid_t id;

	rnm_idstr(&id, cid);
	rnm_free_event(s, &id);
	return 0;
}

void rnm_client_send_clientlist(struct rnm_client *c, uint8_t sequance)
{
	struct rnm_server *s = c->server;
	struct rnm_packet packet;
	uint8_t max_clients_in_packet = RNM_VARIABLE_SIZE_MAXIMUM / sizeof(struct rnm_client_info);
	struct rnm_client_info *client_info = (struct rnm_client_info *) packet.buffer;
	uint8_t client_count = 0;
	int i;
	struct rnm_client *client;


	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_TYPE_CLIENT_LIST;

	packet.header.id.c[0] = 0;
	packet.header.id.c[1] = (s->client_count / max_clients_in_packet) + 1;
	packet.header.id.c[3] = sequance;
	packet.header.id.c[4] = 0;


	for (i = 0; i < RNM_CLIENT_MAXIMUM; i++)
		if (s->clients[i].socketfd != -1) {
			client = &s->clients[i];
			client_info[client_count].id = client->id;
			client_info[client_count].event_subscribe = client->event_subscribe;
			client_info[client_count].event_write = client->event_write;
			client_info[client_count].rx_event_count = client->rx_event_count;
			client_info[client_count].tx_event_count = client->tx_event_count;
			client_info[client_count].ip = client->addr.sin_addr.s_addr;
			client_count++;
			if (client_count >= max_clients_in_packet) {
				packet.header.id.c[2] = client_count;
				packet.header.data_size = client_count * sizeof(struct rnm_client_info);
				rn_blocking_send(c->socketfd, &packet, sizeof(struct rnm_header)+packet.header.data_size, MSG_NOSIGNAL);
				c->tx_event_count++;
				packet.header.id.c[0]++;
				client_count = 0;
			}
		}
	packet.header.id.c[4] = 1;
	if (client_count) {
		packet.header.id.c[2] = client_count;
		packet.header.data_size = client_count * sizeof(struct rnm_client_info);
		rn_blocking_send(c->socketfd, &packet, sizeof(struct rnm_header) +packet.header.data_size, MSG_NOSIGNAL);
		c->tx_event_count++;
	} else {
		packet.header.id.c[2] = 0;
		packet.header.data_size = 0;
		rn_blocking_send(c->socketfd, &packet, sizeof(struct rnm_header), MSG_NOSIGNAL);
		c->tx_event_count++;
	}
}

void rnm_client_send_eventlist(struct rnm_client *c, uint8_t sequance)
{
	struct rnm_server *s = c->server;
	struct rnm_packet packet;
	uint8_t max_events_in_packet = RNM_VARIABLE_SIZE_MAXIMUM / sizeof(struct rnm_event_info);
	struct rnm_event_info *event_info = (struct rnm_event_info *) packet.buffer;
	uint8_t event_count = 0;
	int i;
	struct rnm_event *event;


	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_TYPE_EVENT_LIST;

	packet.header.id.c[0] = 0;
	packet.header.id.c[1] = (s->event_count / max_events_in_packet) + 1;
	packet.header.id.c[3] = sequance;
	packet.header.id.c[4] = 0;
	rtsd_debug("send event list max events in package %d, packages %d, seq %d", max_events_in_packet, packet.header.id.c[1], packet.header.id.c[3]);

	for (i = 0; i < RNM_EVENT_MAXIMUM; i++)
		if (s->events[i].id.i[0] != -1) {
			event = &s->events[i];
			event_info[event_count].id = event->id;
			event_info[event_count].consumers_count = event->consumers_count;
			event_info[event_count].count = event->count;
			event_info[event_count].data_size = event->data_size;
			event_info[event_count].producers_count = event->producers_count;
			event_info[event_count].type = event->data_type;
			memcpy(&event_info[event_count].short_data, event->data, MIN(event->data_size, RNM_VARIABLE_INFO_SIZE_MAXIMUM));
			event_count++;
			if (event_count >= max_events_in_packet) {
				rtsd_debug("send events packet with %d events", event_count);
				packet.header.id.c[2] = event_count;
				packet.header.data_size = event_count * sizeof(struct rnm_event_info);
				rn_blocking_send(c->socketfd, &packet, sizeof(struct rnm_header)+packet.header.data_size, MSG_NOSIGNAL);
				c->tx_event_count++;
				event_count = 0;
				packet.header.id.c[0]++;
			}
		}
	packet.header.id.c[4] = 1;
	if (event_count) {
		packet.header.id.c[2] = event_count;
		packet.header.data_size = event_count * sizeof(struct rnm_event_info);
		rn_blocking_send(c->socketfd, &packet, sizeof(struct rnm_header)+packet.header.data_size, MSG_NOSIGNAL);
		c->tx_event_count++;
	} else {
		packet.header.id.c[2] = 0;
		packet.header.data_size = 0;
		c->tx_event_count++;
		rn_blocking_send(c->socketfd, &packet, sizeof(struct rnm_header), MSG_NOSIGNAL);
	}
}

void rnm_client_send_channellist(struct rnm_client *c, uint8_t sequance)
{
	struct rnm_server *s = c->server;
	struct rnm_packet packet;
	uint8_t max_channels_in_packet = RNM_VARIABLE_SIZE_MAXIMUM / sizeof(struct rnm_channel_info);
	struct rnm_channel_info *channel_info = (struct rnm_channel_info *) packet.buffer;
	uint8_t channel_count = 0;
	int i;
	struct rnm_channel *channel;

	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_TYPE_CHANNEL_LIST;

	packet.header.id.c[0] = 0;
	packet.header.id.c[1] = (s->channel_count / max_channels_in_packet) + 1;
	packet.header.id.c[3] = sequance;
	packet.header.id.c[4] = 0;
	rtsd_debug("send channel list max channels in package %d, packages %d, seq %d", max_channels_in_packet, packet.header.id.c[1], packet.header.id.c[3]);

	for (i = 0; i < RNM_CHANNEL_MAXIMUM; i++)
		if (s->channels [i].id.i[0] != -1) {
			channel = &s->channels[i];
			channel_info[channel_count].id = channel->id;
			channel_info[channel_count].anons_count = channel->anons_count;
			channel_info[channel_count].request_count = channel->request_count;
			channel_info[channel_count].ip = channel->ticket.ip;
			channel_info[channel_count].port = channel->ticket.port;

			channel_count++;
			if (channel_count >= max_channels_in_packet) {
				rtsd_debug("send events packet with %d events", channel_count);
				packet.header.id.c[2] = channel_count;
				packet.header.data_size = channel_count * sizeof(struct rnm_channel_info);
				rn_blocking_send(c->socketfd, &packet, sizeof(struct rnm_header)+packet.header.data_size, MSG_NOSIGNAL);
				c->tx_event_count++;
				channel_count = 0;
				packet.header.id.c[0]++;
			}
		}
	packet.header.id.c[4] = 1;
	if (channel_count) {
		packet.header.id.c[2] = channel_count;
		packet.header.data_size = channel_count * sizeof(struct rnm_channel_info);
		rn_blocking_send(c->socketfd, &packet, sizeof(struct rnm_header)+packet.header.data_size, MSG_NOSIGNAL);
		c->tx_event_count++;
	} else {
		packet.header.id.c[2] = 0;
		packet.header.data_size = 0;
		c->tx_event_count++;
		rn_blocking_send(c->socketfd, &packet, sizeof(struct rnm_header), MSG_NOSIGNAL);
	}
}

int rnm_add_channel(struct rnm_client *c, rnmid_t *id, int flags, struct rnm_channel_ticket *ticket)
{
	struct rnm_server *s = c->server;
	struct rnm_channel *channel = NULL;

	rtsd_debug("looking for exist channel %s", (char *) id);
	channel = rnm_find_channel(s, id);

	if (channel == NULL) {
		channel = rnm_create_channel(s, id);
		if (channel == NULL) return -1;
	};
	channel->anons_count++;

	memcpy(&channel->ticket, ticket, sizeof(struct rnm_channel_ticket));
	channel->ticket.ip = c->addr.sin_addr.s_addr;

	if (c != channel->producer) {
		channel->producer = c;
		channel->producers_count++;
	}
	return 0;
}

int rnm_client_channel_request(struct rnm_client *c, rnmid_t *id, int flags)
{
	struct rnm_channel *channel;
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header) + sizeof(struct rnm_channel_ticket);

	rtsd_debug("client request a channel");
	channel = rnm_find_channel(c->server, id);
	if (channel == NULL)
		return -1;
	rtsd_debug("found channel: type [0x%08x] ", flags & RNM_CHANNEL_MASK);

	rnm_idcpy(&packet.header.id, id);
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_CHANNEL_TICKET;
	packet.header.data_size = sizeof(struct rnm_channel_ticket);

	memcpy(packet.buffer, &channel->ticket, sizeof(struct rnm_channel_ticket));
	rn_blocking_send(c->socketfd, &packet, size, MSG_NOSIGNAL);
	return 0;
}

int rnm_client_channel(struct rnm_client *c, struct rnm_header *packet_header, char *data)
{
	switch (packet_header->type & RNM_CHANNEL_MASK) {

	case RNM_CHANNEL_ANONS:
		rnm_add_channel(c, &packet_header->id, packet_header->type, (struct rnm_channel_ticket *) data);
		break;
	case RNM_CHANNEL_REQUEST:
		rnm_client_channel_request(c, &packet_header->id, packet_header->type);
		break;
	default: return -1;
	}

	return 0;
}

int rnm_client_process_packet(struct rnm_client *c, struct rnm_header *packet_header, char *data)
{
	switch (packet_header->type & RNM_TYPE_MSG_MASK) {
	case RNM_TYPE_SUBSCRIBE:
		rnm_client_subscribe(c, &packet_header->id, packet_header->type, packet_header->update_counter);
		break;
	case RNM_TYPE_UNSUBSCRIBE:
		rnm_client_unsubscribe(c, &packet_header->id);
		break;
	case RNM_TYPE_DEFINE:
		rnm_add_event(c->server, &packet_header->id, packet_header->type, NULL, packet_header->data_size);
		break;
	case RNM_TYPE_UNDEFINE:
		rnm_free_event(c->server, &packet_header->id);
		break;
	case RNM_TYPE_WRITE:
		rnm_client_write(c, &packet_header->id, packet_header->type, data, packet_header->data_size);
		break;
	case RNM_TYPE_READ:
		rnm_client_read(c, &packet_header->id);
		break;
	case RNM_TYPE_CLIENT_LIST:
		rnm_client_send_clientlist(c, (int) packet_header->id.c[0]);
		break;
	case RNM_TYPE_EVENT_LIST:
		rnm_client_send_eventlist(c, (int) packet_header->id.c[0]);
		break;
	case RNM_TYPE_CLIENT_ID:
		if (packet_header->time.tv_sec != RNM_VERSION_MAJOR) {
			rnm_send_error	(c, "Unsupport version", 1);
			rnm_close_client_socket (c);
		}
		memcpy(&c->id, &packet_header->id, sizeof(rnmid_t));
		c->version = ((packet_header->time.tv_sec&0xff) << 8) | (packet_header->time.tv_nsec&0xff);
		break;
	case RNM_TYPE_CHANNEL:
		rnm_client_channel(c, packet_header, data);
		break;
	case RNM_TYPE_CHANNEL_LIST:
		rnm_client_send_channellist(c, (int) packet_header->id.c[0]);
		break;
	default: return -1;
	}
	c->rx_event_count++;
	return 0;
}

int rnm_client_handler(void *client, uint32_t epoll_event)
{
	int read_size;
	struct rnm_client *c = client;
	int socketfd = c->socketfd;
	struct rnm_header *packet_header;
	int buffer_head = 0;
	int buffer_recv = c->buffer_recv;
	uint8_t *buffer = c->buffer;

	read_size = recv(socketfd, buffer + buffer_recv, RNM_CLIENT_BUFFER_SIZE - buffer_recv, 0);
	rtsd_debug("read from client %d %d bytes", c->socketfd, read_size);
	if (read_size < (int) sizeof(struct rnm_header)) {
		if (read_size == -1) {
			if ((errno == EAGAIN) || (errno == EINTR))
				return 0;
			rnm_close_client_socket(c);
		}
		if (read_size == 0) {
			rnm_close_client_socket(c);
		}
		return 0;
	}

	buffer_recv += read_size;

	while ((buffer_recv - buffer_head) >= sizeof(struct rnm_header)) {
		packet_header = (struct rnm_header *) (buffer + buffer_head);

		if (packet_header->magic != RNM_PACKET_MAGIC) {
			buffer_head++;
			continue;
		}
		if (packet_header->magic_data != RNM_PACKET_MAGIC_DATA) {
			buffer_head++;
			continue;
		}
		packet_header->data_size &= RNM_VARIABLE_SIZE_MAXIMUM;
		if ((buffer_recv - buffer_head) < (sizeof(struct rnm_header) +packet_header->data_size)) break;

		rnm_client_process_packet(c, packet_header, (char *) packet_header + sizeof(struct rnm_header));
		buffer_head += sizeof(struct rnm_header) +packet_header->data_size;
	}

	if (buffer_head < buffer_recv) {
		if (buffer_head)
			memmove(buffer, buffer + buffer_head, buffer_recv - buffer_head);
		c->buffer_recv = buffer_recv - buffer_head;
	} else c->buffer_recv = 0;

	return 0;
}

int rnm_add_client(void *server, uint32_t epoll_event)
{
	struct rnm_server *s = server;
	struct rnm_client *c;
	struct epoll_event socket_event;

	rtsd_debug("new client extended");
	c = rnm_get_free_client(s);
	if (c == NULL) {
		rtsd_error("couldn't find slot for client");
		return 0;
	}

	c->addr_size = sizeof(struct sockaddr_in);
	c->server = s;

	c->socketfd = accept(s->socketfd, (struct sockaddr *) &c->addr, (socklen_t*) & c->addr_size);
	if (c->socketfd == -1) {
		if ((errno == ENETDOWN || errno == EPROTO || errno == ENOPROTOOPT || errno == EHOSTDOWN ||
			errno == ENONET || errno == EHOSTUNREACH || errno == EOPNOTSUPP || errno == ENETUNREACH)) {
			return 0;
		};
		rtsd_error("error on wait client: %s", strerror(errno));
		return -1;
	}
	rn_set_nonblocking_socket(c->socketfd, 1024 * 1024, 1024 * 1024);
	rn_set_keepalive(c->socketfd, 600, 3);

	c->epoll_data.socket = c;
	c->epoll_data.cb = &rnm_client_handler;
	c->event_subscribe = 0;
	c->rx_event_count = 0;
	c->tx_event_count = 0;
	c->event_write = 0;

	socket_event.data.ptr = &c->epoll_data;
	socket_event.events = EPOLLIN | EPOLLERR;
	epoll_ctl(s->epollfd, EPOLL_CTL_ADD, c->socketfd, &socket_event);
	s->client_count++;

	rtsd_debug("client connected %d", c->socketfd);
	return 0;
}

void rnm_recv_clients(struct rnm_server *s)
{
	int epollfd = s->epollfd;
	struct epoll_event socket_event;
	struct epoll_event *socket_events = s->socket_events;
	int event_size;
	struct rnm_epoll_cb *epoll_data;
	int i;

	socket_event.data.ptr = &s->epoll_data;
	socket_event.events = EPOLLIN | EPOLLERR;
	epoll_ctl(epollfd, EPOLL_CTL_ADD, s->socketfd, &socket_event);

	while (1) {
		event_size = epoll_wait(epollfd, socket_events, RNM_CLIENT_MAXIMUM, -1);
		for (i = 0; i < event_size; i++) {
			rtsd_debug("event %d from %d", i, event_size);
			epoll_data = (struct rnm_epoll_cb *) socket_events[i].data.ptr;
			epoll_data->cb(epoll_data->socket, socket_events[i].events);
		}
	}
}

void *rnm_server_thread(void *server)
{
	struct rnm_server *s = server;

	rtsd_debug("run server thread");
	while (1) {
		rtsd_debug("open server socket");
		s->socketfd = rn_tcpserver_open(s->addr, s->port);
		if (s->socketfd < 0) {
			rtsd_error("couldn't open socket");
			continue;
		}
		rn_set_nonblocking_socket(s->socketfd, 1024 * 1024, 1024 * 1024);
		s->epollfd = epoll_create(RNM_CLIENT_MAXIMUM + 1); // actually arg is ignore
		if (s->epollfd < 0) {
			rtsd_error("couldn't create epoll descriptor");
			close(s->socketfd);
			continue;
		}
		rnm_recv_clients(s);
		close(s->epollfd);
		close(s->socketfd);
	}

	free(server);
	return NULL;
}

void rnm_server_set_sync_offset(struct rnm_server *s, int ms)
{
	s->sync_offset = ms;
}

static void rnm_server_structure_init(struct rnm_server * s)
{
	int i;

	for (i = 0; i < RNM_EVENT_MAXIMUM; i++) {
		s->events[i].id.i[0] = -1;
	}
	for (i = 0; i < RNM_CHANNEL_MAXIMUM; i++) {
		s->channels[i].id.i[0] = -1;
	}
	for (i = 0; i < RNM_CLIENT_MAXIMUM; i++) {
		s->clients[i].socketfd = -1;
	}
	s->sync_offset = RNM_DEFAULT_SYNC_OFFSET_MS;
}

struct rnm_server * rnm_server_create(const char *addr, int port, const char *cid)
{
	struct rnm_server *s;

	s = calloc(1, sizeof(struct rnm_server));
	if (s == NULL) {
		rtsd_error("couldn't allocate a few memory");
		goto error_server_alloc;
	}

	rnm_server_structure_init(s);
	if (addr != NULL)
		strncpy(s->addr, addr, 20);
	s->port = port;
	if (cid != NULL)
		rnm_idstr(&s->id, cid);
	s->epoll_data.socket = s;
	s->epoll_data.cb = &rnm_add_client;

	pthread_create(&s->thread, NULL, &rnm_server_thread, (void*) s);
	return s;

error_server_alloc:
	return NULL;
}

void rnm_server_stop(struct rnm_server * s)
{

}

void rnm_server_print_event(struct rnm_server * s)
{
	int i;
	char str[15];
	struct in_addr addr;

	rtsd_info("Event statistics");
	rtsd_info("|%30s|%15s|%7s|%7s|%7s", "id", "value", "count", "prod.", "cons.");
	for (i = 0; i < RNM_EVENT_MAXIMUM; i++)
		if (s->events[i].id.i[0] != -1) {
			switch (s->events[i].data_type) {
			case RNM_TYPE_VAR_INT:
				if (isprint(*(int *) s->events[i].data)) snprintf(str, 15, "%d/%c", *(int *) s->events[i].data, *(char *) s->events[i].data);
				else snprintf(str, 15, "%d", *(int *) s->events[i].data);
				break;
			case RNM_TYPE_VAR_LONG: snprintf(str, 15, "%ld", *(long *) s->events[i].data);
				break;
			case RNM_TYPE_VAR_FLOAT: snprintf(str, 15, "%f", *(float *) s->events[i].data);
				break;
			case RNM_TYPE_VAR_DOUBLE: snprintf(str, 15, "%lf", *(double *) s->events[i].data);
				break;
			case RNM_TYPE_VAR_STRING: snprintf(str, 15, "%s", (char *) s->events[i].data);
				break;
			default: snprintf(str, 10, "not support");
				break;
			}
			rtsd_info("|%30s|%15s|%7d|%7d|%7d", (char *) &s->events[i].id, str, s->events[i].count, s->events[i].producers_count, s->events[i].consumers_count);
		}

	rtsd_info("Client statistics");
	rtsd_info("|%20s|%7s|%7s|%7s|%7s|%7s", "id", "rx pkt", "tx pkt", "subscr", "write", "ip");
	for (i = 0; i < RNM_CLIENT_MAXIMUM; i++)
		if (s->clients[i].socketfd != -1) {
			rtsd_info("|%20s|%7d|%7d|%7d|%7d|%7s", (char *) &s->clients[i].id, s->clients[i].rx_event_count, s->clients[i].tx_event_count, s->clients[i].event_subscribe, s->clients[i].event_write,
				inet_ntoa(s->clients[i].addr.sin_addr));
		}

	rtsd_info("Channel statistics");
	rtsd_info("|%20s|%11s|%7s|%7s|%7s|%7s", "id", "ip", "port", "tickets", "prod", "cons.");
	for (i = 0; i < RNM_CHANNEL_MAXIMUM; i++)
		if (s->channels[i].id.i[0] != -1) {
			addr.s_addr = s->channels[i].ticket.ip;
			rtsd_info("|%20s|%11s|%7d|%7d|%7d|%7d", (char *) &s->channels[i].id, inet_ntoa(addr), s->channels[i].ticket.port,
				s->channels[i].request_count, s->channels[i].producers_count, s->channels[i].anons_count);
		}

}


int rnm_server_ssdp_response (struct rnm_server *s, char *buffer, int size)
{
	return (snprintf(buffer, size, "%sCACHE-CONTROL:max-age=120\r\nDATE:\r\nEXT:\r\nLOCATION:%s:%d\r\nSERVER:unknow\r\nST:%s\r\nUSN:%s\r\n\r\n",
		ssdp_headers.response,s->addr,s->port,rnm_ssdp_field.name, s->id.c) );
}


void rnm_server_ssdp_receive(struct rnm_server *s)
{
	char ssdp_client_buffer[SSDP_PACKET_SIZE];
	struct sockaddr_in ssdp_client_addr;
	socklen_t ssdp_client_addr_len = sizeof(struct sockaddr_in);
	ssize_t packet_size;
	int ssdp_msearch_size = strlen(ssdp_headers.msearch);

	
	while (1) {
		rtsd_debug("wait for packet");
		packet_size = recvfrom(s->ssdp_socketfd, ssdp_client_buffer, SSDP_PACKET_SIZE, 0, (struct sockaddr *) &ssdp_client_addr, &ssdp_client_addr_len);
		if (packet_size < 0) return;
		if (packet_size < ssdp_msearch_size) continue;

		if (memcmp(ssdp_client_buffer, ssdp_headers.msearch, ssdp_msearch_size))
			continue;
		rtsd_debug("try target: %s",ssdp_client_buffer);
		if (strstr(ssdp_client_buffer, rnm_ssdp_field.name) == NULL)
			continue;
		packet_size = rnm_server_ssdp_response (s, ssdp_client_buffer, SSDP_PACKET_SIZE);
		sendto (s->ssdp_socketfd, ssdp_client_buffer, packet_size, 0, (struct sockaddr *) &ssdp_client_addr, ssdp_client_addr_len);
	}
}

void *rnm_server_ssdp_thread(void *args)
{
	struct rnm_server *s = args;

	rtsd_debug("run ssdp thread");
	while (1) {
		rtsd_debug("open server socket");
		s->ssdp_socketfd = rn_udpmulticast_open(NULL, ssdp_network.port);
		rn_add_multicast_group (s->ssdp_socketfd, ssdp_network.ip, NULL);
		if (s->ssdp_socketfd < 0) {
			rtsd_error("couldn't open ssdp socket");
			continue;
		}
		rnm_server_ssdp_receive(s);
		close(s->ssdp_socketfd);
	}

	return NULL;
}

void rnm_server_ssdp_create(struct rnm_server *s, char *address)
{
	pthread_create(&s->ssdp_thread, NULL, &rnm_server_ssdp_thread, (void*) s);
}

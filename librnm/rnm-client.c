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
#include <pthread.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <ctype.h>

#include "rn.h"
#include "rnm-common.h"
#include "rnm-client-types.h"

#define MODULE_NAME "rnm-client"
#include <rnm-debug.h>
#undef rtsd_debug
#define rtsd_debug(fmt,args...)

struct rnm_client_event *rnm_get_event(struct rnm_connect *s, rnmid_t *id)
{
	int i;
	for (i = 0; i < RNM_EVENT_MAXIMUM; i++)
		if (rnm_idcmp(&s->events[i].id, id)) {
			return &s->events[i];
		}
	return NULL;
}

void rnm_wait_sync(struct timespec *sync_time)
{
	struct timespec system_time, diff;

	while (1) {
		clock_gettime(CLOCK_REALTIME, &system_time);
		diff.tv_sec = sync_time->tv_sec - system_time.tv_sec;
		diff.tv_nsec = sync_time->tv_nsec - system_time.tv_nsec;
		if ((diff.tv_sec < 0) || ((diff.tv_sec == 0) && (diff.tv_nsec < 0)) || (diff.tv_sec > 1)) break;
		if (diff.tv_nsec < 0) {
			diff.tv_nsec += 1000000000L;
			diff.tv_sec--;
		}
		rtsd_debug("wait for %ld:%ld", (long int) diff.tv_sec, (long int) diff.tv_nsec);

		if ((diff.tv_sec > 0) || (diff.tv_nsec > 1000000L)) {
			nanosleep(&diff, NULL);
		}
	}
}

int rnm_wait_for_read(struct rnm_connect *s, int timeout)
{
	struct timespec to;

	clock_gettime(CLOCK_MONOTONIC, &to);
	to.tv_sec += timeout;

	pthread_mutex_lock(&s->read_mutex);
	while (s->read_wait)
		if (pthread_cond_timedwait(&s->read_cond, &s->read_mutex, &to) == ETIMEDOUT) {
			pthread_mutex_unlock(&s->read_mutex);
			return -ETIMEDOUT;
		}
	pthread_mutex_unlock(&s->read_mutex);
	return 0;
}

int rnm_read(struct rnm_connect *s, int flags, const char *cid, void *data, int *data_size)
{
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header);

	if (s->socketfd < 0)
		return -EBADFD;
	rnm_idstr(&packet.header.id, cid);
	rnm_idcpy(&s->read_id, &packet.header.id);
	s->read_wait = 1;
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_TYPE_READ;
	packet.header.type |= flags & RNM_TYPE_VAR_MASK;
	packet.header.data_size = 0;
	rn_blocking_send(s->socketfd, &packet, size, MSG_NOSIGNAL);

	if (rnm_wait_for_read(s, 3))
		return -ETIMEDOUT;

	if (*data_size > s->read_size)
		*data_size = s->read_size;
	memcpy(data, s->read_data, *data_size);

	rtsd_debug("read [%s] type 0x%08x, data_size %d, ret size %d", cid, packet.header.type, packet.header.data_size, *data_size);
	return 0;
}

int rnm_getvar_int(struct rnm_connect *s, int flags, const char *id, int *data)
{
	int size = sizeof(int);
	return(rnm_read(s, flags | RNM_TYPE_VAR_INT, id, data, &size));
}

int rnm_getvar_long(struct rnm_connect *s, int flags, const char *id, long *data)
{
	int size = sizeof(long);
	return(rnm_read(s, flags | RNM_TYPE_VAR_LONG, id, data, &size));
}

int rnm_getvar_float(struct rnm_connect *s, int flags, const char *id, float *data)
{
	int size = sizeof(float);
	return(rnm_read(s, flags | RNM_TYPE_VAR_FLOAT, id, data, &size));
}

int rnm_getvar_double(struct rnm_connect *s, int flags, const char *id, double *data)
{
	int size = sizeof(double);
	return(rnm_read(s, flags | RNM_TYPE_VAR_DOUBLE, id, data, &size));
}

int rnm_getvar_str(struct rnm_connect *s, int flags, const char *id, char *data, int size)
{
	return(rnm_read(s, flags | RNM_TYPE_VAR_STRING, id, data, &size));
}

int rnm_write(struct rnm_connect *s, int flags, const char *cid, void *data, int data_size)
{
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header);

	if (s->socketfd < 0) return -EBADFD;
	rnm_idstr(&packet.header.id, cid);

	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;

	if (!data_size)
		data_size = rnm_get_size_by_type(flags);
	if (data_size && data != NULL) {
		memcpy(packet.buffer, data, data_size);
		packet.header.data_size = data_size & RNM_VARIABLE_SIZE_MAXIMUM;
		size += packet.header.data_size;
	} else packet.header.data_size = 0;

	packet.header.type = flags & (RNM_TYPE_VAR_MASK | RNM_TYPE_FLAGS_MASK);
	packet.header.type |= RNM_TYPE_WRITE;

	rn_blocking_send(s->socketfd, &packet, size, MSG_NOSIGNAL);
	rtsd_debug("write [%s] type 0x%08x, data_size %d", cid, packet.header.type, packet.header.data_size);
	return 0;
}

int rnm_setvar_int(struct rnm_connect *s, int flags, const char *id, int data)
{
	return(rnm_write(s, flags | RNM_TYPE_VAR_INT, id, &data, 0));
}

int rnm_setvar_long(struct rnm_connect *s, int flags, const char *id, long data)
{
	return(rnm_write(s, flags | RNM_TYPE_VAR_LONG, id, &data, 0));
}

int rnm_setvar_float(struct rnm_connect *s, int flags, const char *id, float data)
{
	return(rnm_write(s, flags | RNM_TYPE_VAR_FLOAT, id, &data, 0));
}

int rnm_setvar_double(struct rnm_connect *s, int flags, const char *id, double data)
{
	return(rnm_write(s, flags | RNM_TYPE_VAR_DOUBLE, id, &data, 0));
}

int rnm_setvar_str(struct rnm_connect *s, int flags, const char *id, const char *data)
{
	return(rnm_write(s, flags | RNM_TYPE_VAR_STRING, id, (void *) data, strlen(data) + 1));
}

int rnm_event(struct rnm_connect *s, int flags, const char *id)
{
	return(rnm_write(s, flags | RNM_TYPE_VAR_EMPTY, id, NULL, 0));
}

int rnm_client_send_channel_anons(struct rnm_connect *s, rnmid_t *id, struct rnm_channel_ticket *ticket)
{
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header) + sizeof(struct rnm_channel_ticket);

	rnm_idcpy(&packet.header.id, id);
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_TYPE_CHANNEL | RNM_CHANNEL_ANONS;
	packet.header.data_size = sizeof(struct rnm_channel_ticket);

	memcpy(packet.buffer, ticket, sizeof(struct rnm_channel_ticket));
	rn_blocking_send(s->socketfd, &packet, size, MSG_NOSIGNAL);
	return 0;
}

int rnm_define(struct rnm_connect *s, const char *cid, int flags)
{
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header);

	rnm_idstr(&packet.header.id, cid);
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_TYPE_DEFINE;
	packet.header.type |= flags & (RNM_TYPE_VAR_MASK | RNM_TYPE_FLAGS_MASK);
	packet.header.data_size = 0;

	rn_blocking_send(s->socketfd, &packet, size, MSG_NOSIGNAL);
	rtsd_debug("sent define event");
	return 0;
}

int rnm_undefine(struct rnm_connect *s, const char *cid)
{
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header);

	rnm_idstr(&packet.header.id, cid);
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_TYPE_DEFINE;
	packet.header.data_size = 0;

	rn_blocking_send(s->socketfd, &packet, size, MSG_NOSIGNAL);
	rtsd_debug("sent undefine event");
	return 0;
}

int rnm_client_send_subscribe(struct rnm_connect *s, rnmid_t *id, int flags, uint64_t update_counter)
{
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header);

	rnm_idcpy(&packet.header.id, id);
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_TYPE_SUBSCRIBE;
	packet.header.type |= flags & (RNM_TYPE_VAR_MASK | RNM_TYPE_FLAGS_MASK);
	packet.header.data_size = 0;
	packet.header.update_counter = update_counter;

	rn_blocking_send(s->socketfd, &packet, size, MSG_NOSIGNAL);
	rtsd_debug("sent subscribe event");
	return 0;
}

int rnm_client_send_unsubscribe(struct rnm_connect *s, rnmid_t *id, int flags)
{
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header);

	rnm_idcpy(&packet.header.id, id);
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_TYPE_UNSUBSCRIBE;
	packet.header.type |= flags & (RNM_TYPE_VAR_MASK | RNM_TYPE_FLAGS_MASK);
	packet.header.data_size = 0;

	rn_blocking_send(s->socketfd, &packet, size, MSG_NOSIGNAL);
	rtsd_debug("sent unsubscribe event");
	return 0;
}

int rnm_client_send_id(struct rnm_connect *s, rnmid_t *id)
{
	struct rnm_header packet;

	rnm_idcpy(&packet.id, id);
	packet.magic = RNM_PACKET_MAGIC;
	packet.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.type = RNM_TYPE_CLIENT_ID;
	packet.data_size = 0;
	packet.time.tv_sec = RNM_VERSION_MAJOR;
	packet.time.tv_nsec = RNM_VERSION_MINOR;

	rn_blocking_send(s->socketfd, &packet, sizeof(struct rnm_header), MSG_NOSIGNAL);
	rtsd_debug("sent client id");
	return 0;
}

int rnm_subscribe_event(struct rnm_connect *s, int flags, const char *cid, void (*cb)(void *, char *, void *, int), void *args)
{
	int i;

	for (i = 0; i < RNM_EVENT_MAXIMUM; i++)
		if (s->events[i].id.i[0] == -1) {
			s->events[i].cb = cb;
			s->events[i].args = args;
			s->events[i].flags = flags;
			rnm_idstr(&s->events[i].id, cid);
			if (s->socketfd >= 0)
				rnm_client_send_subscribe(s, &s->events[i].id, flags, s->events[i].update_counter);
			rtsd_debug("event registrated");
			return 0;
		}
	return -ENOMEM;
}

void rnm_unsubscribe_event(struct rnm_connect *s, const char *cid)
{
	struct rnm_client_event *event;
	rnmid_t id;

	rnm_idstr(&id, cid);
	event = rnm_get_event(s, &id);
	if (event != NULL) {
		rnm_client_send_unsubscribe(s, &event->id, event->flags);
		event->id.i[0] = -1;
	}
	return;
}

void rnm_cb_event(struct rnm_connect *s, struct rnm_header *packet_header)
{
	struct rnm_client_event *event;
	void (*cb)(void *, char *, void *, int);
	rnmid_t *id = &packet_header->id;
	void *data = (char *) packet_header + sizeof(struct rnm_header);
	uint16_t data_size = packet_header->data_size;
	uint64_t update_counter = packet_header->update_counter;

	event = rnm_get_event(s, id);
	if (event != NULL) {
		cb = event->cb;
		if (cb != NULL)
			cb(event->args, (char *) &event->id, data, data_size);
		event->update_counter = update_counter;
	}
}

static void rnm_channel_process_packet(struct rnm_connect * s, struct rnm_header *packet_header, char *data)
{
	switch (packet_header->type & RNM_TYPE_CHANNEL_MASK) {
	case RNM_CHANNEL_TICKET:
		rtsd_debug("receive ticket id %s type 0x%08x", packet_header->id.c, packet_header->type);
		pthread_mutex_lock(&s->ticket_mutex);
		if (s->ticket_wait && rnm_idcmp(&packet_header->id, &s->ticket_id)) {
			memcpy(&s->ticket_data, (char *) packet_header + sizeof(struct rnm_header), sizeof(struct rnm_channel_ticket));
			s->ticket_wait = 0;
			pthread_cond_signal(&s->ticket_cond);
		}
		pthread_mutex_unlock(&s->ticket_mutex);
		break;
	}
}

static void rnm_process_packet(struct rnm_connect * s, struct rnm_header *packet_header, char *data)
{

	switch (packet_header->type & RNM_TYPE_MSG_MASK) {
	case RNM_TYPE_EVENT:
		rtsd_debug("receive event id %s type 0x%08x", packet_header->id.c, packet_header->type);
		if (packet_header->type & RNM_TYPE_SYNC)
			rnm_wait_sync(&(packet_header->time));
		rnm_cb_event(s, packet_header);
		break;
	case RNM_TYPE_CHANNEL:
		rnm_channel_process_packet(s, packet_header, data);
		break;
	case RNM_TYPE_ERROR:
		rtsd_error("Server error: %s", packet_header->id.c);
		if (packet_header->update_counter)
			s->onexit = 1;
		break;
	case RNM_TYPE_READ:
		rtsd_debug("receive read id %s type 0x%08x", packet_header->id.c, packet_header->type);
		pthread_mutex_lock(&s->read_mutex);
		if (s->read_wait && rnm_idcmp(&packet_header->id, &s->read_id)) {
			s->read_size = packet_header->data_size;
			memcpy(s->read_data, (char *) packet_header + sizeof(struct rnm_header), packet_header->data_size);
			s->read_wait = 0;
			pthread_cond_signal(&s->read_cond);
		}
		pthread_mutex_unlock(&s->read_mutex);
		break;
	case RNM_TYPE_EVENT_LIST:
		rtsd_debug("receive event list seq %d[%d] packet %d[%d] end %d count %d", packet_header->id.c[3], s->eventlist_sequence,
			packet_header->id.c[0], s->eventlist_sequence,
			packet_header->id.c[4], packet_header->id.c[2]);
		if (s->events_info == NULL) return;
		if (packet_header->id.c[3] != s->eventlist_sequence) return;
		if (packet_header->id.c[0] != s->eventlist_wait_packet) return;

		rtsd_debug("coping %d event list", packet_header->data_size);
		memcpy(&s->events_info[s->eventlist_recv], data, packet_header->data_size);
		s->eventlist_recv += packet_header->id.c[2];
		s->eventlist_wait_packet++;
		if (packet_header->id.c[4] == 1) {
			rtsd_debug("releasing waiter");
			pthread_mutex_lock(&s->eventlist_mutex);
			s->eventlist_wait = 0;
			pthread_cond_signal(&s->eventlist_cond);
			pthread_mutex_unlock(&s->eventlist_mutex);
		}

		break;
	case RNM_TYPE_CLIENT_LIST:
		rtsd_debug("receive client list seq %d packet %d end %d count %d", packet_header->id.c[3], packet_header->id.c[0], packet_header->id.c[4], packet_header->id.c[2]);
		if (s->clients_info == NULL) return;
		if (packet_header->id.c[3] != s->clientlist_sequence) return;
		if (packet_header->id.c[0] != s->clientlist_wait_packet) return;

		rtsd_debug("coping client list");
		memcpy(&s->clients_info[s->clientlist_recv], data, packet_header->data_size);
		s->clientlist_recv += packet_header->id.c[2];
		s->clientlist_wait_packet++;
		if (packet_header->id.c[4] == 1) {
			rtsd_debug("releasing waiter");
			pthread_mutex_lock(&s->clientlist_mutex);
			s->clientlist_wait = 0;
			pthread_cond_signal(&s->clientlist_cond);
			pthread_mutex_unlock(&s->clientlist_mutex);
		}
		break;
	case RNM_TYPE_CHANNEL_LIST:
		rtsd_debug("receive channel list seq %d[%d] packet %d[%d] end %d count %d", packet_header->id.c[3], s->channellist_sequence,
			packet_header->id.c[0], s->channellist_sequence,
			packet_header->id.c[4], packet_header->id.c[2]);
		if (s->channels_info == NULL) return;
		if (packet_header->id.c[3] != s->channellist_sequence) return;
		if (packet_header->id.c[0] != s->channellist_wait_packet) return;

		rtsd_debug("coping %d channel list", packet_header->data_size);
		memcpy(&s->channels_info[s->channellist_recv], data, packet_header->data_size);
		s->channellist_recv += packet_header->id.c[2];
		s->channellist_wait_packet++;
		if (packet_header->id.c[4] == 1) {
			rtsd_debug("releasing waiter");
			pthread_mutex_lock(&s->channellist_mutex);
			s->channellist_wait = 0;
			pthread_cond_signal(&s->channellist_cond);
			pthread_mutex_unlock(&s->channellist_mutex);
		}

		break;
	}
}

void *rnm_connect_cb_thread(void *server)
{
	struct rnm_connect *s = server;

	pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
	s->connect_cb(s->connect_arg);
	s->connect_cb_status = 0;
	pthread_exit(0);
}

static void rnm_recv(struct rnm_connect * s)
{
	int socketfd = s->socketfd;
	int i;
	fd_set set;
	int res;

	int read_size;
	struct rnm_header *packet_header;
	int buffer_head = 0;
	int buffer_recv = 0;
	uint8_t buffer[RNM_CLIENT_BUFFER_SIZE];

	rnm_client_send_id(s, &s->id);
	rtsd_debug("send subscribe events");
	for (i = 0; i < RNM_EVENT_MAXIMUM; i++) {
		if (s->events[i].id.i[0] != -1)
			rnm_client_send_subscribe(s, &s->events[i].id, s->events[i].flags, s->events[i].update_counter);
	}
	for (i = 0; i < RNM_CHANNEL_MAXIMUM; i++) {
		if (s->channels[i].id.i[0] != -1)
			rnm_client_send_channel_anons(s, &s->channels[i].id, &s->channels[i].ticket);
	}


	if ((s->connect_cb != NULL) && (s->connect_cb_status == 0)) {
		s->connect_cb_status = 1;
		pthread_create(&s->connect_thread, NULL, &rnm_connect_cb_thread, (void*) s);
	}

	FD_ZERO(&set);
	FD_SET(socketfd, &set);
	rtsd_debug("start receive data");
	while (!s->onexit) {
		res = select(socketfd + 1, &set, NULL, NULL, NULL);
		rtsd_debug("select return %d, errno %d, error[%s]", res, errno, strerror(errno));
		if (res == 0) continue;
		if ((res == -1) && (errno == EINTR)) {
			continue;
		}
		read_size = recv(socketfd, buffer + buffer_recv, RNM_CLIENT_BUFFER_SIZE - buffer_recv, 0);
		rtsd_debug("recv return %d, errno %d, error[%s]", read_size, errno, strerror(errno));
		if (read_size < (int) sizeof(struct rnm_header)) {
			if (read_size == -1) {
				if ((errno == EAGAIN) || (errno == EINTR))
					continue;
				break;
			}
			if (read_size == 0) {
				break;
			}
			continue;
		}

		buffer_recv += read_size;
		buffer_head = 0;

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
			rnm_process_packet(s, packet_header, (char *) packet_header + sizeof(struct rnm_header));
			buffer_head += sizeof(struct rnm_header) +packet_header->data_size;
		}

		if (buffer_head < buffer_recv) {
			if (buffer_head)
				memmove(buffer, buffer + buffer_head, buffer_recv - buffer_head);
			buffer_recv = buffer_recv - buffer_head;
		} else buffer_recv = 0;
	}
}

void *rnm_connect_thread(void *server)
{
	struct rnm_connect *s = server;

	rtsd_debug("start client thread");
	while (!s->onexit) {
		s->socketfd = rn_tcpclient_open(s->addr, s->port);
		if (s->socketfd < 0) {
			// rtsd_error("could't open socket");
			usleep(300000);
			continue;
		}
		rn_set_nonblocking_socket(s->socketfd, 1024 * 1024, 1024 * 1024);
		rn_set_keepalive(s->socketfd, 30, 3);
		fcntl(s->socketfd, F_SETFD, FD_CLOEXEC);
		rnm_recv(s);
		close(s->socketfd);
		s->socketfd = -1;
		usleep(1000000);
	}
	return NULL;
}

static void rnm_connect_structure_init(struct rnm_connect * s)
{
	int i;
	pthread_condattr_t attr;

	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&s->read_cond, &attr);
	pthread_mutex_init(&s->read_mutex, NULL);
	pthread_cond_init(&s->eventlist_cond, &attr);
	pthread_mutex_init(&s->eventlist_mutex, NULL);
	pthread_cond_init(&s->clientlist_cond, &attr);
	pthread_mutex_init(&s->clientlist_mutex, NULL);
	pthread_cond_init(&s->channellist_cond, &attr);
	pthread_mutex_init(&s->channellist_mutex, NULL);
	pthread_cond_init(&s->ticket_cond, &attr);
	pthread_mutex_init(&s->ticket_mutex, NULL);

	s->socketfd = -1;
	s->connect_cb = NULL;
	s->connect_arg = NULL;
	s->onexit = 0;
	rtsd_debug("init structure");
	for (i = 0; i < RNM_EVENT_MAXIMUM; i++) {
		s->events[i].id.i[0] = -1;
	}
	for (i = 0; i < RNM_CHANNEL_MAXIMUM; i++) {
		s->channels[i].id.i[0] = -1;
	}
}

struct rnm_connect *rnm_connect(const char *addr, int port, const char *id)
{
	struct rnm_connect *s;

	if ((s = calloc(1, sizeof(struct rnm_connect))) == NULL)
		return NULL;
	rnm_connect_structure_init(s);

	if (addr != NULL)
		strncpy(s->addr, addr, 20);
	if (id != NULL)
		rnm_idstr(&s->id, id);
	s->port = port;
	rtsd_debug("create thread");
	pthread_create(&s->thread, NULL, &rnm_connect_thread, (void*) s);
	return s;
}

struct rnm_connect *rnm_connect_subscribe(const char *addr, int port, const char *id, void (*cb)(void *), void *arg)
{
	struct rnm_connect *s;

	if ((s = rnm_connect(addr, port, id)) == NULL)
		return NULL;
	s->connect_cb = cb;
	s->connect_arg = arg;
	return s;
}

int rnm_wait_for_clientlist(struct rnm_connect *s, int timeout)
{
	struct timespec to;

	clock_gettime(CLOCK_MONOTONIC, &to);
	to.tv_sec += timeout;

	pthread_mutex_lock(&s->clientlist_mutex);
	while (s->clientlist_wait) {
		rtsd_debug("wait for clients list");
		if (pthread_cond_timedwait(&s->clientlist_cond, &s->clientlist_mutex, &to) == ETIMEDOUT) {
			pthread_mutex_unlock(&s->clientlist_mutex);
			return -ETIMEDOUT;
		}
	}
	pthread_mutex_unlock(&s->clientlist_mutex);
	return 0;
}

struct rnm_client_info *rnm_request_clientslist(struct rnm_connect *s, int *count, int timeout)
{
	struct rnm_header packet;


	if (s->clients_info == NULL) {
		s->clients_info = calloc(RNM_CLIENT_MAXIMUM, sizeof(struct rnm_client_info));
		if (s->clients_info == NULL) {
			return NULL;
		}
	}
	if (s->socketfd < 0) {
		*count = 0;
		return NULL;
	}

	packet.id.c[0] = ++s->clientlist_sequence;
	packet.magic = RNM_PACKET_MAGIC;
	packet.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.type = RNM_TYPE_CLIENT_LIST;
	packet.data_size = 0;
	s->clientlist_recv = 0;
	s->clientlist_wait_packet = 0;
	s->clientlist_wait = 1;

	rn_blocking_send(s->socketfd, &packet, sizeof(struct rnm_header), MSG_NOSIGNAL);
	rtsd_debug("request clients info");

	if (rnm_wait_for_clientlist(s, timeout))
		return NULL;

	*count = s->clientlist_recv;
	return s->clients_info;
}

void rnm_free_clientslist(struct rnm_connect *s)
{
	free(s->clients_info);
	s->clients_info = NULL;
}

int rnm_wait_for_eventlist(struct rnm_connect *s, int timeout)
{
	struct timespec to;

	clock_gettime(CLOCK_MONOTONIC, &to);
	to.tv_sec += timeout;

	pthread_mutex_lock(&s->eventlist_mutex);
	while (s->eventlist_wait) {
		rtsd_debug("wait for events list");
		if (pthread_cond_timedwait(&s->eventlist_cond, &s->eventlist_mutex, &to) == ETIMEDOUT) {
			pthread_mutex_unlock(&s->eventlist_mutex);
			return -ETIMEDOUT;
		}
	}
	pthread_mutex_unlock(&s->eventlist_mutex);
	return 0;
}

struct rnm_event_info *rnm_request_eventslist(struct rnm_connect *s, int *count, int timeout)
{
	struct rnm_header packet;

	if (s->events_info == NULL) {
		s->events_info = calloc(RNM_EVENT_MAXIMUM, sizeof(struct rnm_event_info));
		if (s->events_info == NULL) {
			return NULL;
		}
	}

	if (s->socketfd < 0) {
		*count = 0;
		return NULL;
	}

	packet.id.c[0] = ++s->eventlist_sequence;
	packet.magic = RNM_PACKET_MAGIC;
	packet.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.type = RNM_TYPE_EVENT_LIST;
	packet.data_size = 0;
	s->eventlist_recv = 0;
	s->eventlist_wait_packet = 0;
	s->eventlist_wait = 1;

	rn_blocking_send(s->socketfd, &packet, sizeof(struct rnm_header), MSG_NOSIGNAL);
	rtsd_debug("request events info");

	if (rnm_wait_for_eventlist(s, timeout))
		return NULL;

	*count = s->eventlist_recv;
	return s->events_info;
}

void rnm_free_eventslist(struct rnm_connect *s)
{
	free(s->events_info);
	s->events_info = NULL;
}

int rnm_isconnect(struct rnm_connect *s)
{
	if ((s == NULL) || (s->socketfd < 0)) return 0;
	else
		return 1;
}

void rnm_disconnect(struct rnm_connect *s)
{
	s->onexit = 1;
	if (s->connect_cb_status == 1)
		pthread_cancel(s->connect_thread);
	rn_tcpclient_close(s->socketfd);
	pthread_join(s->thread, NULL);
	if (s->clients_info)
		rnm_free_clientslist(s);
	if (s->events_info)
		rnm_free_eventslist(s);
	free(s);
}

struct rnm_connect_channel *rnm_find_free_channel(struct rnm_connect *s)
{
	int i;

	for (i = 0; i < RNM_CHANNEL_MAXIMUM; i++)
		if (s->channels[i].id.i[0] == -1) {
			return &s->channels[i];
		}
	return NULL;
}

int rnm_wait_for_ticket(struct rnm_connect *s, int timeout)
{
	struct timespec to;

	clock_gettime(CLOCK_MONOTONIC, &to);
	to.tv_sec += timeout;

	pthread_mutex_lock(&s->ticket_mutex);
	while (s->ticket_wait)
		if (pthread_cond_timedwait(&s->ticket_cond, &s->ticket_mutex, &to) == ETIMEDOUT) {
			pthread_mutex_unlock(&s->ticket_mutex);
			return -ETIMEDOUT;
		}
	pthread_mutex_unlock(&s->ticket_mutex);
	return 0;
}

int rnm_channel_anons(struct rnm_connect *s, const char *id, int flags, int port)
{
	struct rnm_connect_channel *c;

	c = rnm_find_free_channel(s);
	c->ticket.ip = 0;
	c->ticket.port = port;
	c->ticket.flags = flags;
	rnm_idstr(&c->id, id);

	if (s->socketfd >= 0)
		rnm_client_send_channel_anons(s, &c->id, &c->ticket);

	return 0;
}

int rnm_channel_request(struct rnm_connect *s, const char *id, struct rnm_channel_ticket *ticket)
{
	struct rnm_packet packet;
	int size = sizeof(struct rnm_header);

	if (s->socketfd < 0)
		return -EBADFD;

	rnm_idstr(&packet.header.id, id);
	s->ticket_id = packet.header.id;
	packet.header.magic = RNM_PACKET_MAGIC;
	packet.header.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.header.type = RNM_TYPE_CHANNEL | RNM_CHANNEL_REQUEST;
	packet.header.data_size = 0;

	rn_blocking_send(s->socketfd, &packet, size, MSG_NOSIGNAL);
	rtsd_debug("sent request");
	if (rnm_wait_for_ticket(s, 3))
		return -ETIMEDOUT;

	memcpy(ticket, &s->ticket_data, sizeof(struct rnm_channel_ticket));

	if (ticket->ip == htonl(INADDR_LOOPBACK))
		ticket->ip = inet_addr(s->addr);

	return 0;
}

int rnm_wait_for_channellist(struct rnm_connect *s, int timeout)
{
	struct timespec to;

	clock_gettime(CLOCK_MONOTONIC, &to);
	to.tv_sec += timeout;

	pthread_mutex_lock(&s->channellist_mutex);
	while (s->channellist_wait) {
		rtsd_debug("wait for channels list");
		if (pthread_cond_timedwait(&s->channellist_cond, &s->channellist_mutex, &to) == ETIMEDOUT) {
			pthread_mutex_unlock(&s->channellist_mutex);
			return -ETIMEDOUT;
		}
	}
	pthread_mutex_unlock(&s->channellist_mutex);
	return 0;
}

struct rnm_channel_info *rnm_request_channelslist(struct rnm_connect *s, int *count, int timeout)
{
	struct rnm_header packet;
	int i;

	if (s->channels_info == NULL) {
		s->channels_info = calloc(RNM_CHANNEL_MAXIMUM, sizeof(struct rnm_channel_info));
		if (s->channels_info == NULL) {
			return NULL;
		}
	}

	if (s->socketfd < 0) {
		*count = 0;
		return NULL;
	}

	packet.id.c[0] = ++s->channellist_sequence;
	packet.magic = RNM_PACKET_MAGIC;
	packet.magic_data = RNM_PACKET_MAGIC_DATA;
	packet.type = RNM_TYPE_CHANNEL_LIST;
	packet.data_size = 0;
	s->channellist_recv = 0;
	s->channellist_wait_packet = 0;
	s->channellist_wait = 1;

	rn_blocking_send(s->socketfd, &packet, sizeof(struct rnm_header), MSG_NOSIGNAL);
	rtsd_debug("request channels info");

	if (rnm_wait_for_channellist(s, timeout))
		return NULL;

	for (i = 0; i < s->channellist_recv; i++) {
		if ((s->channels_info[i].ip == htonl(INADDR_LOOPBACK)) && (s->addr != NULL) && (*s->addr != 0))
			s->channels_info[i].ip = inet_addr(s->addr);
	}
	*count = s->channellist_recv;
	return s->channels_info;

}

void rnm_free_channelslist(struct rnm_connect *s)
{
	if (s->channels_info != NULL) {
		free(s->channels_info);
		s->channels_info = NULL;
	}
}

int rnm_ssdp_msearch (char *buffer, int size)
{
	return (snprintf(buffer, size, "%sHOST:%s:%d\r\nMAN:\"ssdp:discover\"\r\nMX:1\r\nST:%s\r\nUSER-AGENT:unknow\r\n\r\n",
		ssdp_headers.msearch, ssdp_network.ip, ssdp_network.port, rnm_ssdp_field.name));
}

int rnm_find_server(char *addr, int *port)
{
	int fd;
	struct sockaddr_in gaddr;
	struct sockaddr_in ssdp_server_addr;
	socklen_t ssdp_server_addr_len = sizeof (struct sockaddr_in);
	char ssdp_buffer[SSDP_PACKET_SIZE];
	int packet_size = 0;
	int ssdp_response_size = strlen(ssdp_headers.response);
	char *location;
	int addr_count = 0;
	int _port = 0;
	
	fd = rn_udpmulticast_open(NULL, ssdp_network.port);
	rn_add_multicast_group (fd, ssdp_network.ip, NULL);
	rn_set_multicast_group (&gaddr, ssdp_network.ip, ssdp_network.port);
	rn_set_rxtimeout(fd, 0, 500000);
	
	packet_size = rnm_ssdp_msearch (ssdp_buffer, SSDP_PACKET_SIZE);
	sendto (fd, ssdp_buffer, packet_size, 0, (struct sockaddr *) &gaddr,  sizeof(struct sockaddr_in));
			
	while (1) {
		rtsd_debug("wait for ssdp packet");
		packet_size = recvfrom(fd, ssdp_buffer, SSDP_PACKET_SIZE, 0, (struct sockaddr *) &ssdp_server_addr, &ssdp_server_addr_len);
		if (packet_size < 0) break;
		if (packet_size < ssdp_response_size) continue;
		
		if (memcmp(ssdp_buffer, ssdp_headers.response, ssdp_response_size))
			continue;
		if (strstr(ssdp_buffer, rnm_ssdp_field.name) == NULL)
			continue;
		location = strstr(ssdp_buffer,"LOCATION:");
		if (location == NULL) 
			continue;
		while (*location != ':') location++;
		location++;
		while (*location != ':') {
			*addr++ = *location++;
			if (addr_count>INET_ADDRSTRLEN) 
				break;
		}
		location++;
		while (isdigit (*location)) {
			_port *= 10;
			_port += *location - '0';
			location++;
		}
		*port = _port;
		inet_ntop(AF_INET, &(ssdp_server_addr.sin_addr), addr, INET_ADDRSTRLEN);
		rn_udpserver_close (fd);
		return 0;
	}
	rn_udpserver_close (fd);
	return -1;
}
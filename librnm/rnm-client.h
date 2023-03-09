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
#ifndef __RNM_CLIENT__
#define __RNM_CLIENT__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rnm-types.h>

	
struct rnm_connect *rnm_connect(const char *addr, int port, const char *id, void (*cb)(void *), void *args);
struct rnm_connect *rnm_connect_simple(const char *addr, int port, const char *id);
struct rnm_connect *rnm_udpconnect(const char *addr, int port, const char *id);

int rnm_find_server (char *addr, int *port);
int rnm_isconnect(struct rnm_connect *s);
int rnm_connect_wait(struct rnm_connect *s, int timeout);
void rnm_disconnect(struct rnm_connect *s);

int rnm_define(struct rnm_connect *s, const char *id, int flags);
int rnm_undefine(struct rnm_connect *s, const char *id);
int rnm_subscribe_event(struct rnm_connect *s, int flags, const char *id, void (*cb)(void *, char *, void *, int), void *args);
int rnm_unsubscribe_event(struct rnm_connect *s, const char *id);

int rnm_read(struct rnm_connect *s, int flags, const char *id, void *data, int *data_size);
int rnm_getvar_int(struct rnm_connect *s, int flags, const char *id, int *data);
int rnm_getvar_long(struct rnm_connect *s, int flags, const char *id, long *data);
int rnm_getvar_float(struct rnm_connect *s, int flags, const char *id, float *data);
int rnm_getvar_double(struct rnm_connect *s, int flags, const char *id, double *data);
int rnm_getvar_str(struct rnm_connect *s, int flags, const char *id, char *data, int size);

int rnm_wait(struct rnm_connect *s, int flags, const char *id, void *data, int *data_size);
int rnm_wait_int(struct rnm_connect *s, int flags, const char *id, int *data);
int rnm_wait_long(struct rnm_connect *s, int flags, const char *id, long *data);
int rnm_wait_float(struct rnm_connect *s, int flags, const char *id, float *data);
int rnm_wait_double(struct rnm_connect *s, int flags, const char *id, double *data);
int rnm_wait_str(struct rnm_connect *s, int flags, const char *id, char *data, int size);
int rnm_wait_command(struct rnm_connect *s, int flags, const char *id, char *data);
int rnm_wait_response(struct rnm_connect *s, int flags, const char *id, char *data, int size);

int rnm_write(struct rnm_connect *s, int flags, const char *id, void *data, int data_size);
int rnm_setvar_int(struct rnm_connect *s, int flags, const char *id, int data);
int rnm_setvar_long(struct rnm_connect *s, int flags, const char *id, long data);
int rnm_setvar_float(struct rnm_connect *s, int flags, const char *id, float data);
int rnm_setvar_double(struct rnm_connect *s, int flags, const char *id, double data);
int rnm_setvar_str(struct rnm_connect *s, int flags, const char *id, const char *data);
int rnm_send_command(struct rnm_connect *s, int flags, const char *id, void *data, int data_size);
int rnm_send_response(struct rnm_connect *s, int flags, const char *id, void *data, int data_size);
int rnm_event(struct rnm_connect *s, int flags, const char *id);

struct rnm_client_info *rnm_request_clientslist(struct rnm_connect *s, int *count, int timeout);
void rnm_free_clientslist(struct rnm_connect *s);
struct rnm_event_info *rnm_request_eventslist(struct rnm_connect *s, int *count, int timeout);
void rnm_free_eventslist(struct rnm_connect *s);

int rnm_channel_anons(struct rnm_connect *s, const char *id, int flags, int port);
int rnm_channel_request(struct rnm_connect *s, const char *id, struct rnm_channel_ticket *ticket);
struct rnm_channel_info *rnm_request_channelslist(struct rnm_connect *s, int *count, int timeout);

#ifdef __cplusplus
}
#endif

#endif //__RNM_CLIENT__
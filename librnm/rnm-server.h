/**************************************************************
* (C) Copyright 2017
* RTSoft
* Russia
* All rights reserved.
*
* Description: Library of network variables and channels
* Author: Alexander Krapivniy (akrapivny@dev.rtsoft.ru)
***************************************************************/

#ifndef __RNM_SERVER__
#define __RNM_SERVER__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rnm-types.h>

struct rnm_server *rnm_server_create(const char *addr, int port, const char *id);

int rnm_server_define(struct rnm_server *s, const char *id, int type, void *data, int size);
int rnm_server_undefine(struct rnm_server *s, const char *id);

int rnm_server_subscribe_event(struct rnm_server *s, int flags, const char *id, void (*cb)(void *, char *, void *, int), void *args);
void rnm_server_unsubscribe_event(struct rnm_server *s, const char *id);

int rnm_server_read(struct rnm_server *s, int flags, const char *id, void *data, int *data_size);
int rnm_server_getint(struct rnm_server *s, int flags, const char *id, int *data);
int rnm_server_getlong(struct rnm_server *s, int flags, const char *id, long *data);
int rnm_server_getfloat(struct rnm_server *s, int flags, const char *id, float *data);
int rnm_server_getdouble(struct rnm_server *s, int flags, const char *id, double *data);
int rnm_server_getstr(struct rnm_server *s, int flags, const char *id, char *data, int size);

int rnm_server_write(struct rnm_server *s, int flags, const char *id, void *data, int data_size);
int rnm_server_setint(struct rnm_server *s, int flags, const char *id, int data);
int rnm_server_setlong(struct rnm_server *s, int flags, const char *id, long data);
int rnm_server_setfloat(struct rnm_server *s, int flags, const char *id, float data);
int rnm_server_setdouble(struct rnm_server *s, int flags, const char *id, double data);
int rnm_server_setstr(struct rnm_server *s, int flags, const char *id, const char *data);

void rnm_server_stop(struct rnm_server *s);
void rnm_server_set_sync_offset(struct rnm_server *s, int ms);

void rnm_server_print_event(struct rnm_server * s);
int rnm_server_ssdp_create (struct rnm_server *s, char *address);


#ifdef __cplusplus
}
#endif

#endif //__RNM_SERVER__
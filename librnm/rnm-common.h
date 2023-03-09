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
#ifndef __RNM_COMMON__
#define __RNM_COMMON__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "rnm-types.h"


#define SSDP_PACKET_SIZE 1500

static struct {
	const char *msearch;
	const char *notify;
	const char *response;
} ssdp_headers = {
	.msearch = "M-SEARCH * HTTP/1.1\r\n",
	.notify = "NOTIFY * HTTP/1.1\r\n",
	.response = "HTTP/1.1 200 OK\r\n",
};

static struct {
	const char *ip;
	const int port;
} ssdp_network = {
	.ip = "239.255.255.250",
	.port = 1900,
};

static struct {
	const char *name;
} rnm_ssdp_field = {
	.name = "rnm-server",
};
	
#define RNM_COMPARE_ID(a,b) ((a[0]==b[0])&&(a[1]==b[1])&&(a[2]==b[2])&&(a[3]==b[3]))

static __attribute__((always_inline)) inline int rnm_idcmp (rnmid_t *a, rnmid_t *b)
{
	if (RNM_COMPARE_ID (a->i,b->i)) return 1; else return 0;
}

static __attribute__((always_inline)) inline void rnm_idcpy (rnmid_t *a, rnmid_t *b)
{
	a->i[0] = b->i[0];
	a->i[1] = b->i[1];
	a->i[2] = b->i[2];
	a->i[3] = b->i[3];
}

static __attribute__((always_inline)) inline void rnm_idstr (rnmid_t *a, const char *b)
{
	char *s = a->c;
	int i = sizeof (rnmid_t);
	a->i[0] = 0; a->i[1] = 0; a->i[2] = 0; a->i[3] = 0;
	while (--i && (*s++ = *b++ )!= 0) ;
}

static __attribute__((always_inline)) inline int rnm_get_size_by_type(int type)
{
	switch (type & RNM_TYPE_VAR_MASK) {
	case RNM_TYPE_VAR_FLOAT:
	case RNM_TYPE_VAR_INT: return 4;
	case RNM_TYPE_VAR_DOUBLE:
	case RNM_TYPE_VAR_LONG: return 8;
	}
	return 0;
}

static __attribute__((always_inline)) inline void rnm_fill_header (struct rnm_header *p, rnmid_t *id, uint32_t type)
{
        rnm_idcpy(&p->id, id);
        p->magic = RNM_PACKET_MAGIC;
        p->magic_data = RNM_PACKET_MAGIC_DATA;
        p->type = type;
}

static __attribute__((always_inline)) inline void rnm_fill_header_request_str (struct rnm_header *p, const char *cid, uint32_t type)
{
        rnm_idstr(&p->id, cid);
        p->magic = RNM_PACKET_MAGIC;
        p->magic_data = RNM_PACKET_MAGIC_DATA;
        p->data_size = 0;
        p->type = type;
}

static __attribute__((always_inline)) inline void rnm_fill_header_request_id (struct rnm_header *p, rnmid_t *id, uint32_t type)
{
        rnm_idcpy(&p->id, id);
        p->magic = RNM_PACKET_MAGIC;
        p->magic_data = RNM_PACKET_MAGIC_DATA;
        p->data_size = 0;
        p->type = type;
}

#ifdef __cplusplus
}
#endif



#endif //__RNM_COMMON__
/**************************************************************
* (C) Copyright 2017
* RTSoft
* Russia
* All rights reserved.
*
* Description: Library of network variables and channels
* Author: Alexander Krapivniy (akrapivny@dev.rtsoft.ru)
***************************************************************/

#ifndef __RN_H__
#define __RN_H__

#ifdef __cplusplus
extern "C" {
#endif
#include <arpa/inet.h>

int rn_tcpserver_open(const char *addr, int port);
void rn_tcpserver_close(int socketfd);
int rn_udpserver_open(const char *addr, int port);
void rn_udpserver_close(int socketfd);

int rn_udpmulticast_open(const char *addr, int port);

int rn_tcpclient_open(const char *addr, int port);
void rn_tcpclient_close(int socketfd);
int rn_udpclient_open(const char *addr, int port, struct sockaddr_in *serveraddr);
void rn_udpclient_close(int socketfd);

void rn_set_nonblocking_socket(int socketfd, int rx_size, int tx_size);
int rn_blocking_send (int sock, void *buffer, int len, int flags);
void rn_set_keepalive(int socketfd, int idle, int count);
void rn_set_rxtimeout(int socketfd, int s, int us);
int rn_add_multicast_group(int socketfd, const char *maddr, const char *addr);
void rn_set_multicast_group(struct sockaddr_in *gaddr, const char *maddr, int port);

#ifdef __cplusplus
}
#endif

#endif //__RN_H__
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
int rn_add_multicast_route(char *ifname);


#ifdef __cplusplus
}
#endif

#endif //__RN_H__
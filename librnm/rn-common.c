/**************************************************************  
 * Description: Library of network variables and channels
 * Copyright (c) 2020 Alexander Krapivniy (a.krapivniy@gmail.com)
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

#include <stdio.h> 
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <net/if.h>


#define MODULE_NAME "rtsnet-common"
#include <rnm-debug.h>
#undef rtsd_debug
#define rtsd_debug(fmt,args...)

#define RN_MULTICAST_NET "224.0.0.0"

void rn_set_nonblocking_socket(int socketfd, int rx_size, int tx_size)
{
	int flags;

	flags = fcntl(socketfd, F_GETFL, 0);
	fcntl(socketfd, F_SETFL, flags | O_NONBLOCK);

	if (rx_size) {
		if (setsockopt(socketfd, IPPROTO_TCP, SO_RCVBUF, (const char*) &rx_size, sizeof(rx_size)) < 0) {
			//			rtsd_error("can't setting tcp socket receive buffer:%s", strerror(errno));
		}
	}

	if (tx_size) {
		if (setsockopt(socketfd, IPPROTO_TCP, SO_SNDBUF, (const char*) &tx_size, sizeof(tx_size)) < 0) {
			//			rtsd_error("can't setting tcp socket transmit buffer:%s", strerror(errno));
		}
	}
}

void rn_set_rxtimeout(int socketfd, int s, int us)
{
	struct timeval tv;
	tv.tv_sec = s;
	tv.tv_usec = us;
	if (setsockopt(socketfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		rtsd_error("can't setting socket timeout:%s", strerror(errno));
	}
}

int rn_add_multicast_group(int socketfd, const char *maddr, const char *addr)
{
	struct ip_mreq group;

	group.imr_multiaddr.s_addr = inet_addr(maddr);
	if ((addr != NULL) && (*addr != 0)) group.imr_interface.s_addr = inet_addr(addr);
	else group.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(socketfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *) &group, sizeof(group)) < 0) {
		rtsd_error("can't add to multicast group:%s", strerror(errno));
		return errno;
	}
	return 0;
}

void rn_set_multicast_group(struct sockaddr_in *gaddr, const char *maddr, int port)
{
	memset(gaddr, 0, sizeof(struct sockaddr_in));
	gaddr->sin_family = AF_INET;
	gaddr->sin_addr.s_addr = inet_addr(maddr);
	gaddr->sin_port = htons(port);
}

int rn_add_network_route_dev(char *net, char *mask, char *dev)
{
	int fd;
	struct rtentry route;
	struct sockaddr_in *addr;

	if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) == 0) {
		rtsd_error("can't open control socket:%s", strerror(errno));
		return errno;
	}

	memset(&route, 0, sizeof( route));
	addr = (struct sockaddr_in *) &route.rt_gateway;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = 0;

	addr = (struct sockaddr_in*) &route.rt_dst;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(net);

	addr = (struct sockaddr_in*) &route.rt_genmask;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(mask);

	route.rt_flags = RTF_UP;
	route.rt_metric = 0;
	route.rt_dev = dev;

	if (ioctl(fd, SIOCADDRT, &route)) {
		close(fd);
		rtsd_error("can't add network:%s", strerror(errno));
		return errno;
	}
	close(fd);
	return 0;
}

int rn_add_multicast_route(char *ifname)
{
	struct ifaddrs *ifaddr, *ifa;

	if (ifname != NULL) {
		return (rn_add_network_route_dev(RN_MULTICAST_NET, RN_MULTICAST_NET, ifname));
	}

	if (getifaddrs(&ifaddr) == -1) {
		rtsd_error("can't get network list:%s", strerror(errno));
		return -1;
	}
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_flags & IFF_LOOPBACK) continue;
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_PACKET) continue;
		if (!memcmp (ifa->ifa_name, "dummy", 5)) continue;
		if (!memcmp (ifa->ifa_name, "lo", 2)) continue;
		rn_add_network_route_dev (RN_MULTICAST_NET, RN_MULTICAST_NET, ifa->ifa_name);
	}
	freeifaddrs(ifaddr);
	return 0;
}

void rn_set_keepalive(int socketfd, int idle, int count)
{
	int one = 1;

	if (setsockopt(socketfd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)) < 0) {
		rtsd_error("can't setting tcp socket keepalive:%s", strerror(errno));
	}
	if (setsockopt(socketfd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0) {
		rtsd_error("can't setting tcp socket keepalive idle time:%s", strerror(errno));
	}
	if (setsockopt(socketfd, IPPROTO_TCP, TCP_KEEPINTVL, &one, sizeof(one)) < 0) {
		rtsd_error("can't setting tcp socket keepalive interval time:%s", strerror(errno));
	}
	if (setsockopt(socketfd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count)) < 0) {
		rtsd_error("can't setting tcp socket keepalive count:%s", strerror(errno));
	}
}

int rn_blocking_send(int sock, void *buffer, int len, int flags)
{
	int ssent;
	unsigned char *_buffer = (unsigned char *) buffer;

	while (len > 0) {
		ssent = send(sock, _buffer, len, flags);
		if (ssent == -1)
			return -1;

		_buffer += ssent;
		len -= ssent;
	}
	return 0;
}

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <pthread.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <rnm-client.h>

#define MODULE_NAME "rnmmon"
#include <rnm-debug.h>
#undef rtsd_debug
#define rtsd_debug(fmt,args...)


static struct option long_options[] = {
	{"address", required_argument, 0, 'a'},
	{"port", required_argument, 0, 'p'},
	{"period", required_argument, 0, 'n'},
	{"one", no_argument, 0, '1'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};
static const char *short_options = "hp:a:n:1";

int main(int argc, char** argv)
{
	struct rnm_connect *rnm_server;
	int port = 0;
	char address[32] = "";
	int count;
	int i;
	struct rnm_event_info *events_info;
	struct rnm_client_info *clients_info;
	struct rnm_channel_info *channels_info;
	int period = 1000000;
	int watch = 1;
	char str[15];
	struct in_addr in_addr;
	char ch;

	int long_index;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, short_options,
		long_options, &long_index)) != -1) {
		switch (opt) {
		case 'p':
			port = atoi(optarg);
			break;
		case 'n':
			period = atoi(optarg) * 1000;
			break;
		case 'a':
			strncpy(address, optarg, 32);
			break;
		case '1':
			watch = 0;
			break;
		case 'h':
			printf("Usage: ./rnmmon \n");
			printf(" Additional options:\n");
			printf("\t-a,--address - server IP address \n");
			printf("\t-p,--port - server port \n");
			printf("\t-n,--period - requests period (ms) \n");
			printf("\t-1,--one - show list and exit \n");
			printf(" Examples:\n");
			printf("\t./rnmctrl -p 100\n");
			printf("\t./rnmctrl --address 10.100.1.1 -p 4443\n");
			exit(1);
			break;
		default:
			break;
		}
	}

	rnm_server = rnm_connect_simple(address, port, "rnm-monitor");
	

	printf("Wait for connect to %s:%d \n", address, port);
	rnm_connect_wait (rnm_server, 30);

	do {
		events_info = rnm_request_eventslist(rnm_server, &count, 5);
		if (events_info == NULL) continue;
		printf("Event statistics\n");
		printf("|%31s|%15s|%7s|%7s|%7s\n", "id", "value", "count", "prod.", "cons.");

		for (i = 0; i < count; i++) {
			switch (events_info[i].type) {
			case RNM_TYPE_VAR_INT:
				ch = *(char *) events_info[i].short_data;
				if (isprint(ch))
					snprintf(str, 15, "%d/%c", *(int *) events_info[i].short_data, *(char *) events_info[i].short_data);
				else
					snprintf(str, 15, "%d", *(int *) events_info[i].short_data);
				break;
			case RNM_TYPE_VAR_LONG: snprintf(str, 15, "%ld", *(long *) events_info[i].short_data);
				break;
			case RNM_TYPE_VAR_FLOAT: snprintf(str, 15, "%f", *(float *) events_info[i].short_data);
				break;
			case RNM_TYPE_VAR_DOUBLE: snprintf(str, 15, "%lf", *(double *) events_info[i].short_data);
				break;
			case RNM_TYPE_VAR_STRING: 
					events_info[i].short_data[events_info[i].data_size] = 0;
					snprintf(str, 15, "%s", (char *) events_info[i].short_data);
				break;
			default: snprintf(str, 10, "not support");
				break;
			}
			printf("|%31s|%15s|%7d|%7d|%7d\n", (char *) &events_info[i].id, str, events_info[i].count, events_info[i].producers_count, events_info[i].consumers_count);
		}

		clients_info = rnm_request_clientslist(rnm_server, &count, 5);
		if (clients_info == NULL) continue;
		printf("Client statistics\n");
		printf("|%31s|%7s|%7s|%7s|%7s|%7s\n", "id", "rx pkt", "tx pkt", "subscr", "write", "ip");
		for (i = 0; i < count; i++) {
			in_addr.s_addr = clients_info[i].ip;
			printf("|%31s|%7d|%7d|%7d|%7d|%7s\n", (char *) &clients_info[i].id, clients_info[i].rx_event_count, clients_info[i].tx_event_count, clients_info[i].event_subscribe, clients_info[i].event_write,
				inet_ntoa(in_addr));
		}
		channels_info = rnm_request_channelslist(rnm_server, &count, 5);
		if (channels_info == NULL) continue;
		printf("Channel statistics\n");
		printf("|%20s|%11s|%7s|%7s|%7s\n", "id", "ip", "port", "tickets", "prod");
		for (i = 0; i < count; i++) {
			in_addr.s_addr = channels_info[i].ip;
			printf("|%20s|%11s|%7d|%7d|%7d\n", (char *) &channels_info[i].id, inet_ntoa(in_addr), channels_info[i].port,
				channels_info[i].request_count, channels_info[i].anons_count);
		}
		usleep(period);
	} while (watch);


	return 0;
}

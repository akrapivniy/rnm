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
#include <rnm-server.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

#define MODULE_NAME "rnm-test-server"
#include <rnm-debug.h>


struct timespec client_time[8];
int client_number = 0;
int client_count = 0;
int server_count = 0;
int server_count_copy = 0;

struct client_data {
	int count;
	struct timespec time;
};

int count = 0;


void client_cb(void *args, char *id, void *data, int size)
{
	int new_count = *(int *)data;

	if (new_count != count + 1)
				printf ("E");
	count = new_count;
}


void speed_cb(void *args, char *id, void *data, int size)
{
	struct client_data *cd = data;
	int i;

	if (size != sizeof(struct client_data)) {
		rtsd_error("event data");
	}
	rtsd_debug("data %d", cd->count);
	if (cd->count > client_count) {
		printf("%02d(%02d) -", client_count, client_number);
		for (i = 1; i < client_number; i++) {
			printf("%d[%6ld.%6ld] ", i, (client_time[0].tv_sec - client_time[i].tv_sec), (client_time[0].tv_nsec - client_time[i].tv_nsec) / 1000);
		}
		printf("-\n");
		client_count = cd->count;
		client_number = 0;
	}
	if (client_count != cd->count) return;
	client_time[client_number & 7] = cd->time;
	client_number = (client_number + 1)&0x07;
}

int main()
{
	struct rnm_server *s;
	
	rtsd_info("creating server...");
	s = rnm_server_create(NULL, 4444, "test");
	if (s == NULL) {
		rtsd_error("server create");
		return -1;
	}
	rnm_server_ssdp_create (s, "rnm.com", 1);
	rtsd_info("defining variables...");
	rnm_server_define(s, "client_count", RNM_TYPE_VAR_INT, NULL, 0);
	rnm_server_define(s, "server_count", RNM_TYPE_VAR_INT, NULL,0);
	rnm_server_define(s, "client_string", RNM_TYPE_VAR_STRING, NULL,0);
	rnm_server_subscribe_event (s, RNM_TYPE_VAR_INT, "client_count", client_cb, NULL);

	rtsd_info("main loop...");
	while (1) {
		sleep (1);
	//	rnm_server_write(s, RNM_TYPE_VAR_INT, "server_count", &server_count, 0);
		server_count++;
	}
	rnm_server_stop(s);
}

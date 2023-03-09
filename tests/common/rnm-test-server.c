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

void cb(void *args, char *id, void *data, int size)
{
	struct client_data *cd = data;

	if (size != sizeof(struct client_data)) {
		rtsd_error("event data");
	}
	rtsd_debug("data %d", cd->count);
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
	rnm_server_define(s, "count", RNM_TYPE_VAR_INT, NULL,0);
	rnm_server_define(s, "0123456789012345678901234567890123456789012345", RNM_TYPE_VAR_INT, NULL,0);


	rtsd_info("subscribing enent...");
	rnm_server_subscribe_event(s, 0, "count", cb, s);
	rnm_server_subscribe_event(s, 0, "0123456789012345678901234567890123456789012345", cb, s);
	rtsd_info("main loop...");
	while (1) {
		rnm_server_print_event (s);
		usleep(500000);
	}


	rnm_server_stop(s);
}

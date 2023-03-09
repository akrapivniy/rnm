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
#include <rnm-client.h>
#include <stdint.h>
#include <unistd.h>
#include <libconfig.h>
#include <time.h>

#define MODULE_NAME "rnm-test-client"
#include <rnm-debug.h>

void client_cb(void *args, char *id, void *data, int size)
{
	rtsd_error("CALLBACK is called!");
}

int main()
{
	config_t cfg;
	const char *ipaddress;
	char *default_ipaddress = "127.0.0.1";
	struct rnm_connect *s;
	int server_count;
	int i;
	char addr[20];
	int port;
	

	config_init(&cfg);

	if (!config_read_file(&cfg, "client.config")) {
		rtsd_error("%s:%d - %s\n", config_error_file(&cfg),
			config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return(-1);
	}

	if (!config_lookup_string(&cfg, "ipaddress", &ipaddress))
		ipaddress = default_ipaddress;

	rnm_find_server (addr, &port);
	rtsd_debug("connecting to %s:%d", addr, port);
	
	while (1) {
		rtsd_debug("connecting to %s", ipaddress);
		s = rnm_connect((char *) ipaddress, 4444, "test_client", NULL, NULL);
		rnm_subscribe_event(s, RNM_TYPE_VAR_INT, "count", client_cb, s);
		rnm_channel_anons (s, "debug", 0, 5555);

		for (i = 0; i < 10; i++) {
			rnm_setvar_int(s, 0, "count", 0);
			rnm_getvar_int(s, 0, "count", &server_count);
			rtsd_debug("read value %d", server_count);
			sleep(1);
		}
		rnm_disconnect (s);
	}

	config_destroy(&cfg);
}

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
#include <test_tools.h>


int count = 0;
int packet_count = 0;

void client_cb(void *args, char *id, void *data, int size)
{
	int new_count = *(int *)data;
	struct rnm_connect *s = args;

	if (new_count != count + 1) 
		printf ("E");
	packet_count++;
	count = new_count;
}

void client_str_cb(void *args, char *id, void *data, int size)
{
	struct rnm_connect *s = args;

	packet_count++;
}


int main()
{
	struct rnm_connect *s = NULL;
	struct timespec start;
	struct timespec end;
	uint32_t start_count, stop_count;
	double timediff;
	uint32_t packet_diff;

	s = rnm_connect_simple(NULL, 0, "client3");
//	s = rnm_find_udpconnect("client3", 0);
	if (s == NULL) {
		rtsd_debug("error due connection");
		return -1;
	}
	rnm_subscribe_event(s, RNM_TYPE_VAR_INT, "client_count", client_cb, NULL);
	rnm_subscribe_event(s, RNM_TYPE_VAR_STRING, "client_string", client_str_cb, NULL);
	rnm_connect_wait (s, 0);
	
	while (1) {
		packet_count = 0;
		start_count = count;
		clock_gettime(CLOCK_MONOTONIC, &start);
		sleep (1);
		clock_gettime(CLOCK_MONOTONIC, &end);
		stop_count = count;
		packet_diff = packet_count;
		timediff = (double)tt_clockusdiff (start, end) / 100000;
		rtsd_debug ("Speed = %lf packet/sec, lost %i from %i ",  (double) packet_diff/ timediff, (stop_count - start_count) - packet_diff, packet_diff);
	}
	rnm_disconnect(s);
}

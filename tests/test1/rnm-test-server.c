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
	rnm_server_ssdp_create (s, "rnm.com");
	rtsd_info("defining variables...");
	rnm_server_define(s, "client_count", RNM_TYPE_VAR_INT, NULL, 0);
	rnm_server_define(s, "client_echo_count", RNM_TYPE_VAR_INT, NULL, 0);
	rnm_server_define(s, "server_count", RNM_TYPE_VAR_INT, NULL,0);
	rnm_server_define(s, "012345678901234567890123456789123456789012345", RNM_TYPE_VAR_INT, NULL,0);


	rtsd_info("subscribing enent...");
	rnm_server_subscribe_event(s, 0, "client_count", speed_cb, s);
	rnm_server_subscribe_event(s, 0, "012345678901234567890123456789123456789012345", speed_cb, s);
	rtsd_info("main loop...");
	while (1) {
//		rnm_server_print_event (s);
		rnm_server_write(s, RNM_TYPE_VAR_INT, "server_count", &server_count, 0);
		rnm_server_getint (s, 0, "server_count", &server_count_copy);
//		rtsd_info("server count %d : %d", server_count, server_count_copy);
		server_count++;
		usleep(500000);
	}


	rnm_server_stop(s);
}

#include <stdio.h>
#include <rnm-client.h>
#include <stdint.h>
#include <unistd.h>
#include <libconfig.h>
#include <time.h>

#define MODULE_NAME "rnm-test-client"
#include <rnm-debug.h>

void server_cb(void *args, char *id, void *data, int size)
{
	struct timespec time;
	int *mode = (int *) data;
	struct rnm_connect *s = args;
	int client_count = 0;

	clock_gettime(CLOCK_REALTIME, &time);
	rtsd_debug("event %d from client at %lu:%lu", *mode, time.tv_sec, time.tv_nsec);

	rnm_write(s, RNM_TYPE_VAR_INT, "client_count", &client_count, 4);
	rnm_write(s, RNM_TYPE_VAR_INT | RNM_TYPE_ECHO, "client_echo_count", &client_count, 4);
	client_count++;
}

void client_echo_cb(void *args, char *id, void *data, int size)
{
	rtsd_debug("server gets event");
}

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
		s = rnm_connect((char *) ipaddress, 4444, "client1");
		rnm_subscribe_event(s, RNM_TYPE_VAR_INT, "server_count", server_cb, s);
		rnm_subscribe_event(s, RNM_TYPE_VAR_INT, "client_echo_count", client_echo_cb, s);
		rnm_subscribe_event(s, RNM_TYPE_VAR_INT, "client_count", client_cb, s);
		rnm_channel_anons (s, "debug", 0, 5555);

		for (i = 0; i < 10; i++) {
			rnm_getvar_int(s, 0, "server_count", &server_count);
			rtsd_debug("read value %d", server_count);
			sleep(1);
		}
		rnm_disconnect (s);
	}

	config_destroy(&cfg);
}

#include <stdio.h>
#include <rnm-client.h>
#include <stdint.h>
#include <unistd.h>
#include <libconfig.h>
#include <time.h>

#define MODULE_NAME "rnm-test-monitor"
#include <rnm-debug.h>

int main()
{
	config_t cfg;
	const char *ipaddress;
	char *default_ipaddress = "127.0.0.1";
	struct rnm_connect *s;
	int count;
	struct rnm_event_info *events_info;
	struct rnm_client_info *clients_info;
	int i;
	char str[15];

	config_init(&cfg);

	if (!config_read_file(&cfg, "client.config")) {
		rtsd_error("%s:%d - %s\n", config_error_file(&cfg),
			config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return(-1);
	}

	if (!config_lookup_string(&cfg, "ipaddress", &ipaddress))
		ipaddress = default_ipaddress;

	rtsd_debug("connecting to %s", ipaddress);
	s = rnm_connect((char *) ipaddress, 3333, "client1");

	while (1) {
		events_info = rnm_request_eventslist(s, &count, 5);
		if (events_info == NULL) continue;
		printf("Event statistics\n");
		printf("|%15s|%15s|%7s|%7s|%7s\n", "id", "value", "count", "prod.", "cons.");
		
		for (i = 0; i < count; i++) {
			switch (events_info[i].type) {
			case RNM_TYPE_VAR_INT: snprintf(str, 15, "%d", *(int *) events_info[i].short_data);
				break;
			case RNM_TYPE_VAR_LONG: snprintf(str, 15, "%ld", *(long *) events_info[i].short_data);
				break;
			case RNM_TYPE_VAR_FLOAT: snprintf(str, 15, "%f", *(float *) events_info[i].short_data);
				break;
			case RNM_TYPE_VAR_DOUBLE: snprintf(str, 15, "%lf", *(double *) events_info[i].short_data);
				break;
			case RNM_TYPE_VAR_STRING: snprintf(str, 15, "%s", (char *) events_info[i].short_data);
				break;
			default: snprintf(str, 10, "not support");
				break;
			}
			printf("|%15s|%15s|%7d|%7d|%7d\n", (char *) &events_info[i].id, str, events_info[i].count, events_info[i].producers_count, events_info[i].consumers_count);
		}

		clients_info = rnm_request_clientslist(s, &count, 5);
		if (clients_info == NULL) continue;
		printf("Client statistics\n");
		printf("|%15s|%7s|%7s|%7s|%7s\n", "id", "rx pkt", "tx pkt", "subscr", "write");
		for (i = 0; i < count; i++) {
			printf("|%15s|%7d|%7d|%7d|%7d\n", (char *) &clients_info[i].id, clients_info[i].rx_event_count, clients_info[i].tx_event_count, clients_info[i].event_subscribe, clients_info[i].event_write);
		}
		sleep(1);
	}

	config_destroy(&cfg);
}

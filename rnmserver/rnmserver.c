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
#include <libconfig.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <arpa/inet.h>


#define MODULE_NAME "rnm-server"
#include <rnm-debug.h>
#include <rnm-server.h>
#include <rnm-client.h>

struct rnm_control {
	struct rnm_server *server;
	struct rnm_connect *client;
};

int rnm_register_variables(struct rnm_control *d, config_t *cfg)
{
	config_setting_t *dbx_variables_list, *dbx_variable;
	int variable_count = 0;
	char const *name, *type;
	int size, flags;
	char const *value_str;
	char str[RNM_VARIABLE_SIZE_MAXIMUM];
	int value_int;
	double value_double;
	float value_float;

	dbx_variables_list = config_lookup(cfg, "variables");
	if (dbx_variables_list == NULL) {
		rtsd_debug("can't find variables section in config");
		return -1;
	}
	while (1) {
		dbx_variable = config_setting_get_elem(dbx_variables_list, variable_count++);
		if (dbx_variable == NULL)
			break;

		if (!config_setting_lookup_string(dbx_variable, "name", &name)) {
			continue;
		}
		if (!config_setting_lookup_string(dbx_variable, "type", &type)) {
			continue;
		}
		size = 0;
		config_setting_lookup_int(dbx_variable, "size", &size);

		if (!strcmp(type, "empty"))
			flags = RNM_TYPE_VAR_EMPTY;
		else if (!strcmp(type, "int"))
			flags = RNM_TYPE_VAR_INT;
		else if (!strcmp(type, "long"))
			flags = RNM_TYPE_VAR_LONG;
		else if (!strcmp(type, "float"))
			flags = RNM_TYPE_VAR_FLOAT;
		else if (!strcmp(type, "double"))
			flags = RNM_TYPE_VAR_DOUBLE;
		else if (!strcmp(type, "string"))
			flags = RNM_TYPE_VAR_STRING;
		else if (!strcmp(type, "struct"))
			flags = RNM_TYPE_VAR_STRUCTURE;
		else if (!strcmp(type, "any"))
			flags = RNM_TYPE_VAR_ANY;
		else flags = RNM_TYPE_VAR_NOT_DEFINED;

		switch (flags) {
		case RNM_TYPE_VAR_INT:
		case RNM_TYPE_VAR_LONG:
			if (config_setting_lookup_int(dbx_variable, "value", &value_int)) {
				rtsd_info("register %d variable %s type int %s size %d value %d ", variable_count, name, type, size, value_int);
				rnm_server_define(d->server, name, flags, &value_int, size);
				continue;
			}
			break;
		case RNM_TYPE_VAR_FLOAT:
			if (config_setting_lookup_float(dbx_variable, "value", &value_double)) {
				value_float = value_double;
				rtsd_info("register %d variable %s type float %s size %d value %f ", variable_count, name, type, size, value_float);
				rnm_server_define(d->server, name, flags, &value_float, size);
				continue;
			}
			break;
		case RNM_TYPE_VAR_DOUBLE:
			if (config_setting_lookup_float(dbx_variable, "value", &value_double)) {
				rtsd_info("register %d variable %s type double %s size %d value %lf ", variable_count, name, type, size, value_double);
				rnm_server_define(d->server, name, flags, &value_double, size);
				continue;
			}
			break;
		case RNM_TYPE_VAR_STRING:
			if (config_setting_lookup_string(dbx_variable, "value", &value_str)) {
				strcpy(str, value_str);
				size = strlen(str);
				rtsd_info("register %d variable %s type string %s size %d value %s", variable_count, name, type, size, str);
				rnm_server_define(d->server, name, flags, str, size);
				continue;
			}
			break;
		}
		rtsd_info("register %d variable %s type %s size %d value undefine", variable_count, name, type, size);
		rnm_server_define(d->server, name, flags, NULL, size);
	}
	return 0;
}

int timespec2str(char *buf, int len, struct timespec *ts)
{
	int ret;
	struct tm t;

	tzset();
	if (localtime_r(&(ts->tv_sec), &t) == NULL)
		return 1;

	ret = strftime(buf, len, "%F %T", &t);
	if (ret == 0)
		return 2;
	len -= ret - 1;

	ret = snprintf(&buf[strlen(buf)], len, ".%06ld", ts->tv_nsec / 1000);
	if (ret >= len)
		return 3;

	return 0;
}

static struct option long_options[] = {
	{"configs-dir", required_argument, 0, 'c'},
	{"include-dir", required_argument, 0, 'i'},
	{"silent", no_argument, 0, 's'},
	{0, 0, 0, 0}
};
static const char *short_options = "sc:i:";

int main(int argc, char** argv)
{
	config_t cfg;
	struct rnm_control dbx;
	int server_port = 4444;
	int silent_mode = 0;

	char config_include_dir[255] = ".", config_filename[255] = "./rnm_config";
	int long_index;
	int opt = 0;
	config_init(&cfg);
	while ((opt = getopt_long(argc, argv, short_options,
		long_options, &long_index)) != -1) {
		switch (opt) {
		case 'c':
			strncpy(config_filename, optarg, 255);
			break;
		case 'i':
			strncpy(config_include_dir, optarg, 255);
			break;
		case 's':
			silent_mode = 1;
			break;
		default:
			break;
		}
	}
	config_set_include_dir(&cfg, config_include_dir);

	if (!config_read_file(&cfg, config_filename)) {
		rtsd_error("%s:%d - %s\n", config_error_file(&cfg),
			config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return(-1);
	}

	config_lookup_int(&cfg, "port", &server_port);

	dbx.server = rnm_server_create(NULL, server_port, "MI-server");
	rnm_register_variables(&dbx, &cfg);
	dbx.client = rnm_connect("127.0.0.1", server_port, "rnm server", NULL, NULL);

	while (1) {
		if (!silent_mode)
			rnm_server_print_event(dbx.server);
		usleep(1000000);
	}

	config_destroy(&cfg);
	rtsd_debug("exit");
	return 0;
}

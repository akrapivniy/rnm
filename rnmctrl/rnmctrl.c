/**************************************************************
* (C) Copyright 2017
* RTSoft
* Russia
* All rights reserved.
*
* Description: Application for write to network variables
* Author: Alexander Krapivniy (akrapivny@dev.rtsoft.ru)
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

#include <rnm-client.h>

#define MODULE_NAME "launcher"
#include <rnm-debug.h>


int connect_wait = 1;
pthread_mutex_t mutex;
pthread_cond_t cond;

void cb(void *args)
{
	pthread_mutex_lock(&mutex);
	connect_wait = 0;
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&mutex);
}

static struct option long_options[] = {
	{"write", required_argument, 0, 'w'},
	{"read", required_argument, 0, 'r'},
	{"port", required_argument, 0, 'p'},
	{"address", required_argument, 0, 'a'},
	{"int", optional_argument, 0, 'i'},
	{"char", optional_argument, 0, 'c'},
	{"empty", no_argument, 0, 'e'},
	{"string", optional_argument, 0, 's'},
	{"help", optional_argument, 0, 'h'},
	{0, 0, 0, 0}
};
static const char *short_options = "ehw:r:p:a:i:s:c:";

int main(int argc, char** argv)
{
	struct rnm_connect *rnm_server;
	char mode = 'r';
	int flag = 0;
	char value_size = 0;
	char var_name[33];
	int value_int = 0;
	char value_str[1024] = "";
	void *value = &value_str;
	int port = 4444;
	char address[32] = "127.0.0.1";

	int long_index;
	int opt = 0;

	while ((opt = getopt_long(argc, argv, short_options,
		long_options, &long_index)) != -1) {
		switch (opt) {
		case 'w':
			strncpy(var_name, optarg, 32);
			mode = 'w';
			break;
		case 'r':
			strncpy(var_name, optarg, 32);
			mode = 'r';
			break;
		case 'h':
			printf ("Usage: ./rnmctrl <operation> <variable name> <type> <value> \n");
			printf (" Operations:\n");
			printf ("\t-r, --read - read variable\n");
			printf ("\t-w, --write - write variable\n");
			printf (" Types:\n");
			printf ("\t-s,--string - string variable\n");
			printf ("\t-i,--int - integer variable\n");
			printf ("\t-c,--char - char variable\n");
			printf ("\t-e,--empty - empty variable\n");
			printf (" Additional options:\n");
			printf ("\t-a,--address - server IP address \n");
			printf ("\t-p,--port - server port \n");
			printf (" Examples:\n");
			printf ("\t./rnmctrl -r mode -c 0\n");
			printf ("\t./rnmctrl -w mode -c D\n");
			printf ("\t./rnmctrl -w mode -i 83\n");
			printf ("\t./rnmctrl -w mode -i 83 --address 10.100.1.1 -p 4443\n");
			
			exit (1);
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'a':
			strncpy(address, optarg, 32);
			break;
		case 'i':
			if (optarg) {
				value_int = atoi(optarg);
				value_size = 4;
				printf("args int  = [%d]\n", value_int);
			} else value_size = 0;
			flag = RNM_TYPE_VAR_INT;
			value = &value_int;
			break;
		case 'e':
			flag = RNM_TYPE_VAR_EMPTY;
			value = NULL;
			value_size = 0;
			break;
		case 'c':
			if (optarg) {
				value_int = optarg[0];
				value_size = 4;
				printf("args int  = [%d]\n", value_int);
			} else value_size = 0;
			flag = RNM_TYPE_VAR_INT;
			value = &value_int;
			break;
		case 's':
			if (optarg) {
				strncpy(value_str, optarg, 1024);
				value_size = strlen(value_str) + 1;
			} else value_size = 0;
			flag = RNM_TYPE_VAR_STRING;
			value = &value_str;
			break;
		default:
			break;
		}
	}

	rnm_server = rnm_connect_subscribe(address, port, "rnm-rw", cb, NULL);

	printf("Wait for connect to %s:%d \n", address, port);
	pthread_mutex_lock(&mutex);
	while (connect_wait)
		pthread_cond_wait(&cond, &mutex);
	pthread_mutex_unlock(&mutex);

	if (mode == 'w') {
		if (flag == RNM_TYPE_VAR_INT)
			printf("Write [%s] = [%d]:%d \n", var_name, value_int, value_size);
		else if (flag == RNM_TYPE_VAR_EMPTY)
			printf("Write [%s] event \n", var_name);
		else
			printf("Write [%s] = [%s]:%d \n", var_name, value_str, value_size);

		rnm_write(rnm_server, flag, var_name, value, value_size);
	} else if (mode == 'r') {
		if (flag == RNM_TYPE_VAR_INT) {
			rnm_getvar_int(rnm_server, 0, var_name, &value_int);
			printf("value dec [%d] hex [%x] char [%c] \n", value_int, value_int, value_int);
		} else {
			rnm_getvar_str(rnm_server, 0, var_name, value_str, 1024);
			printf("value str: %s \n", value_str);
		}
	}

	return 0;
}

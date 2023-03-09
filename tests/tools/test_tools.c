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
#define _GNU_SOURCE

#include <stddef.h>
#include <assert.h>
#include <string.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>


#include <sched.h>
#include <pthread.h>

#include <errno.h>
#include <termios.h>
#include "test_tools.h"
#include <time.h>
#include <sys/time.h>


static struct tt_stat *tt_zones[32];
static int tt_zones_count = 0;


void die(char *s)
{
	perror(s);
	exit(1);
}

void tt_clockstart(struct tt_stat *ts)
{
	clock_gettime(CLOCK_MONOTONIC, &ts->start);
}

void tt_setclockstart(struct tt_stat *ts, struct timespec start)
{
	ts->start = start;
}

void tt_clockstop(struct tt_stat *ts)
{
	struct timespec end;
	clock_gettime(CLOCK_MONOTONIC, &end);
	tt_setclockstop(ts, end);
}

uint64_t tt_clockusdiff(struct timespec start, struct timespec stop)
{
    if ((stop.tv_nsec - start.tv_nsec) < 0) 
	return (stop.tv_sec - start.tv_sec - 1) * 1000000L + (stop.tv_nsec - start.tv_nsec)/1000 + 1000000L ;
     else 
 	return (stop.tv_sec - start.tv_sec) * 1000000L + (stop.tv_nsec - start.tv_nsec)/1000;
}


void tt_setclockstop(struct tt_stat *ts, struct timespec end)
{
	struct timeval tv;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];
	uint32_t t;

	if (!ts->start.tv_sec) return;

	t = (uint64_t) (((((uint64_t) end.tv_sec * 1000000000) + (uint64_t) end.tv_nsec) -
		(((uint64_t) ts->start.tv_sec * 1000000000) + (uint64_t) ts->start.tv_nsec)) / 1000);

	if (t > ts->terrible_time) {
		gettimeofday(&tv, NULL);
		nowtime = tv.tv_sec;
		nowtm = localtime(&nowtime);
		strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
		snprintf(buf, sizeof buf, "%s.%06d", tmbuf, (int)tv.tv_usec);
		printf("Terrible time: %dus on %ld times at %s \n", t, ts->count, buf);
		fflush (stdout);
	}
	if (t > ts->max_time) ts->max_time = t;
	if (t < ts->min_time) ts->min_time = t;
	ts->avg_time_sum += t;
	ts->count++;
	if (t > 20000) t = 20000;
	ts->hyst[t / 10]++;
}


int tt_stat_init(struct tt_stat *ts, const char *name, uint32_t terrible_ms)
{
	int i;

	if (name) strncpy (ts->name,name,64);
		else snprintf (ts->name, 64, "Zone %d", tt_zones_count);
	ts->start.tv_sec = 0;
	ts->start.tv_nsec = 0;
	ts->max_time = 0;
	ts->min_time = -1;
	ts->avg_time_sum = 0;
	ts->count = 0;
	if (terrible_ms)
		ts->terrible_time = terrible_ms;
	else
		ts->terrible_time = -1;
	for (i = 0; i < 2001; i++)
		ts->hyst[i] = 0;

	i = tt_zones_count;
	tt_zones[i] = ts;
	tt_zones_count = (tt_zones_count + 1) & 31;

	return i;

}



void tt_stat_sum(struct tt_stat *sum_ts, struct tt_stat *ts)
{
	int i;

	if (sum_ts->max_time > ts->max_time) sum_ts->max_time = ts->max_time;
	if (sum_ts->min_time < ts->min_time) sum_ts->min_time = ts->min_time;

	sum_ts->count += ts->count;
	sum_ts->avg_time_sum += ts->avg_time_sum;

	for (i = 0; i < 2001; i++)
		sum_ts->hyst[i] += ts->hyst[i];
}


void tt_output_line(struct tt_stat *ts)
{
	printf("#Summary results:");
	if (!ts->count) {
		printf(" there is no any results \n");
		return;
	}
	printf("max time:%5ldus; min time:%5ldus; avg time:%5ldus;count:%ld\n", ts->max_time, ts->min_time, ts->avg_time_sum / ts->count, ts->count);
}

void tt_output_hist(struct tt_stat *ts)
{
	unsigned int i, i2;
	unsigned int max = 0;
	char line[255];

	printf("#Histogram\n");
	printf("#time   | count | graph\n");
	printf("#-------+-------+---------------------------------------------------------------------\n");

	for (i = 0; i < 2000; i++)
		if (ts->hyst[i] > max) max = ts->hyst[i];

	if (!max) {
		printf("#There is no any results \n");
		return;
	}
	for (i = 0; i < 2000; i++)
		if (ts->hyst[i]) {
			snprintf(line,255,"#%5dus|%7ld|", (i + 1)*10, ts->hyst[i]);
			for (i2 = 0; i2 < (70 * ts->hyst[i]) / max; i2++) strncat (line, "*", 255);
			printf("%s\n",line);
		}
	printf("#-------+-------+---------------------------------------------------------------------\n");
}

void tt_output(struct tt_stat *ts)
{
	struct timeval tv;
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];

	gettimeofday(&tv, NULL);
	nowtime = tv.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
	snprintf(buf, sizeof buf, "%s.%06ld", tmbuf, tv.tv_usec);

	printf("#----- Statistic results of %s, Date %s -----\n", ts->name, buf);
	tt_output_line(ts);
	tt_output_hist(ts);
	printf("#------------------------------------------------------------------------------------\n");
	fflush(stdout);
}

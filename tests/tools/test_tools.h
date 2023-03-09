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

#ifndef TEST_TOOLS_H
#define	TEST_TOOLS_H

#include <stdint.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

struct tt_stat {
	char name[64];
	unsigned long max_time;
	unsigned long min_time;
	uint64_t avg_time_sum;
	unsigned long count;
	struct timespec start;
	uint32_t terrible_time;
	unsigned long hyst[2001];
};

void tt_clockstart(struct tt_stat *ts);
void tt_setclockstart(struct tt_stat *ts, struct timespec start);
void tt_clockstop(struct tt_stat *ts);
void tt_setclockstop(struct tt_stat *ts, struct timespec end);
int tt_stat_init(struct tt_stat *ts, const char *name, uint32_t terrible_ms);
void tt_stat_sum (struct tt_stat *sum_ts, struct tt_stat *ts);
void tt_output (struct tt_stat *ts);
void tt_output_hist (struct tt_stat *ts);
void tt_output_line (struct tt_stat *ts);
void tt_log_output_line(struct tt_stat *ts);
void tt_thread_output (uint32_t mask);

uint64_t tt_clockusdiff(struct timespec start, struct timespec stop);


void die(char *s);


#ifdef __cplusplus
} // extern "C"
#endif

#endif	/* TEST_TOOLS_H */


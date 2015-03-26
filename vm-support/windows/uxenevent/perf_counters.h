/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _PERF_COUNTERS_H_
#define _PERF_COUNTERS_H_

int perf_counters_init();
int perf_counters_create(void **ctx,
                         char *counter_class_name,
                         char *counter_paths,
                         uint32_t *counter_paths_size,
                         PDH_FMT_COUNTERVALUE *fmt_values,
                         uint32_t *fmt_values_size);
void perf_counters_destroy(void *ctx);
int perf_counters_query(void *ctx);
void perf_start_sampling(uint64_t counters_mask,
                         uint32_t sampling_interval,
                         uint32_t number_of_samples);

#endif /* _PERF_COUNTERS_H_ */

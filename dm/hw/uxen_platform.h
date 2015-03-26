/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXEN_PLATFORM_H_
#define _UXEN_PLATFORM_H_

void uxen_platform_time_update(void);
int uxen_platform_set_balloon_size(int min_mb, int max_mb);
int uxen_platform_get_balloon_size(int *current, int *min, int *max);

#endif  /* _UXEN_PLATFORM_H_ */

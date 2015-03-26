/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _PLATFORM_H_
#define _PLATFORM_H_

#include <stdint.h>

int platform_open(void);
int platform_set_time_update_event(HANDLE event);
int platform_service_balloon_update_event(HANDLE event);
struct shared_info;
struct shared_info *platform_map_shared_info(void);
int platform_update_system_time(void);
int platform_service_balloon(void);

#endif  /* _PLATFORM_H_ */

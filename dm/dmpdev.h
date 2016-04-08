/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DMPDEV_H_
#define _DMPDEV_H_

extern bool dmpdev_enabled;
extern char *dmpdev_dump_location;
extern uint8_t dmpdev_max_dumps;
extern uint64_t dmpdev_max_dump_size;
extern uint8_t dmpdev_max_log_events;
extern bool dmpdev_overwrite;
extern bool dmpdev_query;
extern uint64_t dmpdev_PsActiveProcessHead;
extern uint64_t dmpdev_PsLoadedModulesList;

void dmpdev_init(void);

bool dmpdev_notify_vm_crash();

void dmpdev_notify_dump_complete(bool dump_save_sucessful);

#endif /* _DMPDEV_H_ */

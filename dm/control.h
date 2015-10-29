/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _CONTROL_H_
#define _CONTROL_H_

#include "dict.h"

void control_open(char *path);
void control_command_exit(void);
void control_exit(void);
void control_flush(void);

int control_send_status(const char *key, const char *val, ...);

int control_send_command(const char *command, const dict args,
                         void (*)(void *, dict), void *);
int
control_send_ok(void *send_opaque, const char *command, const char *id,
		const char *fmt, ...);
int
control_queue_ok(void *send_opaque, const char *command, const char *id,
                 const char *fmt, ...);
void control_command_save_finish(int ret, char *err_msg);
void control_command_resume_finish(int ret, char *err_msg);

#ifdef _WIN32
HANDLE control_dup_handle(HANDLE handle);
#endif

#endif	/* _CONTROL_H_ */

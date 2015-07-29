/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _CLIPBOARD_H_
#define _CLIPBOARD_H_

int clip_service_start(void);
void clip_service_stop(void);
int clip_parse_config(yajl_val config);

#endif

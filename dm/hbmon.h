/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef HBMON_H_
#define HBMON_H_

int hbmon_init(void);
void hbmon_ping(void);
void hbmon_cleanup(void);

#endif

/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _CLOCK_H_
#define _CLOCK_H_

#define CLOCK_BASE 1000000000LL

#define SCALE_MS 1000000LL
#define SCALE_US 1000
#define SCALE_NS 1

#define CLOCK_REALTIME 0
#define CLOCK_VIRTUAL  1

typedef struct Clock {
    int type;
} Clock;

extern int64_t time_pause_adjust;
extern int64_t clock_save_adjust;

int64_t _os_get_clock(int);	/* in ns */
int64_t _os_get_clock_ms(int);
#define os_get_clock() _os_get_clock(CLOCK_REALTIME) /* in ns */
#define os_get_clock_ms() _os_get_clock_ms(CLOCK_REALTIME)
#define os_get_clock_s(void) (os_get_clock_ms() / 1000)

Clock *new_clock(int type);
int64_t get_clock(Clock *clock);
#define get_clock_ms(clock) (get_clock_ns(clock) / SCALE_MS)
int64_t get_clock_ns(Clock *clock);
int64_t clock_is_paused(Clock *clock);

#define get_ticks_per_sec(void) (CLOCK_BASE)

void vm_clock_pause(void);
void vm_clock_unpause(void);

#endif	/* _CLOCK_H_ */

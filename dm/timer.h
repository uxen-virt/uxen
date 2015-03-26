/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _TIMER_H_
#define _TIMER_H_

#include "clock.h"
#include "queue.h"

typedef void TimerCB(void *opaque);

struct Timer {
    Clock *clock;
    int64_t expire_time;
    int scale;
    TimerCB *cb;
    void *opaque;
    TAILQ_ENTRY(Timer) queue;
    TimerQueue *active_timers;
};

#ifndef _TYPEDEF_H_
typedef struct Timer Timer;
#endif


extern TimerQueue main_active_timers[];

extern Clock *rt_clock;
extern Clock *vm_clock;

extern int64_t ticks_per_sec;

Timer *_new_timer(TimerQueue *active_timers, Clock *clock, int scale, TimerCB *cb,
		  void *opaque, const char *fn, int line);
#define new_timer_ex(active_timers, clock, scale, cb, opaque) _new_timer(active_timers, clock, scale, cb, opaque, __FUNCTION__, __LINE__)
#define new_timer(clock, scale, cb, opaque) new_timer_ex(NULL, clock, scale, cb, opaque)

void free_timer(Timer *ts);
void del_timer(Timer *ts);
void advance_timer(Timer *ts, int64_t expire_time);
void mod_timer_ns(Timer *ts, int64_t expire_time);
void mod_timer(Timer *ts, int64_t expire_time);
int timer_pending(Timer *ts);
// int timer_expired(Timer *timer_head, int64_t current_time);
void run_timers(TimerQueue *active_timers, Clock *clock);
void timers_init(TimerQueue *active_timers);
void save_timer(QEMUFile *f, Timer *ts);
void load_timer(QEMUFile *f, Timer *ts);
// void run_one_timer(Timer *ts);
void timer_deadline(TimerQueue *active_timers, Clock *clock, int *timeout);

#define new_timer_ms(clock, cb, opaque) new_timer(clock, SCALE_MS, cb, opaque)
#define new_timer_ns(clock, cb, opaque) new_timer(clock, SCALE_NS, cb, opaque)
#define new_timer_ms_ex(active_timers, clock, cb, opaque) new_timer_ex(active_timers, clock, SCALE_MS, cb, opaque)
#define new_timer_ns_ex(active_timers, clock, cb, opaque) new_timer_ex(active_timers, clock, SCALE_NS, cb, opaque)
#endif	/* _TIMER_H_ */

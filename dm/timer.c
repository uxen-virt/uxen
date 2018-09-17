/*
 * Copyright 2012-2018, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <stdint.h>

#include "file.h"
#include "clock.h"
#include "timer.h"
#include "queue.h"

#if defined(_WIN32)
#include <mmsystem.h>
#endif

Clock *rt_clock;
Clock *vm_clock;

int64_t ticks_per_sec;

TimerQueue main_active_timers[2];

Timer *_new_timer(TimerQueue *active_timers, Clock *clock, int scale, TimerCB *cb, void *opaque,
		  const char *fn, int line)
{
    Timer *ts;

    if (!active_timers)
        active_timers = main_active_timers;

    ts = calloc(1, sizeof(Timer));
    ts->clock = clock;
    ts->scale = scale;
    ts->cb = cb;
    ts->active_timers = active_timers;
    ts->opaque = opaque;

    return ts;
}

void free_timer(Timer *ts)
{

    del_timer(ts);
    free(ts);
}

/* stop a timer, but do not dealloc it */
void del_timer(Timer *ts)
{

    if (TAILQ_ACTIVE(ts, queue))
	TAILQ_REMOVE(&ts->active_timers[ts->clock->type], ts, queue);
}

void advance_timer(Timer *ts, int64_t expire_time)
{

    if (!TAILQ_ACTIVE(ts, queue) || ts->expire_time > expire_time * ts->scale)
	mod_timer_ns(ts, expire_time * ts->scale);
}

void mod_timer_ns(Timer *ts, int64_t expire_time)
{
    Timer *t;

    if (TAILQ_ACTIVE(ts, queue)) {
        /* already set at expire_time */
        if (ts->expire_time == expire_time)
            return;
	TAILQ_REMOVE(&ts->active_timers[ts->clock->type], ts, queue);
    }

    TAILQ_FOREACH(t, &ts->active_timers[ts->clock->type], queue)
	if (t->expire_time > expire_time)
	    break;
    ts->expire_time = expire_time;
    if (t)
	TAILQ_INSERT_BEFORE(t, ts, queue);
    else
	TAILQ_INSERT_TAIL(&ts->active_timers[ts->clock->type], ts, queue);
}

void mod_timer(Timer *ts, int64_t expire_time)
{
    mod_timer_ns(ts, expire_time * ts->scale);
}

int timer_pending(Timer *ts)
{

    return TAILQ_ACTIVE(ts, queue) ? 1 : 0;
}

#if 0
static inline int timer_expired_ns(Timer *t, int64_t current_time)
{
    return t && (t->expire_time <= current_time);
}

static inline int timer_expired(Timer *t, int64_t current_time)
{
    return t && timer_expired_ns(t, current_time * t->scale);
}
#endif

void run_timers(TimerQueue *active_timers, Clock *clock)
{
    Timer *ts;
    int64_t current_time;

    if (!active_timers)
        active_timers = main_active_timers;

    if (clock_is_paused(clock))
        return;

    current_time = get_clock_ns(clock);

    while ((ts = TAILQ_FIRST(&active_timers[clock->type]))) {
        if (ts->expire_time > current_time)
            break;

        /* remove timer from the list before calling the callback */
	TAILQ_REMOVE(&active_timers[clock->type], ts, queue);

        /* run the callback (the timer list can be modified) */
        ts->cb(ts->opaque);
    }
}

void timers_init(TimerQueue *active_timers)
{
    bool is_main;

    is_main = (active_timers == NULL);

    if (!active_timers)
        active_timers = main_active_timers;

    if (is_main) {
        ticks_per_sec = CLOCK_BASE;
        rt_clock = new_clock(CLOCK_REALTIME);
        vm_clock = new_clock(CLOCK_VIRTUAL);
    }
    TAILQ_INIT(&active_timers[rt_clock->type]);
    TAILQ_INIT(&active_timers[vm_clock->type]);
}

/* save a timer */
void save_timer(QEMUFile *f, Timer *ts)
{
    int64_t delta;

    if (timer_pending(ts))
        delta = ts->expire_time - get_clock_ns(ts->clock);
    else
        delta = -1;
    qemu_put_be64(f, delta);
}

void load_timer(QEMUFile *f, Timer *ts)
{
    int64_t delta;

    delta = qemu_get_be64(f);
    if (delta != -1)
        mod_timer_ns(ts, delta + get_clock_ns(ts->clock));
    else
        del_timer(ts);
}

#if 0
/* run the specified timer */
void run_one_timer(Timer *ts)
{
    uint64_t current_time;

    /* remove timer from the list before calling the callback */
    del_timer(ts);

    while ((current_time = get_clock_ns(ts->clock)) < ts->expire_time)
        /* sleep until the expire time */
        usleep((ts->expire_time - current_time) / 1000);

    /* run the callback */
    ts->cb(ts->opaque);
}
#endif

void
timer_deadline(TimerQueue *active_timers, Clock *clock, int *timeout)
{
    Timer *ts;
    int64_t delta;

    if (!active_timers)
        active_timers = main_active_timers;

    if (clock_is_paused(clock))
        return;

    ts = TAILQ_FIRST(&active_timers[clock->type]);
    if (ts == NULL)
	return;

    delta = ts->expire_time - get_clock_ns(clock);
    if (delta < 0) {
#ifdef CONFIG_AIO
	if (delta < -SCALE_MS)
	    debug_printf("timer late exp %"PRId64" now %"PRId64
                         " delta %"PRId64"\n",
                         (ts->expire_time / SCALE_MS) % 10000,
                         get_clock_ms(clock) % 10000, delta);
#endif
	delta = 0;
    } else if (delta > 0) {
	delta /= SCALE_MS;
        /* minimum timeout if non-zero delta to avoid spinning */
        if (delta < 1)
            delta = 1;
    }
    if (delta < *timeout)
	*timeout = delta;
}

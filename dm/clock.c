/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdint.h>

#include "clock.h"
#include "lib.h"

#define RELATIVE_CLOCK

#ifdef RELATIVE_CLOCK
static int64_t start_time;
int64_t time_pause_adjust = 0;
static int64_t clock_paused_time = 0;
static critical_section clock_lck;
#else
#define start_time 0
#endif

static void vm_clock_lock(void);
static void vm_clock_unlock(void);

#if defined(_WIN32)
static int64_t clock_freq = 0;

static void __attribute__((constructor))
init_get_clock(void)
{
    LARGE_INTEGER freq;
#ifdef RELATIVE_CLOCK
    LARGE_INTEGER ti;
#endif
    int ret;

    ret = QueryPerformanceFrequency(&freq);
    if (ret == 0)
	err(1, "%s: could not calibrate ticks", __FUNCTION__);

    clock_freq = freq.QuadPart;

#ifdef RELATIVE_CLOCK
    critical_section_init(&clock_lck);
    QueryPerformanceCounter(&ti);
    start_time = ti.QuadPart;
#endif
}

int64_t _os_get_clock(int type)
{
    int64_t ret;
    LARGE_INTEGER ti;

    if (type == CLOCK_VIRTUAL)
        vm_clock_lock();
    if (type == CLOCK_VIRTUAL && clock_paused_time)
        ret = clock_paused_time;
    else {
        QueryPerformanceCounter(&ti);
        ret = muldiv64(ti.QuadPart - start_time, CLOCK_BASE, clock_freq);
        if (type == CLOCK_VIRTUAL)
            ret -= time_pause_adjust;
    }
    if (type == CLOCK_VIRTUAL)
        vm_clock_unlock();

    return ret;
}

int64_t _os_get_clock_ms(int type)
{
    int64_t ret;
    LARGE_INTEGER ti;

    if (type == CLOCK_VIRTUAL)
        vm_clock_lock();
    if (type == CLOCK_VIRTUAL && clock_paused_time)
        ret = clock_paused_time;
    else {
        QueryPerformanceCounter(&ti);
        ret = muldiv64(ti.QuadPart - start_time, CLOCK_BASE, clock_freq);
        if (type == CLOCK_VIRTUAL)
            ret -= time_pause_adjust;
    }
    ret /= SCALE_MS;
    if (type == CLOCK_VIRTUAL)
        vm_clock_unlock();

    return ret;
}

#elif defined(__APPLE__)

#include <mach/mach_time.h>

static void __attribute__((constructor))
init_get_clock(void)
{

#ifdef RELATIVE_CLOCK
    critical_section_init(&clock_lck);
    start_time = mach_absolute_time();
#endif
}

int64_t _os_get_clock(int type)
{
    int64_t ret;

    if (type == CLOCK_VIRTUAL)
        vm_clock_lock();
    if (type == CLOCK_VIRTUAL && clock_paused_time)
        ret = clock_paused_time;
    else {
        ret = mach_absolute_time() - start_time;
        if (type == CLOCK_VIRTUAL)
            ret -= time_pause_adjust;
    }
    if (type == CLOCK_VIRTUAL)
        vm_clock_unlock();

    return ret;
}

int64_t _os_get_clock_ms(int type)
{

    return _os_get_clock(type) / SCALE_MS;
}

#endif	/* _WIN32 / __APPLE__ */

#ifdef RELATIVE_CLOCK
static void vm_clock_lock(void)
{
    critical_section_enter(&clock_lck);
}

static void vm_clock_unlock(void)
{
    critical_section_leave(&clock_lck);
}

void
vm_clock_pause(void)
{

    vm_clock_lock();

    if (!clock_paused_time) {
        clock_paused_time = _os_get_clock(CLOCK_REALTIME) - time_pause_adjust;
        debug_printf("%s\n", __FUNCTION__);
    }

    vm_clock_unlock();
}

void vm_clock_unpause(void)
{

    vm_clock_lock();

    if (clock_paused_time) {
        debug_printf("%s\n", __FUNCTION__);
        clock_paused_time = 0;
    }

    vm_clock_unlock();
}
#else
static void vm_clock_lock(void) { }
static void vm_clock_unlock(void) { }
void vm_clock_pause(void) { }
void vm_clock_unpause(void) { }
#endif

Clock *new_clock(int type)
{
    Clock *clock;

    switch(type) {
    case CLOCK_REALTIME:
    case CLOCK_VIRTUAL:
	break;
    default:
	return NULL;
    }

    clock = calloc(1, sizeof(Clock));
    clock->type = type;

    return clock;
}

int64_t get_clock(Clock *clock)
{
    switch(clock->type) {
    case CLOCK_REALTIME:
        return _os_get_clock(clock->type) / SCALE_MS; /* realtime clock in ms */
    case CLOCK_VIRTUAL:
	return _os_get_clock(clock->type);
    default:
        err(1, "%s: invalid type %d", __FUNCTION__, clock->type);
    }
}

int64_t get_clock_ns(Clock *clock)
{

    switch(clock->type) {
    case CLOCK_REALTIME:
        return _os_get_clock(clock->type);
    case CLOCK_VIRTUAL:
        return _os_get_clock(clock->type);
    default:
        err(1, "%s: invalid type %d", __FUNCTION__, clock->type);
    }
}

int64_t
clock_is_paused(Clock *clock)
{

    switch(clock->type) {
    case CLOCK_REALTIME:
        return 0;
    case CLOCK_VIRTUAL:
        return !!clock_paused_time;
    default:
        err(1, "%s: invalid type %d", __FUNCTION__, clock->type);
    }
}

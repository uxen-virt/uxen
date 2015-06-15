/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <stdint.h>
#include <stdlib.h>

#include "bh.h"
#include "ioh.h"
#include "queue.h"

static ioh_event bh_schedule_event;
static critical_section bh_lock;

struct BH {
    BHFunc *cb;
    void *opaque;
    int scheduled;
    int idle;
    int deleted;
    int delete_one_shot;
    TAILQ_ENTRY(BH) queue;
    char _data[];
};

static TAILQ_HEAD(bh_tailq, BH) bhs = TAILQ_HEAD_INITIALIZER(bhs);

static void
bh_schedule_event_cb(void *opaque)
{

    /* do nothing */
}

void
bh_init(void)
{

    critical_section_init(&bh_lock);

    ioh_event_init(&bh_schedule_event);
    ioh_add_wait_object(&bh_schedule_event, bh_schedule_event_cb, NULL, NULL);
}

BH *
bh_new(BHFunc *cb, void *opaque)
{
    BH *bh;

    bh = calloc(1, sizeof(BH));
    bh->cb = cb;
    bh->opaque = opaque;
    critical_section_enter(&bh_lock);
    TAILQ_INSERT_TAIL(&bhs, bh, queue);
    critical_section_leave(&bh_lock);

    return bh;
}

BH *bh_new_with_data(BHFunc *cb, int data_size, void **data)
{
    BH *bh;

    bh = calloc(1, sizeof(BH) + data_size);
    bh->cb = cb;
    bh->opaque = bh->_data;
    critical_section_enter(&bh_lock);
    TAILQ_INSERT_TAIL(&bhs, bh, queue);
    critical_section_leave(&bh_lock);

    *data = bh->_data;

    return bh;
}

int bh_poll(void)
{
    BH *bh, *next;
    int ret;

    ret = 0;
    critical_section_enter(&bh_lock);
    TAILQ_FOREACH_SAFE(bh, &bhs, queue, next) {
        if (!bh->deleted && bh->scheduled) {
            bh->scheduled = 0;
            if (!bh->idle)
                ret = 1;
            else
                bh->idle = 0;
            critical_section_leave(&bh_lock);
            bh->cb(bh->opaque);
            critical_section_enter(&bh_lock);
            if (bh->delete_one_shot)
                bh->deleted = 1;
        }
	if (bh->deleted) {
	    TAILQ_REMOVE(&bhs, bh, queue);
	    free(bh);
	    continue;
	}
    }
    critical_section_leave(&bh_lock);

    return ret;
}

static void
_bh_schedule(BH *bh)
{

    bh->scheduled = 1;
    ioh_event_set(&bh_schedule_event);
}

void bh_schedule_idle(BH *bh)
{
    if (bh->scheduled)
        return;
    bh->idle = 1;
    _bh_schedule(bh);
}

void bh_schedule(BH *bh)
{
    if (bh->scheduled)
        return;
    bh->idle = 0;
    _bh_schedule(bh);
}

void bh_schedule_one_shot(BH *bh)
{

    bh->delete_one_shot = 1;
    bh_schedule(bh);
}

void bh_cancel(BH *bh)
{
    bh->scheduled = 0;
}

void bh_delete(BH *bh)
{
    bh->scheduled = 0;
    bh->deleted = 1;
}

void bh_update_timeout(int *timeout)
{
    BH *bh;

    critical_section_enter(&bh_lock);
    TAILQ_FOREACH(bh, &bhs, queue) {
        if (!bh->deleted && bh->scheduled) {
            if (bh->idle) {
                /* idle bottom halves will be polled at least
                 * every 10ms */
                *timeout = MIN(10, *timeout);
            } else {
                /* non-idle bottom halves will be executed
                 * immediately */
                *timeout = 0;
                break;
            }
        }
    }
    critical_section_leave(&bh_lock);
}

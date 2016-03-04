/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _ASYNC_OP_H_
#define _ASYNC_OP_H_

enum async_op_type {
    ASOP_SCHED_ASYNC,
    ASOP_PROCESS_ASYNC,
    ASOP_PROCESS,
    ASOP_DONE,
    ASOP_PERMANENT,
    ASOP_PERMANENT_DONE
};

struct async_op_t {
    void *opaque;
    ioh_event *event;

    enum async_op_type state;
    void (*cb_process_async)(void *);
    void (*cb_process)(void *);

    LIST_ENTRY(async_op_t) entry;
};

struct async_op_ctx;

struct async_op_ctx *async_op_init(void);
void async_op_free(struct async_op_ctx *ctx);
int async_op_add(struct async_op_ctx *ctx, void *opaque, ioh_event *event,
                 void (*cb_process_async)(void *), void (*cb_process)(void *));
int async_op_add_bh(struct async_op_ctx *ctx, void *opaque, void (*cb)(void *));

void async_op_process(struct async_op_ctx *ctx);
void async_op_exit_wait(struct async_op_ctx *ctx);
void async_op_set_max_threads(struct async_op_ctx *ctx, int max_threads);

#endif  /* _ASYNC_OP_H_ */

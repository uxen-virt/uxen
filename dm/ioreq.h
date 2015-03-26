/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _IOREQ_H_
#define _IOREQ_H_

#define NR_IOREQ_SERVERS 2

struct ioreq_state;

struct ioreq_event {
    struct ioreq_state *state;
    uxen_notification_event signal;
    uxen_user_notification_event completed;
};

struct shared_iopage;

struct ioreq_state {
    unsigned int serverid;
    struct shared_iopage *io_page;
    struct ioreq_event *events;
};

extern struct ioreq_state *default_ioreq_state;

void ioreq_init(void);

struct ioreq_state *ioreq_new_server(void);
void ioreq_wait_server_events(struct ioreq_state *);

#endif	/* _IOREQ_H_ */

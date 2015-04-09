/*
 * Copyright 2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NICKEL_LAVA_LOG_
#define _NICKEL_LAVA_LOG_

struct nickel;
struct lava_event;
struct net_addr;

int lava_init(struct nickel *ni);
void lava_exit(struct nickel *ni);
void lava_flush(struct nickel *ni);
void lava_timer(struct nickel *ni, int64_t now, int *timeout);
struct lava_event *
lava_event_create(struct nickel *ni, struct sockaddr_in sa, struct sockaddr_in da, bool tcp);
void lava_event_set_denied(struct lava_event *lv);
void lava_event_set_local(struct lava_event *lv);
void lava_event_set_proxy(struct lava_event *lv);
void lava_event_set_established(struct lava_event *lv, uint32_t conn_id);
void lava_event_set_http(struct lava_event *lv, const char *method,
        const char *domain, const char *url, uint16_t port);
void lava_event_remote_connect(struct lava_event *lv);
void lava_event_remote_disconnect(struct lava_event *lv);
void lava_event_remote_set(struct lava_event *lv, const struct net_addr *a, uint16_t port);
void lava_event_remote_established(struct lava_event *lv, struct net_addr *a, uint16_t port);
void lava_event_complete(struct lava_event *lv, bool del);
void lava_event_save_and_clear(QEMUFile *f, struct lava_event *lv);
struct lava_event * lava_event_restore(struct nickel *ni, QEMUFile *f);

#endif /* _NICKEL_LAVA_LOG_ */

/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NETUSER_H_
#define _NETUSER_H_

struct net_user {
    void *opaque;
    int nickel;
    size_t (*can_recv)(void *opaque);
    void (*recv)(void *opaque, const uint8_t *buf, int size);
    void (*send)(void *opaque);
    void (*close)(void *opaque);
    int (*add_wait_object)(void *opaque, ioh_event *ev,
            WaitObjectFunc *cb, void *cb_opaque);
    void (*del_wait_object)(void *opaque, ioh_event *ev);
#ifndef _WIN32
    int (*add_wait_fd)(void *nopaque, int fd, int events, WaitObjectFunc2 *func2, void *opaque);
    void (*del_wait_fd)(void *nopaque, int fd);
#endif

    int (*schedule_bh)(void *opaque, void (*cb1)(void *), void (*cb2)(void *), void *cb_opaque);
    int (*schedule_bh_permanent)(void *opaque, void (*cb)(void *), void *cb_opaque);
    uint32_t (*get_hostaddr)(void *opaque);
};

size_t netuser_can_recv(struct net_user *nu, void *opaque);
void netuser_recv(struct net_user *nu, void *opaque, const uint8_t *buf, int size);
void netuser_send(struct net_user *nu, void *opaque);
void netuser_close(struct net_user *nu, void *opaque);
int netuser_add_wait_object(struct net_user *nu, ioh_event *ev,
                    void (*cb)(void *opaque), void *cb_opaque);
#ifndef _WIN32
int netuser_add_wait_fd(struct net_user *nu, int fd, int events, WaitObjectFunc2 *func2, void *opaque);
void netuser_del_wait_fd(struct net_user *nu, int fd);
#endif

void netuser_del_wait_object(struct net_user *nu, ioh_event *ev);
int netuser_schedule_bh(struct net_user *nu, void (*cb1)(void *), void (*cb2)(void *),
        void *cb_opaque);
int netuser_schedule_bh_permanent(struct net_user *nu, void (*cb)(void *), void *cb_opaque);

uint32_t netuser_get_hostaddr(struct net_user *nu);

#ifdef _WIN32
char * buff_ascii_encode(wchar_t *wstr);
#endif
#endif

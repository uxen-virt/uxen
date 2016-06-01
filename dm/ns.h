/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NS_H_
#define _NS_H_

#include "yajl.h"
#ifndef _WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#endif

struct nickel;
struct ns_desc {
#define NS_SERVICE_TYPE_TCP     0
#define NS_SERVICE_TYPE_UDP     1
    int service_type;
    const char *service_name;
    CharDriverState *(*service_open)(void *, struct nickel *, CharDriverState **,
           struct sockaddr_in, struct sockaddr_in, yajl_val);
    void (*service_close)(CharDriverState *);

    LIST_ENTRY(ns_desc) entry;
};

typedef int (*ns_processor_func_t)(uint8_t *req, int reqsize, uint8_t **resp, 
    int* respsize);

struct ns_data {
    CharDriverState *chr;
    struct nickel *ni;
    void *net_opaque;
    void (*service_close)(CharDriverState *);

    critical_section lock;

    ioh_event write_event;
    int awaiting_write;

    uint8_t *send_buffer;
    int send_len;
    int send_offset;
/* the following fields are used only in "automatic in-thread processing mode" */
    ioh_event request_ready_event;
    ioh_event response_ready_event;
    uxen_thread server_thread;
    uint8_t *recv_buffer;
    int recv_len;
    int recv_offset;
    ns_processor_func_t ns_processor_func;
    int is_close_request;
    int processing_request;
};

int ns_open(struct ns_data *, struct nickel *ni);
void ns_close(struct ns_data *);
int ns_set_threaded_mode(struct ns_data *);

void ns_await_write(struct ns_data *);
void ns_signal_write(struct ns_data *);

void ns_chr_send_event(CharDriverState *chr, int event);

void ns_send_buffer(struct ns_data *d, uint8_t *buffer, int len);
int ns_append_send_buffer(struct ns_data *d, const uint8_t *buffer, int len);
void ns_reset_send_buffer(struct ns_data *d);

struct ns_desc *ns_find_service(const char *, int);

void _ns_add_service(struct ns_desc *);

#define ns_add_service(nsd)                                             \
    static void __attribute__((constructor)) ns_add_service_##nsd(void) { \
        _ns_add_service(&(nsd));                                        \
    }                                                                   \

#endif  /* _NS_H_ */

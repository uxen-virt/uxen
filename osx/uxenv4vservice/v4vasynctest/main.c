/*
 * Copyright 2015-2016, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#include "uxenv4vlib.h"
#include <v4v.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main(int argc, const char * argv[])
{
    if (argc != 4) {
        fprintf(stderr, "bad args. pass: remote domain, remote port, local port\n");
        return 1;
    }
    
    long partner_domain = strtol(argv[1], NULL, 10);
    long dest_port = strtol(argv[2], NULL, 10);
    long source_port = strtol(argv[3], NULL, 10);
    printf(
        "Testing with remote domain %ld, port %ld, local port %ld\n",
        partner_domain, dest_port, source_port);
    
    v4v_channel_t conn = { };
    if (!v4v_open(&conn, 128 * 1024)) {
        switch (errno) {
        case ENOENT:
            fprintf(stderr, "V4V kernel service not found\n");
            break;
        case ENODEV:
            fprintf(stderr, "V4V kernel call failed\n");
            break;
        case ENOMEM:
            fprintf(stderr, "V4V memory issue\n");
            break;
        default:
            warn("v4v_open");
            break;
        }
        return 1;
    }
    
    v4v_bind_values_t bind = { };
    bind.ring_id.addr.port = source_port;
    bind.ring_id.addr.domain = V4V_DOMID_ANY;
    bind.ring_id.partner = partner_domain;
    if (!v4v_bind(&conn, &bind)) {
        printf("Creating ring failed: %d (%x)\n", errno, errno);
        return 1;
    }
    
    dispatch_source_t port_receive_source =
        v4v_dispatch_source_create_receive(&conn, dispatch_get_main_queue());
    dispatch_source_t port_send_source =
        v4v_dispatch_source_create_send(&conn, dispatch_get_main_queue());
    
    dispatch_source_set_cancel_handler(
        port_receive_source,
        ^{
        });
    dispatch_source_set_cancel_handler(
        port_send_source,
        ^{
        });
    
    dispatch_source_set_event_handler(
        port_receive_source,
        ^{
            char buf[128];
            uint32_t protocol = 0;
            v4v_addr_t from = {};
            ssize_t bytes_read = v4v_recvmsg(
                &conn, &from, &protocol, buf, sizeof(buf), true);
            while (bytes_read >= 0)
            {
                printf(
                    "%ld byte message received:\n%*s\n--  \n",
                    bytes_read, (int)bytes_read, buf);
                bytes_read = v4v_recvmsg(
                    &conn, &from, &protocol, buf, sizeof(buf), true);
            }
            printf("No more messages: %ld\n", bytes_read);
        });
    
    dispatch_source_set_event_handler(
        port_send_source,
        ^{
            char msg[] = "V4V message!\n";
            
            ssize_t bytes_sent = v4v_sendto(
                &conn,
                ((v4v_addr_t){ (uint32_t)dest_port, (domid_t)partner_domain }),
                msg,
                sizeof(msg),
                0 /* flags */);
            if (bytes_sent != sizeof(msg)) {
                printf("Sending message failed: %ld (%lx)\n",
                    bytes_sent, bytes_sent);
            } else {
                printf("Bytes sent: %ld\n", bytes_sent);
            }
        });

    
    dispatch_resume(port_send_source);
    dispatch_resume(port_receive_source);

    char msg[] = "V4V message!\n";
    ssize_t bytes_sent = v4v_sendto(
        &conn,
        ((v4v_addr_t){ (uint32_t)dest_port, (domid_t)partner_domain }),
        msg,
        sizeof(msg),
        0 /* flags */);
    if (bytes_sent != sizeof(msg))
        printf("Sending message failed: %ld (%lx)\n", bytes_sent, bytes_sent);
    else
        printf("Bytes sent: %ld\n", bytes_sent);

    dispatch_main();
    
    return 0;
}

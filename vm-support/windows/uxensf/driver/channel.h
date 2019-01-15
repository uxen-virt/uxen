/*
 * Copyright 2013-2019, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#define RING_SIZE 262144

struct channel_req {
    LIST_ENTRY le;
    KEVENT resp_ev;
    void *buf;
    int buf_size;
    int send_size;
    int recv_size;
    int rc;
};

NTSTATUS ChannelConnect(void);
NTSTATUS ChannelPrepareReq(struct channel_req *req, void *buffer, int buffer_size, int send_size);
NTSTATUS ChannelSendReq(struct channel_req *req);
NTSTATUS ChannelRecvResp(struct channel_req *req, int *recv_size);
NTSTATUS ChannelReleaseReq(struct channel_req *req);

void ChannelDisconnect(void);


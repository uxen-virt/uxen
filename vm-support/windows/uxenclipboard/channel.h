/*
 * Copyright 2013-2016, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _CHANNEL_H_
#define _CHANNEL_H_

int ChannelSend(char* buffer, int count);
int ChannelRecv(void **buffer, int *count);
int ChannelSendNotify(char *buffer, int count);
int ChannelRecvNotify(void **msg, int *len);
int ChannelConnect(void);
void ChannelClose(void);

#endif

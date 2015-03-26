/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

int ChannelSend(char* buffer, int count);
int ChannelRecv(char* buffer, int count);
int ChannelRecvHostMsg(char* msg, unsigned int maxlen);
int ChannelConnect(void);


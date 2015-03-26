/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <winsock.h>
#include <iprt/err.h>
#include "../common/defroute.h"

static int connect_to_uxen(uint32_t server, int port, int *retsock)
{
    struct sockaddr_in addr;
    int sock;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET)
        return RTErrConvertFromWin32(GetLastError());
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = server;
    if (connect(sock, (const struct sockaddr *)&addr, sizeof(addr)))
        return RTErrConvertFromWin32(GetLastError());
    *retsock = sock;
    return 0;
}

static int clipboard_socket;
static int hostmsg_socket;

int ChannelConnect()
{
    WORD version = MAKEWORD(2,2);
    WSADATA wsaData;
    int ret;
    uint32_t server = get_default_route();
    if ((ret = WSAStartup(version, &wsaData)))
        return ret;
    /*
    If we open connection to shared-clipboard first and then to
    shared-clipboard-hostmsg, then during ns_open of the latter, the host
    will try to send its clipboard formats. It will fail because of
    ns_uclip_hostmsg_open not finished yet.
    So, arrange for ns_uclip_hostmsg_open being called (and completed) before
    ns_uclip_open - meaning, 44446 before 44445.
    */
    if ((ret = connect_to_uxen(server, 44446, &hostmsg_socket)))
        return ret;
    if ((ret = connect_to_uxen(server, 44445, &clipboard_socket)))
        return ret;
    return 0;
}

int ChannelSend(char* buffer, int count)
{
    int total_sent = 0;
    int ret;
    while (total_sent < count) {
        ret = send(clipboard_socket, buffer, count, 0);
        if (ret == 0)
            return VERR_EOF;
        if (ret < 0)
            return RTErrConvertFromWin32(GetLastError());
        total_sent += ret;
    }
    return 0;
}

static int recv_exact(int socket, char* buffer, int count)
{
    int total_recv = 0;
    int ret;
    while (total_recv < count) {
        ret = recv(socket, buffer + total_recv, count - total_recv, 0);
        if (ret == 0)
            return VERR_EOF;
        if (ret < 0)
            return RTErrConvertFromWin32(GetLastError());
        total_recv += ret;
    }
    return 0;
}
int ChannelRecvHostMsg(char* msg, unsigned int maxlen)
{
    int ret;
    unsigned int msglen;
    ret = recv_exact(hostmsg_socket, msg, sizeof(unsigned int));
    if (ret)
        return ret;
    msglen = *(unsigned int*)msg;
    if (msglen > maxlen - 2 * sizeof(unsigned int))
        return VERR_BUFFER_OVERFLOW;
    ret = recv_exact(hostmsg_socket, msg + sizeof(unsigned int),
        msglen + sizeof(unsigned int));
    if (ret)
        return ret;
    if (send(hostmsg_socket, "X", 1, 0) != 1)
        return VERR_TIMEOUT;
    else
        return 0;
}

int ChannelRecv(char* buffer, int count)
{
    return recv_exact(clipboard_socket, buffer, count);
}

    



/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#define HGCMMagicSimple 0x01020304
typedef struct _TcpMarshallHeader
{
    uint32_t magic;
    uint32_t size;
    uint32_t u32Function;
    union {
        uint32_t cParms;
        uint32_t status;
    }u;
} TcpMarshallHeader;
#ifdef __cplusplus
extern "C"
#endif
int VbglHGCMCall_tcp_marshall(VBoxGuestHGCMCallInfo* info, bool really_send,
    bool is_client, uint32_t* size, char * out);

#ifdef __cplusplus
extern "C"
#endif
int VbglHGCMCall_tcp_unmarshall(VBoxGuestHGCMCallInfo*info, char *hgcmBuf,
    uint32_t cParms, bool is_client, uint32_t size);


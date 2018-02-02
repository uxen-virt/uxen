/*
 * Copyright 2013-2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifdef IN_RING0
    #pragma  hdrstop
    #include "VBoxGuestR0LibSharedFolders.h"
    #include "dbghlp.h"
#else
    #include <VBox/VBoxGuest2.h>
    #include <VBox/VMMDev.h>
    #include <iprt/mem.h>
    #include <string.h>
    #define STATUS_NOT_IMPLEMENTED VERR_INVALID_PARAMETER
    #define STATUS_INFO_LENGTH_MISMATCH VINF_BUFFER_OVERFLOW
    #define verify_on_stack(p)
#endif

#include "hgcm-limits.h"

typedef struct _Buf {
    char * buf;
    uint32_t current_offset;
    bool really_produce;
    uint32_t input_size;
} Buf;

static int verify_dst_on_stack;

static bool pointer_copy_needed(uint32_t type, bool is_client)
{
    if (type == VMMDevHGCMParmType_LinAddr)
        return true;
    if (type == VMMDevHGCMParmType_LinAddr_In && is_client)
        return true;
    if (type == VMMDevHGCMParmType_LinAddr_Out && !is_client)
        return true;
    return false;
}

static int produce(Buf*buf, char * src, unsigned int size)
{
    if (size > MAX_HGCM_PACKET_SIZE || buf->current_offset + size > MAX_HGCM_PACKET_SIZE)
        return STATUS_INFO_LENGTH_MISMATCH;
    if (buf->really_produce)
        memcpy(buf->buf + buf->current_offset, src, size);
    buf->current_offset += size;
    return 0;
}
static int consume(Buf*buf, char * dst, unsigned int size)
{
    /* two checks needed, to not let integer overflow thru */
    if (size > buf->input_size || size + buf->current_offset > buf->input_size)
        return STATUS_INFO_LENGTH_MISMATCH;
    verify_on_stack(buf);
    if (verify_dst_on_stack) verify_on_stack(dst);
    memcpy(dst, buf->buf + buf->current_offset, size);
    buf->current_offset += size;
    return 0;
}
#define produce_type(x,y) produce(x, (char*)(&y), sizeof(y))
#define consume_type(x,y) consume(x, (char*)(&y), sizeof(y))
#define RETURN_ON_ERROR(x) {int rc = x; if (rc) return rc;}

/* Marshall rpc arguments passed in VBoxGuestHGCMCallInfo into a byte
   array. If (really_send), then just compute the required buffer size. */
int VbglHGCMCall_tcp_marshall(VBoxGuestHGCMCallInfo* info, bool really_send,
    bool is_client, uint32_t* size, char * out)
{
    unsigned int i;
    uint32_t type;
    HGCMFunctionParameter * parms = (HGCMFunctionParameter *) (info + 1);
    Buf buffer = {out, 0, really_send, };
    for (i = 0; i < info->cParms; i++) {
        type = parms[i].type;
        if (type == VMMDevHGCMParmType_LinAddr_Locked_In)
            type = VMMDevHGCMParmType_LinAddr_In;
        if (type == VMMDevHGCMParmType_LinAddr_Locked_Out)
            type = VMMDevHGCMParmType_LinAddr_Out;
        RETURN_ON_ERROR(produce_type(&buffer, type));
        switch (type) {
            case VMMDevHGCMParmType_32bit:
                RETURN_ON_ERROR(produce_type(&buffer, parms[i].u.value32));
                break;
            case VMMDevHGCMParmType_64bit:
                RETURN_ON_ERROR(produce_type(&buffer, parms[i].u.value64));
                break;
            case VMMDevHGCMParmType_LinAddr:
            case VMMDevHGCMParmType_LinAddr_In:
            case VMMDevHGCMParmType_LinAddr_Out:
                RETURN_ON_ERROR(produce_type(&buffer, parms[i].u.Pointer.size));
                if (pointer_copy_needed(type, is_client)) {
                    RETURN_ON_ERROR(produce(&buffer,
                        (char*)(uintptr_t)parms[i].u.Pointer.u.linearAddr,
                        parms[i].u.Pointer.size));
                }
                break;
            default:
                return STATUS_NOT_IMPLEMENTED;
        }
    }
    *size = buffer.current_offset;
    return 0;
}
        
/* The reverse of VbglHGCMCall_tcp_marshall. Security-critical: parses
   arbitrary blob received from VM. */
int VbglHGCMCall_tcp_unmarshall(VBoxGuestHGCMCallInfo*info, char *hgcmBuf, 
    int cParms, bool is_client, uint32_t input_size) {
    HGCMFunctionParameter * parms = (HGCMFunctionParameter *) (info + 1); 
    int i;
    uint32_t type;
    uint32_t size;
    uint32_t total_alloc = 0;
    Buf buffer = {hgcmBuf, 0, true, input_size};

    verify_on_stack(info);
    verify_on_stack(parms);

    for (i = 0; i < cParms; i++) {
        RETURN_ON_ERROR(consume_type(&buffer, type));
        parms[i].type = (HGCMFunctionParameterType)type;
        verify_dst_on_stack = 0;
        switch (type) {
            case VMMDevHGCMParmType_32bit:
                verify_dst_on_stack = 1;
                verify_on_stack(&parms[i].u.value32);
                RETURN_ON_ERROR(consume_type(&buffer, parms[i].u.value32));
                break;
            case VMMDevHGCMParmType_64bit:
                verify_dst_on_stack = 1;
                verify_on_stack(&parms[i].u.value64);
                RETURN_ON_ERROR(consume_type(&buffer, parms[i].u.value64));
                break;
            case VMMDevHGCMParmType_LinAddr:
            case VMMDevHGCMParmType_LinAddr_In:
            case VMMDevHGCMParmType_LinAddr_Out:
                RETURN_ON_ERROR(consume_type(&buffer, size));
                if (!is_client) {
#ifndef IN_RING0
                    /* Two comparisons need to prevent integer overflow */
                    if (size > MAX_HGCM_PACKET_SIZE || total_alloc + size > MAX_HGCM_PACKET_SIZE)
                        return STATUS_INFO_LENGTH_MISMATCH;
                    total_alloc += size;
                    if (pointer_copy_needed(type, !is_client)) {
                        /* we will initialize buffer later */
                        parms[i].u.Pointer.u.linearAddr = (RTGCPTR64)(uintptr_t)RTMemAlloc(size);
                    } else {
                        parms[i].u.Pointer.u.linearAddr = (RTGCPTR64)(uintptr_t)RTMemAllocZ(size);
                    }
                    if (!parms[i].u.Pointer.u.linearAddr)
                        return VERR_NO_MEMORY;
                    parms[i].u.Pointer.size = size;
#endif                    
                } else {
                    if (parms[i].u.Pointer.size < size)
                        return STATUS_INFO_LENGTH_MISMATCH;
                }
                if (pointer_copy_needed(type, !is_client)) {
                    char *addr = (char*)(uintptr_t)parms[i].u.Pointer.u.linearAddr;
                    RETURN_ON_ERROR(consume(&buffer, addr, size));
                }
                break;
            default:
                return STATUS_NOT_IMPLEMENTED;
        }
    }
    return 0;
}


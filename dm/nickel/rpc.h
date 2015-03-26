/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _NICKEL_RPC_H_
#define _NICKEL_RPC_H_

#include <dm/dict.h>
enum _tagBromiumNetworkAccessPolicyType
{
    BrNAPT_DENY_ALL = 0,
    BrNAPT_ALLOW_ALL = 1,
    BrNAPT_RESTRICTED = 2,
    BrNAPT_RESTRICTED_IP = 3
} BromiumNetworkAccessPolicyType;

typedef unsigned int CertificateStatus;

/* they need to be the same on Krypton ! */
#define kCertificateStatusErrorMask  0x0000ffff
#define kCertificateStatusValid  0x00000000
#define kCertificateStatusCommonNameInvalid  0x00000001
#define kCertificateStatusDateInvalid  0x00000002
#define kCertificateStatusAuthorityInvalid  0x00000004
#define kCertificateStatusCertificateContainsErrors  0x00000008
#define kCertificateStatusNoRevocationMechanism  0x00000010
#define kCertificateStatusUnableToCheckRevocation  0x00000020
#define kCertificateStatusRevoked  0x00000030
#define kCertificateStatusInvalid  0x00000040
#define kCertificateStatusWeakSignatureAlgorithm  0x00000080
#define kCertificateStatusNotInDNS  0x00000100
#define kCertificateStatusNonUniqueName  0x00000200
#define kCertificateStatusWeakKey  0x00000400
#define kCertificateStatusInfoMask  0xffff0000

struct nickel;
struct ni_rpc_response {
    struct nickel *ni;
    dict d;
};

int ni_rpc_send(struct nickel *ni, const char *command, dict args, void (*cb) (void *, dict),
        void *opaque);
int ni_rpc_send_sync(struct nickel *ni, const char *command, const dict args, dict *response);

int rpc_http_event(struct nickel *ni, void *opaque, const char *id, const char *opt,
        dict d, void *command_opaque);
int rpc_ac_event(struct nickel *ni, void *opaque, const char *id, const char *opt,
        dict d, void *command_opaque);
#endif

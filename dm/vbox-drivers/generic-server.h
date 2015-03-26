/*
 * Copyright 2012-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

typedef void (*svcCall_t) (void *, VBOXHGCMCALLHANDLE callHandle,
    uint32_t u32ClientID, void *pvClient, uint32_t u32Function,
    uint32_t cParms, VBOXHGCMSVCPARM paParms[]);
int generic_server_process_request(char *req, int reqsize, char** respbuf,
    int* respsize, int preallocated, svcCall_t svcCall, void *clientdata, int *g_HelperRc);


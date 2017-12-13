/*
 * Copyright 2015-2017, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _SF_QUOTA_H_
#define _SF_QUOTA_H_

struct quota_op {
    SHFLCLIENTDATA *client;
    SHFLHANDLE shflhandle;
    SHFLROOT root;
    uint64_t qmax, qcur;
    uint64_t filesize;
    int64_t delta;
    int islink;
    wchar_t path[MAX_PATH];
};

int quota_start_op(struct quota_op *op,
                   SHFLCLIENTDATA *client, SHFLROOT root,
                   SHFLHANDLE shflhandle, const wchar_t *path,
                   const wchar_t *guest_path);

uint64_t quota_get_filesize(struct quota_op *op);
int quota_set_delta(struct quota_op *op, int64_t delta);
int quota_complete_op(struct quota_op *op);

#endif

/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Michael Dales <michael@digitalflapjack.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef __WEBDAV_H__
#define __WEBDAV_H__

#include <time.h>

#include "queue.h"

typedef void (*DavIO) (void *opaque, const char *buf, size_t len);

typedef struct DavFSCallbacks {
    DavIO output;
} DavFSCallbacks;

struct http_parser;

typedef struct DavGetRequest {
    int fd;
    off_t offset;
    size_t left;
    char *payload;
} DavGetRequest;

typedef struct DavClient {
    struct http_parser *parser;
    DavFSCallbacks callbacks;
    void *opaque;
    LIST_ENTRY(DavClient) entry;

    char *host_dir;

    /* Incoming state */
    char *request_path;
    char *canonical_filename;
    char *current_header;
    FILE *put_file;

    /* Outgoing state */
    char *headerBuf;
    size_t headerSize;

    int complete;
    int close_connection;

    /* HTTP header values. */
    int depth;
    char *destination;
    char *overwrite;
    int use_range;
    size_t from, to;
    time_t last_modified;

    DavGetRequest *last_get_request;
} DavClient;

int dav_init(DavClient *dc, DavFSCallbacks *callbacks, const char *host_dir, void *opaque);
int dav_input(DavClient *dc, char *buf, size_t len);

int dav_write_ready(DavClient *dc);
int dav_close(DavClient *dc);

#endif /* __WEBDAV_H__ */

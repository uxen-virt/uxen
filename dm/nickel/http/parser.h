/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _HTTP_PARSER_H_
#define _HTTP_PARSER_H_

#include <dm/nickel/http-parser/http_parser.h>
#include <buff.h>
#define NUM_HEADERS 128

#define HS_NONE 0
#define HS_FIELD 1
#define HS_VALUE 2

#define PS_INIT         0
#define PS_HEADER       1
#define PS_HCOMPLETE    2
#define PS_MCOMPLETE    3

#define HTTP_PARSE_BUFF(p, buff)  parser_execute(p, (const char *)(buff->m), buff->len)
#define HTTP_PARSE_STR(p, s, len) parser_execute(p, (const char *)(s), len)

struct header_field {
    struct buff *name;
    struct buff *value;
};
struct http_header {
    int crt_header;
    int http_major;
    int http_minor;
    uint64_t content_length;
    size_t header_length;
    const char *method;
    int status_code;
    struct buff *url;
    struct header_field headers[NUM_HEADERS];
    size_t hint_size;
};

struct parser_ctx {
    int initialized;
    int req_type;
    size_t parsed_len;
    size_t message_len;
    struct http_parser parser;
    struct http_parser_settings settings;
    const char *body_at;
    int header_state;
    int msg_complete;
    int conn_close;
    int http_close;
    int parse_state;
    int parse_error;
    struct http_header h;
    int headers_parsed;
    void *hx;
};

size_t parser_execute(struct parser_ctx *p, const char *buf, size_t len);
bool parser_is_http_req(struct buff *b);
int parser_create_request(struct parser_ctx **p, void *hx);
int parser_create_response(struct parser_ctx **p, void *hx);
void parser_free(struct parser_ctx **pp);
void parser_reset(struct parser_ctx *p);
void parser_reset_header(struct http_header *h);
#endif

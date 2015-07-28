/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include "strings.h"
#include "parser.h"
#include <log.h>

#ifndef ULLONG_MAX
# define ULLONG_MAX ((uint64_t) -1) /* 2^64-1 */
#endif

/* req */
static int req_on_message_begin(struct http_parser *parser)
{
    struct parser_ctx *p = (struct parser_ctx *) parser->data;

    p->parse_state = PS_HEADER;
    return 0;
}

static int req_on_url(struct http_parser *parser, const char *at, size_t length)
{
    int ret = -1;
    struct parser_ctx *p = (struct parser_ctx *) parser->data;
    struct http_header *h = &p->h;

    if (!h->method)
        h->method = http_method_str(parser->method);

    if (!h->url && !buff_new_priv(&h->url, 256))
        goto out;
    if (buff_append(h->url, at, length) < 0)
        goto out;

    h->hint_size += length;
    ret = 0;
out:
    return ret;
}

static int req_on_header_field(struct http_parser *parser, const char *at, size_t length)
{
    int ret = -1;
    struct parser_ctx *p = (struct parser_ctx *) parser->data;
    struct http_header *h = &p->h;

    if (h->crt_header >= NUM_HEADERS - 1)
        goto out;

    if (p->header_state == HS_VALUE)
        h->crt_header++;
    p->header_state = HS_FIELD;
    if (!h->headers[h->crt_header].name && !buff_new_priv(&h->headers[h->crt_header].name, 64))
        goto out;
    if (buff_append(h->headers[h->crt_header].name, at, length) < 0)
        goto out;
    h->hint_size += length;
    ret = 0;
out:
    return ret;
}

static int req_on_header_value(struct http_parser *parser, const char *at, size_t length)
{
    int ret = -1;
    struct parser_ctx *p = (struct parser_ctx *) parser->data;
    struct http_header *h = &p->h;

    if (h->crt_header >= NUM_HEADERS - 1)
        goto out;

    p->header_state = HS_VALUE;
    if (!h->headers[h->crt_header].value && !buff_new_priv(&h->headers[h->crt_header].value, 64))
        goto out;
    if (buff_append(h->headers[h->crt_header].value, at, length) < 0)
        goto out;
    h->hint_size += length;
    ret = 0;
out:
    return ret;
}

static int req_on_headers_complete(struct http_parser *parser)
{
    struct parser_ctx *p = (struct parser_ctx *) parser->data;
    struct http_header *h = &p->h;

    h->http_major = parser->http_major;
    h->http_minor = parser->http_minor;
    h->header_length = parser->nread;
    if (parser->content_length != ULLONG_MAX)
        h->content_length = parser->content_length;
    if (h->crt_header >= NUM_HEADERS - 1)
        return -1;
    if (h->headers[h->crt_header].value)
        h->crt_header++;
    p->parse_state = PS_HCOMPLETE;
    p->msg_complete = 1;
    return 0;
}

static int req_on_message_complete(struct http_parser *parser)
{
    struct parser_ctx *p = (struct parser_ctx *) parser->data;

    p->parse_state = PS_MCOMPLETE;
    return 0;
}

static int req_on_body(struct http_parser* parser, const char *at, size_t length)
{
    struct parser_ctx *p = (struct parser_ctx *) parser->data;

    p->body_at = at;
    return 0;
}


/* resp */
static int resp_on_message_begin(struct http_parser *parser)
{
    struct parser_ctx *p = (struct parser_ctx *) parser->data;

    p->parse_state = PS_HEADER;
    return 0;
}

static int resp_on_status_complete(struct http_parser *parser)
{
    struct parser_ctx *p = (struct parser_ctx *) parser->data;

    p->h.status_code = p->parser.status_code;
    return 0;
}

static int resp_on_headers_complete(struct http_parser *parser)
{
    struct parser_ctx *p = (struct parser_ctx *) parser->data;

    if (!p->h.status_code)
        p->h.status_code = p->parser.status_code;
    p->h.http_major = parser->http_major;
    p->h.http_minor = parser->http_minor;
    p->h.header_length = parser->nread;
    if (parser->content_length != ULLONG_MAX)
        p->h.content_length = parser->content_length;
    p->parse_state = PS_HCOMPLETE;

    if (p->h.crt_header >= NUM_HEADERS - 1)
        return -1;

    if (p->h.headers[p->h.crt_header].value)
        p->h.crt_header++;

    NETLOG5("%s: hx %"PRIxPTR, __FUNCTION__, (uintptr_t) p->hx);
    if (!p->conn_close && !p->keep_alive) {
        int i;

        for (i = 0; i < p->h.crt_header; i++) {
            if (!p->h.headers[i].name || !p->h.headers[i].value)
                continue;
            if (strcasecmp(BUFF_CSTR(p->h.headers[i].name), S_CONNECTION) != 0 &&
                    strcasecmp(BUFF_CSTR(p->h.headers[i].name), S_PROXY_CONNECTION) != 0) {

                continue;
            }

            if (strcasecmp(BUFF_CSTR(p->h.headers[i].value), S_CLOSE) == 0)
                p->conn_close = 1;
            else if (strcasecmp(BUFF_CSTR(p->h.headers[i].value), S_KEEPALIVE) == 0)
                p->keep_alive = 1;

            break;
        }
    }

    if (!(parser->flags & F_CHUNKED) && parser->content_length == ULLONG_MAX)
        p->http_close = 1;

    return 0;
}

static int resp_on_message_complete(struct http_parser *parser)
{
    struct parser_ctx *p = (struct parser_ctx *) parser->data;

    NETLOG5("%s: hx %"PRIxPTR, __FUNCTION__, (uintptr_t) p->hx);
    p->h.status_code = p->parser.status_code;
    p->msg_complete = 1;
    p->parse_state = PS_MCOMPLETE;

    if (!p->http_close && !(parser->flags & F_CHUNKED) && parser->content_length == ULLONG_MAX)
        p->http_close = 1;

    return 0;
}

static int resp_on_header_field(struct http_parser *parser, const char *at, size_t length)
{
    int ret = -1;
    struct parser_ctx *p = (struct parser_ctx *) parser->data;
    struct http_header *h = &p->h;

    if (p->parser.status_code && !p->h.status_code)
        p->h.status_code = p->parser.status_code;

    if (h->crt_header >= NUM_HEADERS - 1)
        goto out;

    if (p->header_state == HS_VALUE)
        h->crt_header++;
    p->header_state = HS_FIELD;
    if (!h->headers[h->crt_header].name && !buff_new_priv(&h->headers[h->crt_header].name, 64))
        goto out;
    if (buff_append(h->headers[h->crt_header].name, at, length) < 0)
        goto out;
    NETLOG5("%s: hx %"PRIxPTR" '%s'", __FUNCTION__, (uintptr_t) p->hx,
            BUFF_CSTR(h->headers[h->crt_header].name));
    h->hint_size += length;
    ret = 0;
out:
    return ret;
}

static int resp_on_header_value(struct http_parser *parser, const char *at, size_t length)
{
    int ret = -1;
    struct parser_ctx *p = (struct parser_ctx *) parser->data;
    struct http_header *h = &p->h;

    if (h->crt_header >= NUM_HEADERS - 1)
        goto out;

    p->header_state = HS_VALUE;
    if (!h->headers[h->crt_header].value && !buff_new_priv(&h->headers[h->crt_header].value, 64))
        goto out;
    if (buff_append(h->headers[h->crt_header].value, at, length) < 0)
        goto out;
    NETLOG5("%s: hx %"PRIxPTR" '%s'", __FUNCTION__, (uintptr_t) p->hx,
            BUFF_CSTR(h->headers[h->crt_header].value));
    h->hint_size += length;
    ret = 0;
out:
    return ret;
}

int parser_create_request(struct parser_ctx **pp, void *hx)
{
    int ret = -1;
    struct parser_ctx *parser;

    parser = calloc(1, sizeof(*parser));
    if (!parser)
        goto out;
    parser->settings.on_message_begin = req_on_message_begin;
    parser->settings.on_url = req_on_url;
    parser->settings.on_header_field = req_on_header_field;
    parser->settings.on_header_value = req_on_header_value;
    parser->settings.on_headers_complete = req_on_headers_complete;
    parser->settings.on_message_complete = req_on_message_complete;
    parser->settings.on_body = req_on_body;
    parser->parser.data = parser;
    parser->hx = hx;
    parser->req_type = 1;
    parser_reset(parser);

    *pp = parser;
    ret = 0;
out:
    return ret;
}

int parser_create_response(struct parser_ctx **pp, void *hx)
{
    int ret = -1;
    struct parser_ctx *parser;

    parser = calloc(1, sizeof(*parser));
    if (!parser)
        goto out;
    parser->settings.on_message_begin = resp_on_message_begin;
    parser->settings.on_status_complete = resp_on_status_complete;
    parser->settings.on_headers_complete = resp_on_headers_complete;
    parser->settings.on_header_field = resp_on_header_field;
    parser->settings.on_header_value = resp_on_header_value;
    parser->settings.on_message_complete = resp_on_message_complete;
    parser->parser.data = parser;
    parser->hx = hx;
    parser->req_type = 0;
    parser_reset(parser);

    *pp = parser;
    ret = 0;
out:
    return ret;
}

size_t parser_execute(struct parser_ctx *p, const char *b, size_t l)
{
    size_t ret = 0;

    if (l == 0)
        goto out;

    p->body_at = NULL;
    ret = http_parser_execute(&p->parser, &p->settings, b, l);
    p->parsed_len += ret;
    if (!p->h.header_length) {
        if (p->body_at) {
            assert(p->body_at - b > 0 && p->body_at - b <= l);
            p->h.header_length = p->parsed_len - ret + (p->body_at - b);
        } else if (p->parse_state == PS_HCOMPLETE || p->parse_state == PS_MCOMPLETE) {
            p->h.header_length = p->parsed_len;
        }
    }

    if (p->h.header_length && !p->message_len) {
        p->message_len = p->h.header_length;
        if (p->h.content_length > 0)
            p->message_len += p->h.content_length;
    }

out:
    return ret;
}

void parser_reset(struct parser_ctx *p)
{
    int i;

    //http_parser_init(&p->parser, p->req_type ? HTTP_REQUEST : HTTP_RESPONSE);
    http_parser_init(&p->parser, HTTP_BOTH);

    p->h.crt_header = 0;
    p->h.hint_size = 0;
    p->h.method = NULL;
    p->h.status_code = 0;
    p->h.http_major = p->h.http_minor = 0;
    p->h.content_length = 0;
    p->h.header_length = 0;

    BUFF_RESET(p->h.url);
    for (i = 0; i < NUM_HEADERS; i++) {
        buff_free(&p->h.headers[i].name);
        buff_free(&p->h.headers[i].value);
    }

    p->body_at = NULL;
    p->header_state = HS_NONE;
    p->parse_state = PS_INIT;
    p->parsed_len = 0;
    p->message_len = 0;
    p->msg_complete = 0;
    p->conn_close = 0;
    p->keep_alive = 0;
    p->parse_error = 0;
    p->http_close = 0;
    p->headers_parsed = 0;
}

void parser_reset_header(struct http_header *h)
{
    int i;

    if (!h)
        return;

    for (i = 0; i < NUM_HEADERS; i++) {
        buff_free(&h->headers[i].name);
        buff_free(&h->headers[i].value);
    }

    buff_free(&h->url);
    memset(h, 0, sizeof (*h));
}

void parser_free(struct parser_ctx **pp)
{
    struct parser_ctx *p = *pp;

    if (!p)
        return;

    parser_reset_header(&p->h);
    free(p);
    *pp = NULL;
}

bool parser_is_http_req(struct buff *b)
{
    struct http_parser parser;
    size_t l;
    http_parser_settings settings = {0};

    http_parser_init(&parser, HTTP_REQUEST);
    l = http_parser_execute(&parser, &settings, (char*)b->m, b->len);
    if (l == b->len)
        return true;
    NETLOG4("%s: parsed %lu out of %lu", __FUNCTION__, l, b->len);
    NETLOG4("%s: http parser: %s %s", __FUNCTION__, http_errno_name(HTTP_PARSER_ERRNO(&parser)),
            http_errno_description(HTTP_PARSER_ERRNO(&parser)));
    return false;
}

/*
 * Copyright 2013-2018, Bromium, Inc.
 * Author: Michael Dales <michael@digitalflapjack.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>

#ifndef _WIN32
#include <xlocale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

#define __strftime_variant(s, max, f, t, loc) strftime_l((s), (max), (f), (t), (loc))
#else
#define __strftime_variant(s, max, f, t, loc) strftime((s), (max), (f), (t))
#endif

#ifdef QEMU_UXEN
#include "debug.h"
#include "nickel/http-parser/http_parser.h"
#else
#include "http_parser.h"
#endif

#include "webdav.h"

#ifdef __APPLE__
#ifndef st_mtime
#define st_mtime st_mtimespec.tv_sec
#endif
#ifndef st_ctime
#define st_ctime st_ctimespec.tv_sec
#endif
#endif

typedef enum {
    DAV_DEPTH_UNDEF = 0,
    DAV_DEPTH_ZERO,
    DAV_DEPTH_ONE,
    DAV_DEPTH_INF,
} DavDepth;

int dav_init(DavClient *dc, DavFSCallbacks *callbacks, const char *host_dir,
        void *opaque)
{
    memset(dc, 0, sizeof(DavClient));
    dc->parser = malloc(sizeof(http_parser));
    if (!dc->parser) {
        debug_printf("webdav: Failed to allocate memory for http parser !\n");
        return -1;
    }

    http_parser_init(dc->parser, HTTP_REQUEST);
    dc->parser->data = (void*) dc;

    dc->callbacks = *callbacks;
#ifndef _WIN32
    dc->host_dir = realpath(host_dir, NULL);
#else
    dc->host_dir = _fullpath(NULL, host_dir, 0);
#endif
    if (!dc->host_dir) {
        debug_printf("webdav: Failed to find real path for %s\n", host_dir);
        free(dc->parser);
        return -1;
    }

    dc->opaque = opaque;
    return 0;
}

static void dav_flush(DavClient *dc)
{
    if (dc->headerSize > 0) {
        dc->callbacks.output(dc->opaque, dc->headerBuf, dc->headerSize);
        dc->headerSize = 0;
        free(dc->headerBuf);
        dc->headerBuf = NULL;
    }
}

static void dav_send(DavClient *dc, const char *buf, size_t len)
{
    dav_flush(dc);
    dc->callbacks.output(dc->opaque, buf, len);
}

static void dav_header(DavClient *dc, char *fmt, ...)
{
    char *buf, *tmp;
    va_list ap;
    size_t len, realloc_size;
    va_start(ap, fmt);

    vasprintf(&buf, fmt, ap);
    va_end(ap);

    if (!buf) {
        debug_printf("webdav: Failed to allocate memory for header field\n");
        goto err;
    }

    len = strlen(buf);

    realloc_size = dc->headerSize + len + 2;
    if (dc->headerSize >= realloc_size) {
        warnx("webdav %s: alloc len overflow fail 1\n", __FUNCTION__);
        goto err;
    }
    if (len >= realloc_size) {
        warnx("webdav %s: alloc len overflow fail 2 (len=%"PRIuSIZE")\n", __FUNCTION__, len);
        goto err;
    }

    tmp = realloc(dc->headerBuf, realloc_size);
    if (!tmp) {
        warnx("webdav %s: failed to expand header buffer\n", __FUNCTION__);
        goto err;
    }
    dc->headerBuf = tmp;
    memcpy(dc->headerBuf + dc->headerSize, buf, len);
    dc->headerSize += len;
    dc->headerBuf[dc->headerSize++] = '\r';
    dc->headerBuf[dc->headerSize++] = '\n';
err:
    free(buf);
    return;
}

static inline void dav_format_time_rfc1123(char *buffer, size_t sz, time_t t)
{
    __strftime_variant(buffer, sz, "%a, %d %b %Y %H:%M:%S GMT",
                       gmtime(&t), NULL);
}

static inline void dav_format_time_rfc3339(char *buffer, size_t sz, time_t t)
{
    __strftime_variant(buffer, sz, "%Y-%m-%dT%H:%M:%S%z",
                       localtime(&t), NULL);
}

static inline time_t dav_parse_time(const char* buffer)
{
#ifndef _WIN32
    struct tm tval;
    if (strptime(buffer, "%a, %d %b %Y %H:%M:%S GMT", &tval) == NULL) {
        return 0;
    }
    return mktime(&tval);
#else
    debug_printf("%s: not implemented!\n", __FUNCTION__);
    return 0;
#endif
}

static char* dav_url_decode(const char *str)
{
    char *tmp;
    char *ptr;
    size_t len;
    
    if (str == NULL) {
        return NULL;
    }

    /* transform "absolute URL" into "relative URL" */
    if (strncasecmp(str, "http://", 7) == 0) {

        /* find the third '/' or empty */
        const char *p = (const char *) str;

        p = strchr(p, '/');
        if (p) {
            p = strchr(p + 1, '/');
            if (p) {
                p = strchr(p + 1, '/');
                str = p ? p : "/";
            }
        }
    }

    /* the output string will either be same length or shorter */
    len = strlen(str);
    if (len > len + 1) {
        warnx("webdav %s: alloc len overflow fail\n", __FUNCTION__);
        return NULL;
    }
    tmp = (char *)malloc(len + 1);
    if (tmp == NULL) {
        return NULL;
    }

    ptr = tmp;
    memset(tmp, 0, strlen(str) + 1);

    const char *end = str + strlen(str);
    while (str < end) {
        int c;
        int match = sscanf(str, "%%%02x", &c);
        if (match) {
            *ptr++ = (c & 0xFF);
            str += 3;
        } else {
            *ptr++ = *str;
            str += 1;
        }
    }
    *ptr = '\0';

    return tmp;
}

static char *dav_url_encode(const char *str)
{
    const char hex[] = "0123456789abcdef";
    char *pstr;
    char *buf;
    char *pbuf;
    unsigned char c;
    size_t len, alloc_size;

    pstr = (char*)str;
    len = strlen(str);
    alloc_size = (len * 3) + 1;
    if (len > alloc_size) {
        warnx("webdav %s: alloc len overflow fail\n", __FUNCTION__);
        return NULL;
    }

    buf = (char *)malloc(alloc_size);
    if (!buf) {
        warnx("webdav %s malloc fail\n", __FUNCTION__);
        return NULL;
    }
    pbuf = buf;

    do {
        c = *pstr++;
        switch (c) {
            case '\0':
            case '/':
            case '-':
            case '_':
            case '.':
            case '~':
                *pbuf++ = c;
                break;
            default:
                if (isalnum(c)) {
                    *pbuf++ = c;
                } else {
                    *pbuf++ = '%';
                    *pbuf++ = hex[(c & 0xf0) >> 4];
                    *pbuf++ = hex[ c & 0x0f ];
                }
                break;
        }
    } while (c);
    return buf;
}

static void dav_header_date(DavClient *dc)
{
    time_t rawtime;
    char buffer[80];

    time(&rawtime);
    dav_format_time_rfc1123(buffer, sizeof(buffer), rawtime);
    dav_header(dc, "Date: %s", buffer);
}

static void dav_header_end(DavClient *dc, int close_connection)
{
    dav_header_date(dc);
    dav_header(dc, "Accept-Ranges: bytes");
    if (close_connection) {
        dav_header(dc, "Connection: close");
    }
    dav_header(dc, "");
}

static int dav_generic(DavClient *dc, int code)
{
    char *text;

    switch (code) {
        case 200: text = "OK"; break;
        case 201: text = "Created"; break;
        case 202: text = "Created"; break;
        case 204: text = "No content"; break;
        case 304: text = "Not Modified"; break;
        case 400: text = "Bad Request"; break;
        case 403: text = "Forbidden"; break;
        case 404: text = "Not found"; break;
        case 405: text = "Method Not Allowed"; break;
        case 409: text = "Conflict"; break;
        case 412: text = "Precondition Failed"; break;
        case 415: text = "Unsupported Media Type"; break;
        case 416: text = "Requested Range not satisfiable"; break;
        case 500: text = "Internal Server Error"; break;
        case 501: text = "Not implemented"; break;
        default:
            text = "??";
            break;
    }

    dav_header(dc, "HTTP/1.1 %d %s", code, text);
    dav_header(dc, "Content-Length: 0");
    dav_header(dc, "Content-Type: application/octet-stream");
    dav_header_end(dc, !http_should_keep_alive(dc->parser));
    debug_printf("Response status: %d\n", code);

    return 0;
}

static int dav_redirect_index(DavClient *dc)
{
    dav_header(dc, "HTTP/1.1 301 Moved Permanently");
    dav_header(dc, "Content-Length: 0");
    dav_header(dc, "Content-Type: application/octet-stream");
    dav_header(dc, "Location: %s%s%s", dc->request_path,
            (dc->request_path[strlen(dc->request_path) - 1] == '/') ? "" : "/",
            "index.html");
    dav_header_end(dc, !http_should_keep_alive(dc->parser));

    return 0;
}

static inline char *dav_mkpath(DavClient *dc, const char *fn)
{
    char *s;
    asprintf(&s, "%s/%s", dc->host_dir, fn);
    return s;
}

static inline char *dav_memrchr(char* a, char c, size_t len)
{
    char *p;

    if (len != 0) {
        p = a + (len - 1);
        while (p >= a) {
            if (*p == c)
                return p;
            p--;
        }
    }

    return NULL;
}

#ifndef _WIN32
static char * dav_normalize_path(const char * src, size_t src_len) {

        char * res;
        size_t res_len, alloc_size;

        const char * ptr = src;
        const char * end = &src[src_len];
        const char * next;

        if (src_len > 0) {
            alloc_size = src_len + 1;
            if (src_len > alloc_size) {
                warnx("webdav %s: alloc len overflow fail\n", __FUNCTION__);
                return NULL;
            }
        } else {
            alloc_size = 2;
        }

        res = malloc(alloc_size);
        if (!res) {
            return NULL;
        }
        res_len = 0;

        for (ptr = src; ptr < end; ptr=next+1) {
                size_t len;
                next = memchr(ptr, '/', end-ptr);
                if (next == NULL) {
                        next = end;
                }
                len = next-ptr;
                switch(len) {
                case 2:
                        if (ptr[0] == '.' && ptr[1] == '.') {
                                const char * slash = dav_memrchr(res, '/', res_len);
                                if (slash != NULL) {
                                        res_len = slash - res;
                                }
                                continue;
                        }
                        break;
                case 1:
                        if (ptr[0] == '.') {
                                continue;

                        }
                        break;
                case 0:
                        continue;
                }
                res[res_len++] = '/';
                memcpy(&res[res_len], ptr, len);
                res_len += len;
        }

        if (res_len == 0) {
                res[res_len++] = '/';
        }
        res[res_len] = '\0';
        return res;
}
#endif

#ifndef _WIN32
static char* dav_make_canonical_path(char* path)
{
    /* this is different from realpath in that it doesn't require the path exists */

    char *canonical = dav_normalize_path(path, strlen(path));
    if (canonical != NULL)
        return canonical;

    /* if it doesn't exist, check for a single leaf node */
    char *p = path + strlen(path);
    while ((p > path) && (*p != '/'))
        p--;

    if (p == path)
        return NULL;

    *p = '\0';
    canonical = dav_normalize_path(path, strlen(path));
    *p = '/';

    if (canonical == NULL)
        return NULL;

    if (strcmp(p, "/..") == 0) {
        free(canonical);
        return NULL;
    }

    char *s;
    asprintf(&s, "%s%s", canonical, p);
    free(canonical);
    return s;
}
#endif

static char* dav_canonical_name(DavClient *dc, const char *request_path)
{
    /* combine with the mount point, and get a canonical filename */
    char* unsafe_path = dav_mkpath(dc, request_path);
    if (unsafe_path == NULL) {
        return NULL;
    }
#ifndef _WIN32
    char* canonical_unsafe_path = dav_make_canonical_path(unsafe_path);
    free(unsafe_path);
    if (canonical_unsafe_path == NULL) {
        return NULL;
    }
    /* now test that the canonical path starts with a complete version of the original mount point */
    int host_dir_len = strlen(dc->host_dir);
    if (strncmp(dc->host_dir, canonical_unsafe_path, host_dir_len) != 0) {
        free(canonical_unsafe_path);
        return NULL;
    }
    /* and finally the names should either be identical or len(host_dir)+1 should be a / */
    if ((host_dir_len < strlen(canonical_unsafe_path)) && (canonical_unsafe_path[host_dir_len] != '/')) {
        free(canonical_unsafe_path);
        return NULL;
    }
    return canonical_unsafe_path;
#else
    return _fullpath(NULL, unsafe_path, 0);
#endif
}


/* Use large chunk size to improve disk throughput. */
#define CHUNK_SIZE (1 << 20)

int dav_write_ready(DavClient *dc)
{
    size_t take;
    ssize_t r = 0;

    if (dc->last_get_request == NULL)
        return 0;

    take = dc->last_get_request->left < CHUNK_SIZE ? dc->last_get_request->left : CHUNK_SIZE;
    do {
        /* win32 does not have pread() */
        lseek(dc->last_get_request->fd, dc->last_get_request->offset, SEEK_SET);
        r = read(dc->last_get_request->fd, dc->last_get_request->payload, take);
    } while (r < 0 && errno == EINTR);

    if (r > 0) {
        char lenbuffer[16];
        sprintf(lenbuffer, "%"PRIxSIZE"\r\n", r);
        dav_send(dc, lenbuffer, strlen(lenbuffer));
        dav_send(dc, dc->last_get_request->payload, r);
        dav_send(dc, "\r\n", 2);
    } else {
        /* failed, so tidy up */
        goto complete;
    }

    if (r >= dc->last_get_request->left) {
        dav_send(dc, "0\r\n\r\n", 5);
        goto complete;
    }

    dc->last_get_request->left -= r;
    dc->last_get_request->offset += r;
    return 0;

complete:
    debug_printf("Completed get request\n");
    free(dc->last_get_request->payload);
    close(dc->last_get_request->fd);
    free(dc->last_get_request);
    dc->last_get_request = NULL;

    return 0;
}

typedef struct ContentType {
    const char *ext;
    const char *type;
} ContentType;

static ContentType dav_content_types[] = {
    { ".css", "text/css" },
    { ".gif", "image/gif" },
    { ".html", "text/html" },
    { ".ico", "image/x-icon" },
    { ".jpeg", "image/jpeg" },
    { ".jpg", "image/jpeg" },
    { ".jpg", "image/jpeg" },
    { ".js", "application/javascript" },
    { ".png", "image/png" },
    { ".ttf", "application/x-font-ttf" },
    { ".txt", "text/plain" },
    { ".xhtml", "application/xhtml+xml" },
    { ".xml", "text/xml" },
};

static const char *dav_mime_type_from_ext(const char *fn)
{
    int i;
    size_t len = strlen(fn);

    for (i = 0; i < sizeof(dav_content_types) / sizeof(dav_content_types[0]); ++i) {
        ContentType *t = &dav_content_types[i];
        size_t tl = strlen(t->ext);
        if (len >= tl && !memcmp(fn + len - tl, t->ext, tl)) {
            return t->type;
        }
    }
    debug_printf("%s: using default context type!\n", __FUNCTION__);
    return "application/octet-stream";
}

int dav_GET_OR_HEAD(DavClient *dc, int send_body)
{
    size_t left;
    off_t offset;
    void *payload = NULL;
    int f;
    struct stat st;
    int status;
    char lastmod[80];
    DavGetRequest *request;

    if (dc->last_get_request != NULL)
    {
        /* XXX: Mostly expect this to fail */
        debug_printf("overlapping GET requests!\n");
        status = 500;
        goto error;
    }

    if (stat(dc->canonical_filename, &st) < 0) {
        debug_printf("webdav: error %d stating '%s'\n", errno, dc->canonical_filename);
        status = 404;
        goto error;
    }    

    if ((st.st_mode & 0770000) != S_IFREG) {
        return dav_redirect_index(dc);
    }

#ifndef _WIN32
    if (st.st_mtime <= dc->last_modified) {
        status = 304;
        goto error;
    }
#endif

    f = open(dc->canonical_filename, O_RDONLY | O_BINARY);
    if (f < 0) {
        debug_printf("webdav: error %d opening '%s'\n", errno, dc->canonical_filename);
        status = 404;
        goto error;
    }

    if (!st.st_size) {
        status = 204;
        goto error;
    }

    payload = malloc(st.st_size < CHUNK_SIZE ? st.st_size : CHUNK_SIZE);
    if (!payload) {
        status = 500;
        goto error;
    }

    dav_format_time_rfc1123(lastmod, sizeof(lastmod), (time_t) st.st_mtime);
    if (dc->use_range) {
        offset = dc->from;
        if ((dc->to == 0) || (dc->to >= st.st_size)) {
            dc->to = st.st_size - 1;
        }
        left = 1 + dc->to - dc->from;

        /* 416: Range not satisfiable */
        if (offset >= st.st_size) {
            status = 416;
            free(payload);
            goto error;
        }

        dav_header(dc, "HTTP/1.1 206 Partial Content");
        dav_header(dc, "Content-Range: %"PRIuSIZE"-%"PRIuSIZE"/%"PRIuSIZE"", dc->from, dc->to, st.st_size);
    } else {
        offset = 0;
        left = st.st_size;
        dav_header(dc, "HTTP/1.1 200 OK");
    }
    dav_header(dc, "Content-Type: %s",
            dav_mime_type_from_ext(dc->canonical_filename));
    dav_header(dc, "Last-Modified: %s", lastmod);
    if (send_body) {
        dav_header(dc, "Transfer-Encoding: chunked");
    } else {
        dav_header(dc, "Content-Length: %"PRIuSIZE"", left);
    }

    dav_header_end(dc, !http_should_keep_alive(dc->parser));
    dav_flush(dc);

    if (send_body) {

        /* set up the get request  */
        request = (DavGetRequest*)malloc(sizeof(DavGetRequest));
        if (request == NULL) {
            free(payload);
            status = 500;
            goto error;
        }
        request->fd = f;
        request->offset = offset;
        request->left = left;
        request->payload = payload;
        dc->last_get_request = request;

        /* do the first chunk */
        dav_write_ready(dc);
    } else {
        free(payload);
    }

    return 0;

error:
    debug_printf("status: %d\n", status);
    if (status != 416) {
        dav_generic(dc, status);
    } else {
        dav_header(dc, "HTTP/1.1 416 Requested Range Not Satisfiable");
        dav_header(dc, "Content-Length: 0");
        dav_header(dc, "Content-Type: application/octet-stream");
        dav_header(dc, "Content-Range: bytes */%"PRIuSIZE"", st.st_size);
        dav_header_end(dc, !http_should_keep_alive(dc->parser));
    }
    dav_flush(dc);
    return 0;
}

int dav_OPTIONS(DavClient *dc)
{
    /* copied from the OS X Server web dav headers */
    dav_header(dc, "HTTP/1.1 200 OK");
    dav_header(dc, "Allow: OPTIONS,GET,HEAD,POST,DELETE,TRACE,PROPFIND,PROPPATCH,COPY,MOVE,LOCK,UNLOCK,MKCOL");
    dav_header(dc, "DAV: 1,2"); /* Protocol version 1 for now, implies read-only on OSX. */
    dav_header(dc, "Content-Type: application/octet-stream");
    dav_header(dc, "Content-Disposition: attachment");
    dav_header(dc, "Content-Length: 0");
    dav_header_end(dc, !http_should_keep_alive(dc->parser));
    return 0;
}

/* Canned XML PROPFIND responses. */
const char prop_begin[] = 
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
    "<D:multistatus xmlns:D=\"DAV:\">\n";

const char prop_dir[] =
    "  <D:response>\n"
    "    <D:href>%s</D:href>\n"
    "      <D:propstat>\n"
    "      <D:prop>\n"
    "        <D:resourcetype><D:collection/></D:resourcetype>\n"
    "        <D:creationdate>%s</D:creationdate>\n"
    "        <D:getlastmodified>%s</D:getlastmodified>\n"
    "        <D:getetag>\"%x\"</D:getetag>\n"
    "        <D:quota-available-bytes>100000000</D:quota-available-bytes>\n"
    "        <D:quota-used-bytes>0</D:quota-used-bytes>\n"
    "      </D:prop>\n"
    "      <D:status>HTTP/1.1 200 OK</D:status>\n"
    "    </D:propstat>\n"
    "  </D:response>\n";

const char prop_end[] = "</D:multistatus>\n" ;

const char prop_file[] = 
    "  <D:response>\n"
    "    <D:href>%s</D:href>\n"
    "      <D:propstat>\n"
    "      <D:prop>\n"
    "        <D:resourcetype/>\n"
    "        <D:getcontentlength>%"PRIuSIZE"</D:getcontentlength>\n"
    "        <D:creationdate>%s</D:creationdate>\n"
    "        <D:getlastmodified>%s</D:getlastmodified>\n"
    "        <D:getetag>\"%x\"</D:getetag>\n"
    "        <D:getcontenttype>application/octet-stream</D:getcontenttype>\n"
    "      </D:prop>\n"
    "      <D:status>HTTP/1.1 200 OK</D:status>\n"
    "    </D:propstat>\n"
    "  </D:response>\n";

/* Returns 0 on success, non-0 on failure. The caller must free the buffer. */
int dav_bprintf(char **buffer, char **end, size_t *size, const char *fmt, ...)
{
    size_t len;
    size_t ret;
    va_list ap;

    len = *end - *buffer;
    if (*size < len) {
        warnx("webdav %s: forman len overflow fail\n", __FUNCTION__);
        return -1;
    }

    va_start(ap, fmt);
    ret = (size_t)vsnprintf(*buffer + len, *size - len, fmt, ap);
    va_end(ap);
    if (ret >= (*size - len)) {

        int realloc_size = len + ret + 1;
        if (ret >= realloc_size) {
            warnx("webdav %s: alloc len overflow fail 1\n", __FUNCTION__);
            return -1;
        }
        if (len >= realloc_size) {
            warnx("webdav %s: alloc len overflow fail 2\n", __FUNCTION__);
            return -1;
        }

        char *bigger_buffer = realloc(*buffer, realloc_size);
        if (!bigger_buffer) {
            warnx("%s realloc of size %d failed with %d", __FUNCTION__,
                  realloc_size, errno);
            return -1;
        } else {
            *buffer = bigger_buffer;
        }
        *size = len + ret + 1;
        va_start(ap, fmt);
        ret = vsnprintf(*buffer + len, *size - len, fmt, ap);
        va_end(ap);
    }
    *end = *buffer + len + ret;

    return 0;
}


int dav_PROPFIND(DavClient *dc)
{
    struct stat st;
    char *b = NULL;
    char *e = NULL;
    size_t sz = 0;
    int status;
    int r;
    char *name;
    char creation[80];
    char lastmod[80];
    int isdir;
            
    r = stat(dc->canonical_filename, &st);
    if (r != 0) {
        status = 404;
        goto error;
    }
    isdir = ((st.st_mode & S_IFDIR) == S_IFDIR);

    if (dav_bprintf(&b, &e, &sz, prop_begin)) {
        status = 500;
        goto error;
    }

    if (isdir) {
        dav_format_time_rfc3339(creation, sizeof(creation), (time_t) st.st_ctime);
        dav_format_time_rfc1123(lastmod, sizeof(lastmod), (time_t) st.st_mtime);
        if (dav_bprintf(&b, &e, &sz, prop_dir, dc->request_path,
                        creation, lastmod, (uint32_t)st.st_mtime)) {
            status = 500;
            goto error;
        }
    }

    if (dc->depth != DAV_DEPTH_ZERO && isdir) {
        struct dirent *ent;
        DIR *dir;
        dir = opendir(dc->canonical_filename);

        if (dir) {
            while ((ent = readdir(dir))) { 

                if ((strcmp(ent->d_name, ".") == 0) || (strcmp(ent->d_name, "..") == 0)) {
                    continue;
                }                

                asprintf(&name, "%s/%s", dc->canonical_filename, ent->d_name);
                if (!name) {
                    status = 500;
                    goto error;
                }

                r = stat(name, &st);
                free(name);
                if (r < 0) {
                    debug_printf("stat error: %s\n", strerror(errno));
                    continue;
                }

                if ((st.st_mode & (S_IFREG | S_IFDIR)) == 0) {
                    debug_printf("Not a regular file/directory!\n");
                    continue;
                }

                asprintf(&name, "%s%s", dc->request_path, ent->d_name);
                char *encoded_name = dav_url_encode(name);
                free(name);
                if ((st.st_mode & S_IFREG) == S_IFREG) {
                    dav_format_time_rfc3339(creation, sizeof(creation), (time_t) st.st_ctime);
                    dav_format_time_rfc1123(lastmod, sizeof(lastmod), (time_t) st.st_mtime);
                    if (dav_bprintf(&b, &e, &sz, prop_file, encoded_name, (size_t)st.st_size,
                                creation, lastmod, (uint32_t) st.st_mtime) < 0) {
                        free(encoded_name);
                        status = 500;
                        goto error;
                    }
                } else {
                    dav_format_time_rfc3339(creation, sizeof(creation), (time_t) st.st_ctime);
                    dav_format_time_rfc1123(lastmod, sizeof(lastmod), (time_t) st.st_mtime);
                    if (dav_bprintf(&b, &e, &sz, prop_dir, encoded_name,
                                    creation, lastmod, (uint32_t)st.st_mtime)) {
                        free(encoded_name);
                        status = 500;
                        goto error;
                    }
                }
                free(encoded_name);
            }
        }
    }

    if (dc->depth == DAV_DEPTH_ZERO && !isdir) {
        debug_printf("stat %s at depth zero\n", dc->canonical_filename);

        r = stat(dc->canonical_filename, &st);
        if (r < 0) {
            debug_printf("error stating %s : %s\n", name, strerror(errno));
            status = 404;
            goto error;
        }

        dav_format_time_rfc3339(creation, sizeof(creation), (time_t) st.st_ctime);
        dav_format_time_rfc1123(lastmod, sizeof(lastmod), (time_t) st.st_mtime);
        char *encoded_name = dav_url_encode(dc->request_path);
        if (dav_bprintf(&b, &e, &sz, prop_file, encoded_name, (size_t)st.st_size,
                    creation, lastmod, (uint32_t) st.st_mtime) < 0) { 
            free(encoded_name);
            status = 500;
            goto error;
        }
        free(encoded_name);
    }

    if (dav_bprintf(&b, &e, &sz, prop_end) < 0) {
        status = 500;
        goto error;
    }

    dav_header(dc, "HTTP/1.1 207 Multi-Status");
    dav_header(dc, "Content-Type: text/xml; charset=\"utf-8\"");
    dav_header(dc, "Content-Length: %u", e - b);
    dav_header_end(dc, !http_should_keep_alive(dc->parser));
    dav_send(dc, b, e - b);
    free(b);
    return 0;

error:
    free(b);
    return dav_generic(dc, status);
}

int dav_PUT(DavClient *dc)
{
    /* simple test - if we have an open FILE* at this point all is well, otherwise it's a fail */
    if (!dc->put_file) {
        return dav_generic(dc, 403);
    }
    return dav_generic(dc, 201);
}

int dav_LOCK(DavClient *dc)
{
    return dav_generic(dc, 204);
}

int dav_UNLOCK(DavClient *dc)
{
    return dav_generic(dc, 204);
}

int dav_MOVE(DavClient *dc)
{
    int r;;
    const char *dst = dc->destination;
    if (!strncmp(dst, "http://", 7)) {
        dst += 7;
        while (*dst != '/' && *dst != 0) {
            ++dst;
        }
    }
    while (*dst == '/') {
        ++dst;
    }

    char* decoded_path = dav_url_decode(dst); 
    if (decoded_path == NULL) {
        return -1;
    }

    char* canonical_dest = dav_canonical_name(dc, decoded_path);
    free(decoded_path);
    if (canonical_dest == NULL) {
        return dav_generic(dc, 403);
    }
    debug_printf("MOVE: %s -> %s\n", dc->canonical_filename, canonical_dest);
    if (dc->overwrite && dc->overwrite[0] == 'T') {
        unlink(canonical_dest);
    }

    r = rename(dc->canonical_filename, canonical_dest);
    free(canonical_dest);

    if (r >= 0) {
        return dav_generic(dc, 201);
    } else {
        if (r < 0 && errno == EPERM) {
            return dav_generic(dc, 204);
        }
        switch (errno) {
            case EEXIST:
                return dav_generic(dc, 412);
            case ENOENT:
                return dav_generic(dc, 409);
            default:
                return dav_generic(dc, 403);
        }
    }
}

int dav_DELETE(DavClient *dc)
{
    int r;
    r = remove(dc->canonical_filename);
    if (r >= 0) {
        return dav_generic(dc, 200);
    } else {
        warn("Failed to remove %s", dc->canonical_filename);
        switch (errno) {
            case ENOENT:
                return dav_generic(dc, 404);
            default:
                return dav_generic(dc, 403);
        }
    }
}

int dav_MKCOL(DavClient *dc)
{
    assert(dc->canonical_filename != NULL);

#ifndef _WIN32
    int r;
    r = mkdir(dc->canonical_filename, 0700);
    if (r >= 0) {
#else
    if (CreateDirectory(dc->canonical_filename, NULL)) {
#endif
        return dav_generic(dc, 201);
    } else {
        Wwarn("Failed to mkdir %s", dc->canonical_filename);
        switch (errno) {
#ifndef _WIN32
            case EDQUOT:
#endif
            case ENOSPC:
                return dav_generic(dc, 507);
            case EROFS:
                return dav_generic(dc, 415);
            default:
                return dav_generic(dc, 403);
        }
    }
}

/* typedef int (*http_cb) (http_parser*); */
int dav_url_cb(http_parser* parser, const char *buf, size_t len)
{
    DavClient *dc = parser->data;

    char *rawpath = malloc(len + 1);
    if (rawpath == NULL) {
        return -1;
    }
    memcpy(rawpath, buf, len);
    rawpath[len] = '\0';

    char *path;
    path = dav_url_decode(rawpath);
    free(rawpath);
    if (path == NULL) {
        return -1;
    }

    char *canonical_path = dav_canonical_name(dc, path);
    if (canonical_path == NULL) {
        free(path);
        return -1;
    }

    dc->request_path = path;
    dc->canonical_filename = canonical_path;

    return 0;
}

int dav_header_cb(http_parser* parser, const char *buf, size_t len)
{
    DavClient *dc = parser->data;
    char *h;
    if (len > len + sizeof(char)) {
        warnx("webdav %s: alloc len overflow fail\n", __FUNCTION__);
        return -1;
    }
    h = malloc(len + sizeof(char));
    if (!h) {
        return -1;
    }
    memcpy(h, buf, len);
    h[len] = '\0';
    if (dc->current_header) {
        free((void*)dc->current_header);
    }
    dc->current_header = h;
    return 0;
}

int dav_value_cb(http_parser* parser, const char *buf, size_t len)
{
    DavClient *dc = parser->data;
    char *h = dc->current_header;
    char *v;
    int ret = 0;
    
    if (!h) {
        return -1;
    }

    if (len > len + sizeof(char)) {
        warnx("webdav %s: alloc len overflow fail\n", __FUNCTION__);
        return -1;
    }
    v = malloc(len + sizeof(char));
    if (!v) {
        free((void*)h);
        dc->current_header = NULL;
        return -1;
    }
    memcpy(v, buf, len);
    v[len] = '\0';

    if (!strcasecmp(h, "Depth")) {
        if (!strcmp(v, "0")) {
            dc->depth = DAV_DEPTH_ZERO;
        } else if (!strcmp(v, "1")) {
            dc->depth = DAV_DEPTH_ONE;
        } else if (!strcasecmp(v, "infinity")) {
            dc->depth = DAV_DEPTH_INF;
        } else {
            dc->depth = DAV_DEPTH_UNDEF;
        }
    } else if (!strcasecmp(h, "Destination")) {
        dc->destination = v;
        v = NULL;
    } else if (!strcasecmp(h, "Overwrite")) {
        dc->overwrite = v;
        v = NULL;
    } else if (!strcasecmp(h, "Range") ||
                    !strcasecmp(h, "Content-Range")) {
        if (sscanf(v, "bytes=%"PRIuSIZE"-%"PRIuSIZE"", &dc->from, &dc->to) == 2) {
            dc->use_range = 1;
            if (dc->from > dc->to) {
                Wwarn("NEGATIVE CONTENT-LENGTH: %s, cannot continue", v);
                ret = -1;
                goto out;
            }
        } else if (sscanf(v, "bytes=%"PRIuSIZE"-", &dc->from) == 1) {
            dc->use_range = 1;
            dc->to = 0;
        } else if (sscanf(v, "bytes=-%"PRIuSIZE"", &dc->to) == 1) {
            dc->use_range = 1;
            dc->from = 0;
        } else {
            debug_printf("UNABLE TO PARSE %s\n", v);
            dc->use_range = 0;
        }
    } else if (!strcasecmp(h, "If-Modified-Since")) {
        dc->last_modified = dav_parse_time(v);
    } else {
        debug_printf("UNHANDLED: %s=%s\n", h, v);
    }

out:
    free(h);
    free(v);
    dc->current_header = NULL;

    return ret;
}

int dav_body_cb(http_parser* parser, const char *buf, size_t len)
{
    DavClient *dc = parser->data;

    /* We should only get body data on a PUT request, so check */
    if (parser->method == HTTP_PUT) {
        if (!dc->put_file)
            return -1;

        if (fwrite(buf, 1, len, dc->put_file) < len) {
            debug_printf("Error putting data into file: %s\n", strerror(errno));
            fclose(dc->put_file);
            dc->put_file = NULL;
            return 0;
        }
    }

    /* For non PUT things we don't care about the body, so it can
     * all fall on the floor */
    return 0;
}

int dav_header_complete_cb(http_parser *parser)
{
    DavClient *dc = parser->data;

    /* at this point we should have enough information
     * to know if it's a put request, and create somewhere
     * to stash the body (ahem). */
    if (parser->method == HTTP_PUT) {
        if (dc->canonical_filename == NULL) {
            debug_printf("Error: got a PUT method but no filename\n");
            return -1;
        }
        debug_printf("put open: %s, use_range: %d, from: %"PRIuSIZE", to: %"PRIuSIZE"\n",
                dc->canonical_filename, dc->use_range, dc->from, dc->to);
        if(dc->put_file) {
            fclose(dc->put_file);
        }
        dc->put_file = fopen(dc->canonical_filename, dc->use_range?"rb+":"wb");
        if (!dc->put_file) {
            Wwarn("Error: %s, failed to fopen", dc->canonical_filename);
            return -1;
        }
        if (dc->use_range) {
            int res = fseek(dc->put_file, dc->from, SEEK_SET);
            if (res) {
                Wwarn("Error: %s, failed to fseek to %"PRIuSIZE,
                      dc->canonical_filename, dc->from);
                return -1;
            }
        }
    }

    return 0;
}

int dav_complete_cb(http_parser *parser)
{
    DavClient *dc = parser->data;
    int r;

    debug_printf("handle %s %s\n", http_method_str(parser->method), dc->request_path);
    switch (parser->method) {
        case HTTP_GET:
            r = dav_GET_OR_HEAD(dc, 1);
            break;
        case HTTP_HEAD:
            r = dav_GET_OR_HEAD(dc, 0);
            break;
        case HTTP_OPTIONS:
            r = dav_OPTIONS(dc);
            break;
        case HTTP_PROPFIND:
            r = dav_PROPFIND(dc);
            break;
        case HTTP_PUT:
            r = dav_PUT(dc);
            break;
        case HTTP_MOVE:
            r = dav_MOVE(dc);
            break;
        case HTTP_LOCK:
            r = dav_LOCK(dc);
            break;
        case HTTP_UNLOCK:
            r = dav_UNLOCK(dc);
            break;
        case HTTP_DELETE:
            r = dav_DELETE(dc);
            break;       
        case HTTP_MKCOL:
            r = dav_MKCOL(dc);
            break;
        default:
            debug_printf("unhandled method %s\n", http_method_str(parser->method));
            r = dav_generic(dc, 400);
            break;
    }
    

    dav_flush(dc);

    /* Reset parsing state. */
    free(dc->current_header);dc->current_header = NULL;
    free(dc->destination); dc->destination = NULL;
    free(dc->request_path); dc->request_path = NULL;
    free(dc->canonical_filename); dc->canonical_filename = NULL;
    free(dc->overwrite); dc->overwrite = NULL;
    dc->use_range = 0;
    dc->last_modified = 0;

    if (dc->put_file) 
        fclose(dc->put_file);
    dc->put_file = NULL;

    dc->close_connection = !http_should_keep_alive(parser);
    return r;
}

int dav_input(DavClient *dc, char *buf, size_t len)
{
    struct http_parser_settings settings = {
        .on_url = dav_url_cb,
        .on_header_field = dav_header_cb,
        .on_header_value = dav_value_cb,
        .on_headers_complete = dav_header_complete_cb,
        .on_body = dav_body_cb,
        .on_message_complete = dav_complete_cb,
    };

    if (http_parser_execute(dc->parser, &settings, buf, len) < len) {
        return -1;
    } else {
        return dc->close_connection ? -1 : 0;
    }
}

int dav_close(DavClient *dc)
{
    debug_printf("%p: closing connection\n", dc);
    if (dc->last_get_request != NULL) {
        free(dc->last_get_request->payload);
        close(dc->last_get_request->fd);
        free(dc->last_get_request);
    }

    free(dc->host_dir);
    free(dc->parser);

    /* Reset parsing state. */
    free(dc->current_header);
    free(dc->destination);
    free(dc->request_path);
    free(dc->canonical_filename);
    free(dc->overwrite);
    free(dc->headerBuf);

    if (dc->put_file)
        fclose(dc->put_file);

    memset(dc, 0, sizeof(*dc));

    return 0;
}


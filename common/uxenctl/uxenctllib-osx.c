/*
 *  uxenctllib-osx.c
 *  uxen
 *
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 *
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <mm_malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mach/mach_types.h>
#include <mach-o/loader.h>
#include <mach/mach_port.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <uxen_ioctl.h>

#include <uxen_def.h>

#include "uxenctllib.h"

#include <IOKit/kext/KextManager.h> // KextManagerLoadKextWithURL

#define UXEN_KEXT_IDENTIFIER "org.uxen.uxen"

static int
notificationport_init(UXEN_HANDLE_T h)
{
    kern_return_t kr;
    mach_port_qos_t qos;

    bzero(&qos, sizeof(qos));
    qos.prealloc = 1;

    kr = mach_port_allocate_qos(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &qos, &h->notify_port);
    if (kr != KERN_SUCCESS) {
        warnx("mach_port_allocate() failed");
        errno = ENOMEM;
        return -1;
    }

    kr = IOConnectSetNotificationPort(h->connection, 0, h->notify_port, 0);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), h->notify_port);
        h->notify_port = MACH_PORT_NULL;;
        warnx("IOConnectSetNotificationPort failed\n");
        errno = EFAULT;
        return -1;
    }

    return 0;
}

static void
notificationport_free(UXEN_HANDLE_T h)
{

    if (h->notify_port)
        mach_port_deallocate(mach_task_self(), h->notify_port);
    h->notify_port = MACH_PORT_NULL;
}

int
uxen_ioctl(UXEN_HANDLE_T h, uint64_t ctl, ...)
{
    va_list ap;
    int ret;
    void *in = NULL;
    void *out = NULL;
    size_t in_len = 0;
    size_t out_len = 0;

    va_start(ap, ctl);

    if (ctl & (UXEN_IOR_FLAG | UXEN_IOW_FLAG)) {
        void *buf = va_arg(ap, void *);
        size_t buf_len = (ctl >> 8) & 0x3fffff;

        if (ctl & UXEN_IOR_FLAG) {
            out = buf;
            out_len = buf_len;
        }
        if (ctl & UXEN_IOW_FLAG) {
            in = buf;
            in_len = buf_len;
        }
    }

    ret = IOConnectCallMethod(h->connection, (uint32_t)ctl,
                              NULL, 0,
                              in, in_len,
                              NULL, 0,
                              out, &out_len);

    if (ret) {
        errno = ret;
        ret = -1;
    }

    va_end(ap);

    return ret;
}

static int
load_kext(const char *path, const char *dependency_dir_path)
{
    struct stat st;
    int ret;
    int rc;
    CFStringRef cfpath;
    CFURLRef url;
    CFURLRef dependency_dir_url;
    CFArrayRef dependency_dir_url_list = NULL;

    /* Check dir and perms because OSX won't give us useful errors */
    ret = stat(path, &st);
    if (ret) {
        warn("stat %s", path);
        return -1;
    }

    if (st.st_uid != 0 || st.st_gid != 0) {
        fprintf(stderr, "Wrong permissions on %s. Should be root:wheel\n",
                path);
        errno = EPERM;
        return -1;
    }

    if (dependency_dir_path) {
        cfpath = CFStringCreateWithCString(NULL,
                                           dependency_dir_path,
                                           kCFStringEncodingUTF8);
        dependency_dir_url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault,
                                                           cfpath,
                                                           kCFURLPOSIXPathStyle,
                                                           true);
        dependency_dir_url_list = CFArrayCreate(NULL,
                                            (const void**)&dependency_dir_url,
                                            1,
                                            &kCFTypeArrayCallBacks);
        CFRelease(cfpath);
        CFRelease(dependency_dir_url);
    }
    cfpath = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
    url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, cfpath,
                                        kCFURLPOSIXPathStyle, true);
    rc = KextManagerLoadKextWithURL(url, dependency_dir_url_list);
    CFRelease(url);
    CFRelease(cfpath);
    if (dependency_dir_url_list) {
        CFRelease(dependency_dir_url_list);
    }

    if (rc != kOSReturnSuccess) {
        fprintf(stderr, "KextManagerLoadKextWithURL %s: rc=%x\n", path, rc);
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static int
unload_kext(const char *identifier)
{
    CFStringRef id;
    int rc;

    id = CFStringCreateWithCString(NULL, identifier, kCFStringEncodingUTF8);
    rc = KextManagerUnloadKextWithIdentifier(id);
    CFRelease(id);

    if (rc != kOSReturnSuccess) {
        fprintf(stderr, "KextManagerUnloadKextWithIdentifer %s: rc=%x\n",
                identifier, rc);
        errno = EINVAL;
        return -1;
    }

    return 0;
}

struct service_match_params
{
    const char *name;
    io_service_t service;
};

static void
service_match_cb(void *ref, io_iterator_t iter)
{
    struct service_match_params *p = ref;
    io_service_t service;

    service = IOIteratorNext(iter);
    while (service) {
        io_name_t name;

        IOObjectGetClass(service, name);
        if (!strcmp(p->name, name)) {
            p->service = service;
            break;
        }

        IOObjectRelease(service);
        service = IOIteratorNext(iter);
    }
}

static io_connect_t
io_service_connect(const char *name)
{
    task_port_t self;
    CFDictionaryRef dict;
    io_connect_t connection = 0;
    kern_return_t kr;
    IONotificationPortRef np;
    CFRunLoopSourceRef runloopsrc;
    io_iterator_t iter;
    struct service_match_params match_params;

    self = mach_task_self();
    dict = IOServiceMatching(name);
    np = IONotificationPortCreate(kIOMasterPortDefault);
    runloopsrc = IONotificationPortGetRunLoopSource(np);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), runloopsrc,
                       kCFRunLoopDefaultMode);

    match_params.name = name;
    match_params.service = 0;
    kr = IOServiceAddMatchingNotification(np, kIOFirstMatchNotification,
                                          dict, service_match_cb, &match_params,
                                          &iter);
    if (kr != KERN_SUCCESS) {
        warnx("IOServiceAddMatchingNotification failed\n");
        errno = EINVAL;
        return 0;
    }
    service_match_cb(&match_params, iter);

    while (!match_params.service)
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0, true);

    IONotificationPortDestroy(np);
    IOObjectRelease(iter);

    kr = IOServiceOpen(match_params.service, self, 0, &connection);
    if (kr != KERN_SUCCESS) {
        IOObjectRelease(match_params.service);
        warnx("IOServiceOpen failed (%x)\n", kr);
        errno = ENOENT;
        return 0;
    }

    return connection;
}

int
uxen_manage_driver(BOOLEAN install, BOOLEAN fail_ok, const char *path)
{
    UXEN_HANDLE_T h;
    int ret = -1;

    /* Check user permissions because OSX won't give us useful errors */
    if (geteuid() != 0) {
        warnx("root permissions required to load/unload kernel extensions");
        errno = EPERM;
        return -1;
    }

    if (install) {
        char buf[PATH_MAX];
        char *cwd = NULL;

        if (!path)
            path = cwd = getcwd(NULL, PATH_MAX);

        snprintf(buf, PATH_MAX, "%s/uxen.kext", path);

        if (cwd)
            free(cwd);

        ret = load_kext(buf, path);
        /* fallback trying to load the kext from default location */
        if (ret && errno == ENOENT)
            ret = load_kext("/Library/Extensions/uxen.kext",
                            "/Library/Extensions");
        if (!ret) {
            h = calloc(1, sizeof(*h));
            if (!h)
                return 0;
            ret = -1;
            h->connection = io_service_connect("uxen_driver");
            if (h->connection) {
                ret = uxen_load_xnu_symbols(h, "/mach_kernel");
                if (ret)
                    /* Try loading in new (10.10) location instead */
                    ret = uxen_load_xnu_symbols(h, "/System/Library/Kernels/kernel");
                if (ret)
                    errx(1, "load symbols failed");
            }
            uxen_close(h);
        }
    } else {
        ret = unload_kext(UXEN_KEXT_IDENTIFIER);
    }

    if (fail_ok)
        ret = 0;

    return ret;
}

UXEN_HANDLE_T
uxen_open(int index, BOOLEAN install_driver, const char *path)
{
    UXEN_HANDLE_T h = NULL;
    int ret = -1;

    h = calloc(1, sizeof(*h));
    if (!h) {
        errno = ENOMEM;
        goto out;
    }

    h->connection = io_service_connect("uxen_driver");
    if (!h->connection)
        goto out;

    ret = notificationport_init(h);

  out:
    if (ret != 0 && h) {
        if (h->connection)
            IOServiceClose(h->connection);
        free(h);
        h = NULL;
    }

    if (h || !install_driver || index != 0)
        return h;

    ret = uxen_manage_driver(TRUE, FALSE, path);
    if (ret)
        return NULL;

    /* try again */
    return uxen_open(index, FALSE, path);
}

void
uxen_close(UXEN_HANDLE_T h)
{

    if (h->connection)
        IOServiceClose(h->connection);
    notificationport_free(h);
    free(h);
}

struct nlist_64 {
    union {
        uint32_t  n_strx;   /* index into the string table */
    } n_un;
    uint8_t n_type;         /* type flag, see below */
    uint8_t n_sect;         /* section number or NO_SECT */
    uint16_t n_desc;        /* see <mach-o/stab.h> */
    uint64_t n_value;       /* value of this symbol (or stab offset) */
};

struct load_command *
find_load_command(struct mach_header_64 *mh, uint32_t cmd)
{
    struct load_command *lc, *foundlc = NULL;

    /* First LC begins straight after the mach header */
    lc = (struct load_command *)((uint64_t)mh + sizeof(struct mach_header_64));
    while ((uint64_t)lc < (uint64_t)mh + (uint64_t)mh->sizeofcmds) {
        if (lc->cmd == cmd) {
            foundlc = (struct load_command *)lc;
            break;
        }

        /* Next LC */
        lc = (struct load_command *)((uint64_t)lc + (uint64_t)lc->cmdsize);
    }

    /* Return the load command (NULL if we didn't find it) */
    return foundlc;
}

int
uxen_load_xnu_symbols(UXEN_HANDLE_T h, const char *filename)
{
    int ret;
    int file_fd;
    void *buf = NULL;
    struct stat statbuf;
    struct mach_header_64 *mh;
    struct symtab_command *symtab = NULL;
    struct nlist_64 *sym_ent = NULL;
    uint32_t i;
    struct uxen_syms_desc usd;
    struct uxen_xnu_sym *xnu_syms = NULL;

    ret = open(filename, O_RDONLY);
    file_fd = ret;
    if (file_fd < 0) {
        fprintf(stderr, "open %s: %s\n", filename, strerror(errno));
        goto out;
    }

    ret = fstat(file_fd, &statbuf);
    if (ret) {
        fprintf(stderr, "fstat %s: %s\n", filename, strerror(errno));
        goto out;
    }

    buf = mmap(NULL, statbuf.st_size, PROT_READ, MAP_FILE | MAP_PRIVATE,
             file_fd, 0);
    if (!buf || buf == MAP_FAILED)
        goto out;

    mh = buf;
    ret = -1;
    if (mh->magic != MH_MAGIC_64) {
        fprintf(stderr, "FAIL: magic number doesn't match - 0x%x\n", mh->magic);
        goto out;
    }
    symtab = (struct symtab_command *)find_load_command(mh, LC_SYMTAB);
    if (!symtab) {
        fprintf(stderr, "FAIL: couldn't find SYMTAB\n");
        goto out;
    }

    usd.usd_size = symtab->nsyms * sizeof (struct uxen_xnu_sym) +
                   symtab->strsize;
    usd.usd_symnum = symtab->nsyms;
    xnu_syms = _mm_malloc(usd.usd_size, PAGE_SIZE);
    if (!xnu_syms) {
        fprintf(stderr, "FAIL: allocation failed\n");
        goto out;
    }
    if (mlock(xnu_syms, usd.usd_size)) {
        perror("mlock()");
        goto out;
    }
    usd.usd_xnu_syms = (uint8_t *)xnu_syms;

    sym_ent = (void *)((char *)buf + symtab->symoff);
    for (i = 0; i < symtab->nsyms; i++) {
        xnu_syms[i].addr = sym_ent->n_value;
        xnu_syms[i].name = sym_ent->n_un.n_strx;
        sym_ent++;
    }
    memcpy(xnu_syms + i, (char *)buf + symtab->stroff, symtab->strsize);

    ret = uxen_ioctl(h, UXENLOADSYMS, &usd);
    if (ret < 0) {
        perror("ioctl(UXENLOADSYMS)");
        goto out;
    }

    ret = 0;
out:
    if (xnu_syms) {
        munlock(xnu_syms, usd.usd_size);
        _mm_free(xnu_syms);
    }

    if (buf && buf != MAP_FAILED)
        munmap(buf, statbuf.st_size);

    if (file_fd >= 0)
        close(file_fd);

    return ret;
}

int
uxen_signal_event(UXEN_HANDLE_T h, void *ev)
{
    int ret;

    ret = uxen_ioctl(h, UXENSIGNALEVENT, ev);
    if (ret < 0)
        warn("ioctl(UXENSIGNALEVENT,%p)", ev);

    return ret;
}

int
uxen_poll_event(UXEN_HANDLE_T h, uint32_t *events)
{
    int ret;
    struct uxen_event_poll_desc uepd;

    ret = uxen_ioctl(h, UXENPOLLEVENT, &uepd);
    if (ret < 0)
        warn("ioctl(UXENPOLLEVENT)");
    else
        *events = uepd.signaled;

    return ret;
}

int
uxen_event_init(UXEN_EVENT_HANDLE_T *ev)
{
    UXEN_EVENT_HANDLE_T e;

    e = calloc(1, sizeof(uint32_t));
    if (!e)
        return -1;

    *ev = e;

    return 0;
}

int
uxen_event_wait(UXEN_HANDLE_T h, UXEN_EVENT_HANDLE_T ev, int timeout_ms)
{
    int ret;
    mach_port_t port;
    kern_return_t kr;
    struct {
        mach_msg_header_t hdr;
        char buf[1024];
    } msg;
    mach_msg_option_t opts;
    uint32_t signaled;

    port = h->notify_port;
    if (!port)
        return EINVAL;

    msg.hdr.msgh_size = sizeof(msg);
    msg.hdr.msgh_remote_port = MACH_PORT_NULL;
    msg.hdr.msgh_local_port = port;

    opts = MACH_RCV_MSG;
    if (timeout_ms >= 0)
        opts |= MACH_RCV_TIMEOUT;
    else
        timeout_ms = MACH_MSG_TIMEOUT_NONE;

    kr = mach_msg(&msg.hdr, opts, 0, sizeof(msg), port, timeout_ms,
                  MACH_PORT_NULL);
    if (kr != MACH_MSG_SUCCESS) {
        warnx("%s: mach_msg failed (%x)", __FUNCTION__, kr);
        return EINVAL;
    }

    ret = uxen_poll_event(h, &signaled);
    if (ret) {
        warnx("%s: poll events failed", __FUNCTION__);
        return EINVAL;
    }

    return 1;
}

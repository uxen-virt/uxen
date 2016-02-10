/*
 * QEMU System Emulator
 *
 * Copyright (c) 2003-2008 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// #include "qemu-common.h"
// #include "net.h"
// #include "console.h"
// #include "sysemu.h"
// #include "qemu-timer.h"
// #include "qemu-char.h"
// #include "block.h"
// #include "hw/usb.h"
// #include "hw/baum.h"
// #include "hw/msmouse.h"
// 
// #include <unistd.h>
// #include <fcntl.h>
// #include <signal.h>
// #include <time.h>
// #include <errno.h>
// #include <sys/time.h>
// #include <zlib.h>
// 
// #ifndef _WIN32
// #include <sys/times.h>
// #include <sys/wait.h>
// #include <termios.h>
// #include <sys/mman.h>
// #include <sys/ioctl.h>
// #include <sys/resource.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <net/if.h>
// #ifdef __NetBSD__
// #include <net/if_tap.h>
// #endif
// #ifdef __linux__
// #include <linux/if_tun.h>
// #endif
// #include <arpa/inet.h>
// #include <dirent.h>
// #include <netdb.h>
// #include <sys/select.h>
// #ifdef _BSD
// #include <sys/stat.h>
// #ifdef __FreeBSD__
// #include <libutil.h>
// #include <dev/ppbus/ppi.h>
// #include <dev/ppbus/ppbconf.h>
// #else
// #include <util.h>
// #endif
// #elif defined (__GLIBC__) && defined (__FreeBSD_kernel__)
// #include <freebsd/stdlib.h>
// #else
// #ifdef __linux__
// #include <pty.h>
// 
// #include <linux/ppdev.h>
// #include <linux/parport.h>
// #endif
// #ifdef __sun__
// #include <sys/stat.h>
// #include <sys/ethernet.h>
// #include <sys/sockio.h>
// #include <netinet/arp.h>
// #include <netinet/in.h>
// #include <netinet/in_systm.h>
// #include <netinet/ip.h>
// #include <netinet/ip_icmp.h> // must come after ip.h
// #include <netinet/udp.h>
// #include <netinet/tcp.h>
// #include <net/if.h>
// #include <syslog.h>
// #include <stropts.h>
// #endif
// #endif
// #endif
// 
// #include "qemu_socket.h"


#include "config.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <termios.h>
#include <util.h>
#include <sys/ioctl.h>
#endif

#include "qemu_glue.h"

#include "char.h"
#include "ioh.h"
#include "monitor.h"
#include "ns.h"
#include "sockets.h"
#include "timer.h"

#ifdef _WIN32
#define NO_UNIX_SOCKETS
#endif

/***********************************************************/
/* character device */

static TAILQ_HEAD(CharDriverStateHead, CharDriverState) chardevs =
    TAILQ_HEAD_INITIALIZER(chardevs);
static critical_section chardevs_lock;

static int initial_reset_issued;

void
chardev_init(void)
{

    critical_section_init(&chardevs_lock);
}

static void qemu_chr_event(CharDriverState *s, int event)
{
    if (!s->chr_event)
        return;
    s->chr_event(s->handler_opaque, event);
}

static void qemu_chr_reset_bh(void *opaque)
{
    CharDriverState *s = opaque;
    qemu_chr_event(s, CHR_EVENT_OPENED);
    bh_delete(s->bh);
    s->bh = NULL;
}

void qemu_chr_reset(CharDriverState *s)
{
    if (s->bh == NULL && initial_reset_issued) {
	s->bh = bh_new(qemu_chr_reset_bh, s);
	bh_schedule(s->bh);
    }
}

void qemu_chr_initial_reset(void)
{
    CharDriverState *chr;

    initial_reset_issued = 1;

    critical_section_enter(&chardevs_lock);
    TAILQ_FOREACH(chr, &chardevs, next) {
        qemu_chr_reset(chr);
    }
    critical_section_leave(&chardevs_lock);
}

int qemu_chr_can_write(CharDriverState *s)
{
    if (!s->chr_can_write)
        return 0;
    return s->chr_can_write(s->handler_opaque);
}

int qemu_chr_write(CharDriverState *s, const uint8_t *buf, int len)
{
    return s->chr_write(s, buf, len);
}

int qemu_chr_write_flush(CharDriverState *s)
{
    if (!s->chr_write_flush)
        return 0;
    return s->chr_write_flush(s);
}

int qemu_chr_ioctl(CharDriverState *s, int cmd, void *arg)
{
    if (!s->chr_ioctl)
        return -ENOTSUP;
    return s->chr_ioctl(s, cmd, arg);
}

int qemu_chr_can_read(CharDriverState *s)
{
    if (!s->chr_can_read)
        return 0;
    return s->chr_can_read(s->handler_opaque);
}

void qemu_chr_read(CharDriverState *s, uint8_t *buf, int len)
{
    s->chr_read(s->handler_opaque, buf, len);
}

void qemu_chr_accept_input(CharDriverState *s)
{
    if (s->chr_accept_input)
        s->chr_accept_input(s);
}

void qemu_chr_printf(CharDriverState *s, const char *fmt, ...)
{
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    qemu_chr_write(s, (uint8_t *)buf, strlen(buf));
    va_end(ap);
}

void qemu_chr_send_event(CharDriverState *s, int event)
{
    if (s->chr_send_event)
        s->chr_send_event(s, event);
}

struct chr_send_event_async_data {
    CharDriverState *chr;
    int event;
};

void
chr_send_event_async_cb(void *opaque)
{
    struct chr_send_event_async_data *data = 
        (struct chr_send_event_async_data *)opaque;

    if (data->chr->chr_send_event)
        data->chr->chr_send_event(data->chr, data->event);

    qemu_chr_put(data->chr);
}

void qemu_chr_send_event_async(CharDriverState *s, int event)
{
    BH *bh;
    struct chr_send_event_async_data *data;

    bh = bh_new_with_data(chr_send_event_async_cb,
                          sizeof(struct chr_send_event_async_data),
                          (void **)&data);
    if (!bh) {
        warnx("%s: bh_new_with_data failed", __FUNCTION__);
        return;
    }

    qemu_chr_get(s);
    data->chr = s;
    data->event = event;

    bh_schedule_one_shot(bh);
}

void qemu_chr_add_handlers(CharDriverState *s,
                           IOCanRWHandler *fd_can_read,
                           IOReadHandler *fd_read,
                           IOEventHandler *fd_event,
                           void *opaque)
{
    s->chr_can_read = fd_can_read;
    s->chr_read = fd_read;
    s->chr_event = fd_event;
    s->handler_opaque = opaque;
    if (s->chr_update_read_handler)
        s->chr_update_read_handler(s);
}

static int null_chr_write(CharDriverState *chr, const uint8_t *buf, int len)
{
    return len;
}

static CharDriverState *qemu_chr_open_null(struct io_handler_queue *iohq)
{
    CharDriverState *chr;

    chr = calloc(1, sizeof(CharDriverState));
    if (!chr)
        return NULL;
    chr->refcnt = 1;
    chr->iohq = iohq;

    chr->chr_write = null_chr_write;
    return chr;
}


#if defined(_WIN32)
int send_all(int fd, const void *buf, int len1)
{
    int ret, len;

    len = len1;
    while (len > 0) {
        ret = send(fd, buf, len, 0);
        if (ret < 0) {
            errno = WSAGetLastError();
            if (errno != WSAEWOULDBLOCK) {
                return -1;
            }
        } else if (ret == 0) {
            break;
        } else {
            buf += ret;
            len -= ret;
        }
    }
    return len1 - len;
}
#elif defined(__APPLE__)
int send_all(int fd, const void *buf, int len1)
{
    int ret, len;

    len = len1;
    while (len > 0) {
        ret = write(fd, buf, len);
        if (ret < 0) {
            if (errno != EWOULDBLOCK) {
                return -1;
            }
        } else if (ret == 0) {
            break;
        } else {
            buf += ret;
            len -= ret;
        }
    }
    return len1 - len;
}

#endif /* !_WIN32 */

#ifndef _WIN32

#define SEND_QUEUE_MAX 131072 /* 128K */

struct send_buf {
    TAILQ_ENTRY(send_buf) link;
    size_t off;
    size_t len;
    unsigned char data[];
};

struct send_queue {
    struct io_handler_queue *iohq;
    int fd;
    int eof;
    int err;
    TAILQ_HEAD(, send_buf) queue;
    critical_section lock;
    size_t len;
};

static void send_queue_write_cb(void *opaque)
{
    struct send_queue *sndq = opaque;
    struct send_buf *b;

    critical_section_enter(&sndq->lock);
    b = TAILQ_FIRST(&sndq->queue);
    if (b) {
        int rc = write(sndq->fd, b->data + b->off, b->len);

        switch (rc) {
        case 0:
            sndq->eof = 1;
            TAILQ_REMOVE(&sndq->queue, b, link);
            free(b);
            break;
        case -1:
            sndq->err = errno;
            TAILQ_REMOVE(&sndq->queue, b, link);
            free(b);
            break;
        default:
            b->len -= rc;
            b->off += rc;
            sndq->len -= rc;
            if (!b->len) {
                TAILQ_REMOVE(&sndq->queue, b, link);
                free(b);
            }
        }
    } else
        ioh_set_write_handler(sndq->fd, sndq->iohq, NULL, sndq);
    critical_section_leave(&sndq->lock);
}

static int send_queue_write(struct send_queue *sndq, const uint8_t *buf, size_t len)
{
    struct send_buf *b;

    if (sndq->eof)
        return 0;
    if (sndq->err) {
        errno = sndq->err;
        return -1;
    }
    if ((sndq->len + len) > SEND_QUEUE_MAX) {
        errno = EWOULDBLOCK;
        return -1;
    }

    b = malloc(sizeof(struct send_buf) + len);
    if (!b)
        return -1;
    b->off = 0;
    b->len = len;
    memcpy(b->data, buf, len);

    critical_section_enter(&sndq->lock);
    TAILQ_INSERT_TAIL(&sndq->queue, b, link);
    sndq->len += len;
    critical_section_leave(&sndq->lock);
    ioh_set_write_handler(sndq->fd, sndq->iohq, send_queue_write_cb, sndq);

    return len;
}

static void send_queue_flush(struct send_queue *sndq)
{
    struct send_buf *b;

    critical_section_enter(&sndq->lock);
    while ((b = TAILQ_FIRST(&sndq->queue))) {
        int rc;

        if (sndq->eof || sndq->err)
            goto release;

        rc = write(sndq->fd, b->data + b->off, b->len);
        switch (rc) {
        case 0:
            sndq->eof = 1;
            goto release;
        case -1:
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                break;
            sndq->err = errno;
            goto release;
        default:
            b->len -= rc;
            b->off += rc;
            sndq->len -= rc;
            if (!b->len)
                goto release;
        }

        continue;
  release:
        TAILQ_REMOVE(&sndq->queue, b, link);
        free(b);
    }
    critical_section_leave(&sndq->lock);
}

static void send_queue_cleanup(struct send_queue *sndq)
{
    struct send_buf *b;

    critical_section_enter(&sndq->lock);
    while ((b = TAILQ_FIRST(&sndq->queue))) {
        TAILQ_REMOVE(&sndq->queue, b, link);
        free(b);
    }
    critical_section_leave(&sndq->lock);

    ioh_set_write_handler(sndq->fd, sndq->iohq, NULL, sndq);
    critical_section_free(&sndq->lock);
}

static void send_queue_init(struct send_queue *sndq, struct io_handler_queue *iohq, int fd)
{
    sndq->iohq = iohq;
    sndq->fd = fd;
    TAILQ_INIT(&sndq->queue);
    critical_section_init(&sndq->lock);
    sndq->eof = 0;
    sndq->err = 0;
    sndq->len = 0;
}

typedef struct {
    int fd_in, fd_out;
    int max_size;
    struct send_queue sndq;
} FDCharDriver;

#define STDIO_MAX_CLIENTS 1
static int stdio_nb_clients = 0;

static int fd_chr_write(CharDriverState *chr, const uint8_t *buf, int len)
{
    FDCharDriver *s = chr->opaque;

    return send_queue_write(&s->sndq, buf, len);
}

static int fd_chr_write_flush(CharDriverState *chr)
{
    FDCharDriver *s = chr->opaque;

    send_queue_flush(&s->sndq);

    return 0;
}

static int fd_chr_read_poll(void *opaque)
{
    CharDriverState *chr = opaque;
    FDCharDriver *s = chr->opaque;

    s->max_size = qemu_chr_can_read(chr);
    return s->max_size;
}

static void fd_chr_read(void *opaque)
{
    CharDriverState *chr = opaque;
    FDCharDriver *s = chr->opaque;
    int size, len;
    uint8_t buf[1024];

    len = sizeof(buf);
    if (len > s->max_size)
        len = s->max_size;
    if (len == 0)
        return;
    size = read(s->fd_in, buf, len);
    if (size == 0) {
        /* peer FD has been closed. Remove fd_in from the active list.  */
        ioh_set_read_handler2(s->fd_in, chr->iohq, NULL, NULL, chr);
        qemu_chr_event(chr, CHR_EVENT_RESET);
        return;
    }
    if (size > 0) {
        qemu_chr_read(chr, buf, size);
    }
}

static void fd_chr_update_read_handler(CharDriverState *chr)
{
    FDCharDriver *s = chr->opaque;

    if (s->fd_in >= 0)
        ioh_set_read_handler2(s->fd_in, chr->iohq, fd_chr_read_poll, fd_chr_read, chr);
}

static void fd_chr_close(struct CharDriverState *chr)
{
    FDCharDriver *s = chr->opaque;

    if (s->fd_out >= 0) {
        send_queue_cleanup(&s->sndq);
        close(s->fd_out);
    }
    if (s->fd_in >= 0) {
        ioh_set_read_handler(s->fd_in, chr->iohq, NULL, chr);
        close(s->fd_in);
    }

    free(s);
}

/* open a character device to a unix fd */
static CharDriverState *qemu_chr_open_fd(int fd_in, int fd_out, struct io_handler_queue *iohq)
{
    CharDriverState *chr;
    FDCharDriver *s;

    socket_set_nonblock(fd_in);
    socket_set_nonblock(fd_out);

    chr = calloc(1, sizeof(CharDriverState));
    if (!chr)
        return NULL;
    chr->refcnt = 1;
    chr->iohq = iohq;

    s = calloc(1, sizeof(FDCharDriver));
    s->fd_in = fd_in;
    s->fd_out = fd_out;
    if (s->fd_out >= 0)
        send_queue_init(&s->sndq, iohq, s->fd_out);
    chr->opaque = s;
    chr->chr_write = fd_chr_write;
    chr->chr_write_flush = fd_chr_write_flush;
    chr->chr_update_read_handler = fd_chr_update_read_handler;
    chr->chr_close = fd_chr_close;

    qemu_chr_reset(chr);

    return chr;
}

static CharDriverState *qemu_chr_open_file_out(const char *file_out, struct io_handler_queue *iohq)
{
    int fd_out;

    fd_out = open(file_out, O_WRONLY | O_TRUNC | O_CREAT | O_BINARY, 0666);
    if (fd_out < 0)
        return NULL;
    return qemu_chr_open_fd(-1, fd_out, iohq);
}

static void
unix_chr_pipe_reconnect(void *opaque)
{
    CharDriverState *chr = opaque;
    FDCharDriver *s;
    char filename_out[256];

    if (!chr)
        return;
    s = chr->opaque;
    if (!s)
        return;

    if (s->fd_out < 0 || s->fd_out == s->fd_in)
        return;

    send_queue_cleanup(&s->sndq);
    close(s->fd_out);
    s->fd_out = -1;

    if (!chr->filename)
        return;

    filename_out[255] = 0;
    if (snprintf(filename_out, 255, "%s.out", chr->filename) < 0)
        return;
    s->fd_out = open(filename_out, O_RDWR | O_NONBLOCK | O_BINARY);
    if (s->fd_out >= 0)
        send_queue_init(&s->sndq, chr->iohq, s->fd_out);
}

static CharDriverState *qemu_chr_open_pipe(const char *filename, struct io_handler_queue *iohq)
{
    int fd_in, fd_out;
    char filename_in[256], filename_out[256];
    CharDriverState *chr;

    snprintf(filename_in, 256, "%s.in", filename);
    snprintf(filename_out, 256, "%s.out", filename);
    fd_in = open(filename_in, O_RDONLY | O_NONBLOCK | O_BINARY);
    fd_out = open(filename_out, O_RDWR | O_NONBLOCK | O_BINARY);
    if (fd_in < 0 || fd_out < 0) {
	if (fd_in >= 0)
	    close(fd_in);
	if (fd_out >= 0)
	    close(fd_out);
        fd_in = fd_out = open(filename, O_RDWR | O_BINARY);
        if (fd_in < 0)
            return NULL;
    }
    chr = qemu_chr_open_fd(fd_in, fd_out, iohq);
    if (!chr)
        return chr;
    chr->filename = strdup(filename);
    chr->chr_reconnect = unix_chr_pipe_reconnect;
    return chr;
}


#ifndef _WIN32
/* for STDIO, we handle the case where several clients use it
   (nographic mode) */

#define TERM_FIFO_MAX_SIZE 1

static uint8_t term_fifo[TERM_FIFO_MAX_SIZE];
static int term_fifo_size;

static int stdio_read_poll(void *opaque)
{
    CharDriverState *chr = opaque;

    /* try to flush the queue if needed */
    if (term_fifo_size != 0 && qemu_chr_can_read(chr) > 0) {
        qemu_chr_read(chr, term_fifo, 1);
        term_fifo_size = 0;
    }
    /* see if we can absorb more chars */
    if (term_fifo_size == 0)
        return 1;
    else
        return 0;
}

static void stdio_read(void *opaque)
{
    int size;
    uint8_t buf[1];
    CharDriverState *chr = opaque;

    size = read(0, buf, 1);
    if (size == 0) {
        /* stdin has been closed. Remove it from the active list.  */
        ioh_set_read_handler2(0, chr->iohq, NULL, NULL, chr);
        return;
    }
    if (size > 0) {
        if (qemu_chr_can_read(chr) > 0) {
            qemu_chr_read(chr, buf, 1);
        } else if (term_fifo_size == 0) {
            term_fifo[term_fifo_size++] = buf[0];
        }
    }
}

/* init terminal so that we can grab keys */
static struct termios oldtty;
static int old_fd0_flags;
static int term_atexit_done;

static void term_exit(void)
{
    tcsetattr (0, TCSANOW, &oldtty);
    fcntl(0, F_SETFL, old_fd0_flags);
}

static void term_init(void)
{
    struct termios tty;

    tcgetattr (0, &tty);
    oldtty = tty;
    old_fd0_flags = fcntl(0, F_GETFL);

    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
                          |INLCR|IGNCR|ICRNL|IXON);
    tty.c_oflag |= OPOST;
    tty.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN);
#if 0
    /* if graphical mode, we allow Ctrl-C handling */
    if (nographic)
        tty.c_lflag &= ~ISIG;
#endif
    tty.c_cflag &= ~(CSIZE|PARENB);
    tty.c_cflag |= CS8;
    tty.c_cc[VMIN] = 1;
    tty.c_cc[VTIME] = 0;

    tcsetattr (0, TCSANOW, &tty);

    if (!term_atexit_done++)
        atexit(term_exit);

    fcntl(0, F_SETFL, O_NONBLOCK);
}

static void qemu_chr_close_stdio(struct CharDriverState *chr)
{
    term_exit();
    stdio_nb_clients--;
    ioh_set_read_handler2(0, chr->iohq, NULL, NULL, chr);
    fd_chr_close(chr);
}

static CharDriverState *qemu_chr_open_stdio(struct io_handler_queue *iohq)
{
    CharDriverState *chr;

    if (stdio_nb_clients >= STDIO_MAX_CLIENTS)
        return NULL;
    chr = qemu_chr_open_fd(0, 1, iohq);
    chr->chr_close = qemu_chr_close_stdio;
    ioh_set_read_handler2(0, chr->iohq, stdio_read_poll, stdio_read, chr);
    stdio_nb_clients++;
    term_init();

    return chr;
}

#ifdef __sun__
/* Once Solaris has openpty(), this is going to be removed. */
int openpty(int *amaster, int *aslave, char *name,
            struct termios *termp, struct winsize *winp)
{
        const char *slave;
        int mfd = -1, sfd = -1;

        *amaster = *aslave = -1;

        mfd = open("/dev/ptmx", O_RDWR | O_NOCTTY);
        if (mfd < 0)
                goto err;

        if (grantpt(mfd) == -1 || unlockpt(mfd) == -1)
                goto err;

        if ((slave = ptsname(mfd)) == NULL)
                goto err;

        if ((sfd = open(slave, O_RDONLY | O_NOCTTY)) == -1)
                goto err;

        if (ioctl(sfd, I_PUSH, "ptem") == -1 ||
            (termp != NULL && tcgetattr(sfd, termp) < 0))
                goto err;

        if (amaster)
                *amaster = mfd;
        if (aslave)
                *aslave = sfd;
        if (winp)
                ioctl(sfd, TIOCSWINSZ, winp);

        return 0;

err:
        if (sfd != -1)
                close(sfd);
        close(mfd);
        return -1;
}

void cfmakeraw (struct termios *termios_p)
{
        termios_p->c_iflag &=
                ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
        termios_p->c_oflag &= ~OPOST;
        termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
        termios_p->c_cflag &= ~(CSIZE|PARENB);
        termios_p->c_cflag |= CS8;

        termios_p->c_cc[VMIN] = 0;
        termios_p->c_cc[VTIME] = 0;
}
#endif

#if defined(__linux__) || defined(__sun__) || defined(__FreeBSD__) \
    || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__APPLE__)

typedef struct {
    int fd;
    int connected;
    int polling;
    int read_bytes;
    QEMUTimer *timer;
} PtyCharDriver;

static void pty_chr_update_read_handler(CharDriverState *chr);
static void pty_chr_state(CharDriverState *chr, int connected);

static int pty_chr_write(CharDriverState *chr, const uint8_t *buf, int len)
{
    PtyCharDriver *s = chr->opaque;

    if (!s->connected) {
        /* guest sends data, check for (re-)connect */
        pty_chr_update_read_handler(chr);
        return 0;
    }
    return send_all(s->fd, buf, len);
}

static int pty_chr_read_poll(void *opaque)
{
    CharDriverState *chr = opaque;
    PtyCharDriver *s = chr->opaque;

    s->read_bytes = qemu_chr_can_read(chr);
    return s->read_bytes;
}

static void pty_chr_read(void *opaque)
{
    CharDriverState *chr = opaque;
    PtyCharDriver *s = chr->opaque;
    int size, len;
    uint8_t buf[1024];

    len = sizeof(buf);
    if (len > s->read_bytes)
        len = s->read_bytes;
    if (len == 0)
        return;
    size = read(s->fd, buf, len);
    if ((size == -1 && errno == EIO) ||
        (size == 0)) {
        pty_chr_state(chr, 0);
        return;
    }
    if (size > 0) {
        pty_chr_state(chr, 1);
        qemu_chr_read(chr, buf, size);
    }
}

static void pty_chr_update_read_handler(CharDriverState *chr)
{
    PtyCharDriver *s = chr->opaque;

    ioh_set_read_handler2(s->fd, chr->iohq, pty_chr_read_poll,
                          pty_chr_read, chr);
    s->polling = 1;
    /*
     * Short timeout here: just need wait long enougth that qemu makes
     * it through the poll loop once.  When reconnected we want a
     * short timeout so we notice it almost instantly.  Otherwise
     * read() gives us -EIO instantly, making pty_chr_state() reset the
     * timeout to the normal (much longer) poll interval before the
     * timer triggers.
     */
    qemu_mod_timer(s->timer, qemu_get_clock(rt_clock) + 10);
}

static void pty_chr_state(CharDriverState *chr, int connected)
{
    PtyCharDriver *s = chr->opaque;

    if (!connected) {
        ioh_set_read_handler2(s->fd, chr->iohq, NULL, NULL, NULL);
        s->connected = 0;
        s->polling = 0;
        /* (re-)connect poll interval for idle guests: once per second.
         * We check more frequently in case the guests sends data to
         * the virtual device linked to our pty. */
        qemu_mod_timer(s->timer, qemu_get_clock(rt_clock) + 1000);
    } else {
        if (!s->connected)
            qemu_chr_reset(chr);
        s->connected = 1;
    }
}

static void pty_chr_timer(void *opaque)
{
    struct CharDriverState *chr = opaque;
    PtyCharDriver *s = chr->opaque;

    if (s->connected)
        return;
    if (s->polling) {
        /* If we arrive here without polling being cleared due
         * read returning -EIO, then we are (re-)connected */
        pty_chr_state(chr, 1);
        return;
    }

    /* Next poll ... */
    pty_chr_update_read_handler(chr);
}

static int pty_chr_getname(struct CharDriverState *chr, char *buf, size_t len) {
    char *name;
    FDCharDriver *s = chr->opaque;

    name = ptsname(s->fd_in);
    if (!name) return -1;
    return snprintf(buf,len, "pty %s", name);
}

static void pty_chr_close(struct CharDriverState *chr)
{
    PtyCharDriver *s = chr->opaque;

    ioh_set_read_handler2(s->fd, chr->iohq, NULL, NULL, chr);

    close(s->fd);
    qemu_del_timer(s->timer);
    free_timer(s->timer);
    free(s);
}

static CharDriverState *qemu_chr_open_pty(struct io_handler_queue *iohq)
{
    CharDriverState *chr;
    PtyCharDriver *s;
    struct termios tty;
    int slave_fd, len;
#if defined(__OpenBSD__)
    char pty_name[PATH_MAX];
#define q_ptsname(x) pty_name
#else
    char *pty_name = NULL;
#define q_ptsname(x) ptsname(x)
#endif

    chr = calloc(1, sizeof(CharDriverState));
    if (!chr)
        return NULL;
    chr->refcnt = 1;
    chr->iohq = iohq;

    s = calloc(1, sizeof(PtyCharDriver));

    if (openpty(&s->fd, &slave_fd, pty_name, NULL, NULL) < 0) {
        return NULL;
    }

    /* Set raw attributes on the pty. */
    tcgetattr(slave_fd, &tty);
    cfmakeraw(&tty);
    tcsetattr(slave_fd, TCSAFLUSH, &tty);
    close(slave_fd);

    len = strlen(q_ptsname(s->fd)) + 5;
    chr->filename = malloc(len);
    snprintf(chr->filename, len, "pty:%s", q_ptsname(s->fd));
    debug_printf("char device redirected to %s\n", q_ptsname(s->fd));

    chr->opaque = s;
    chr->chr_write = pty_chr_write;
    chr->chr_update_read_handler = pty_chr_update_read_handler;
    chr->chr_close = pty_chr_close;
    chr->chr_getname = pty_chr_getname;

    s->timer = qemu_new_timer_ms(rt_clock, pty_chr_timer, chr);

    return chr;
}

static void tty_serial_init(int fd, int speed,
                            int parity, int data_bits, int stop_bits)
{
    struct termios tty;
    speed_t spd;

#if 0
    printf("tty_serial_init: speed=%d parity=%c data=%d stop=%d\n",
           speed, parity, data_bits, stop_bits);
#endif
    tcgetattr (fd, &tty);

#define MARGIN 1.1
    if (speed <= 50 * MARGIN)
        spd = B50;
    else if (speed <= 75 * MARGIN)
        spd = B75;
    else if (speed <= 300 * MARGIN)
        spd = B300;
    else if (speed <= 600 * MARGIN)
        spd = B600;
    else if (speed <= 1200 * MARGIN)
        spd = B1200;
    else if (speed <= 2400 * MARGIN)
        spd = B2400;
    else if (speed <= 4800 * MARGIN)
        spd = B4800;
    else if (speed <= 9600 * MARGIN)
        spd = B9600;
    else if (speed <= 19200 * MARGIN)
        spd = B19200;
    else if (speed <= 38400 * MARGIN)
        spd = B38400;
    else if (speed <= 57600 * MARGIN)
        spd = B57600;
    else if (speed <= 115200 * MARGIN)
        spd = B115200;
    else
        spd = B115200;

    cfsetispeed(&tty, spd);
    cfsetospeed(&tty, spd);

    tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP
                          |INLCR|IGNCR|ICRNL|IXON);
    tty.c_oflag |= OPOST;
    tty.c_lflag &= ~(ECHO|ECHONL|ICANON|IEXTEN|ISIG);
    tty.c_cflag &= ~(CSIZE|PARENB|PARODD|CRTSCTS|CSTOPB);
    switch(data_bits) {
    default:
    case 8:
        tty.c_cflag |= CS8;
        break;
    case 7:
        tty.c_cflag |= CS7;
        break;
    case 6:
        tty.c_cflag |= CS6;
        break;
    case 5:
        tty.c_cflag |= CS5;
        break;
    }
    switch(parity) {
    default:
    case 'N':
        break;
    case 'E':
        tty.c_cflag |= PARENB;
        break;
    case 'O':
        tty.c_cflag |= PARENB | PARODD;
        break;
    }
    if (stop_bits == 2)
        tty.c_cflag |= CSTOPB;

    tcsetattr (fd, TCSANOW, &tty);
}

static int tty_serial_ioctl(CharDriverState *chr, int cmd, void *arg)
{
    FDCharDriver *s = chr->opaque;

    switch(cmd) {
    case CHR_IOCTL_SERIAL_SET_PARAMS:
        {
            QEMUSerialSetParams *ssp = arg;
            tty_serial_init(s->fd_in, ssp->speed, ssp->parity,
                            ssp->data_bits, ssp->stop_bits);
        }
        break;
    case CHR_IOCTL_SERIAL_SET_BREAK:
        {
            int enable = *(int *)arg;
            if (enable)
                tcsendbreak(s->fd_in, 1);
        }
        break;
    case CHR_IOCTL_SERIAL_GET_TIOCM:
        {
            int sarg = 0;
            int *targ = (int *)arg;
            ioctl(s->fd_in, TIOCMGET, &sarg);
            *targ = 0;
            if (sarg & TIOCM_CTS)
                *targ |= CHR_TIOCM_CTS;
            if (sarg & TIOCM_CAR)
                *targ |= CHR_TIOCM_CAR;
            if (sarg & TIOCM_DSR)
                *targ |= CHR_TIOCM_DSR;
            if (sarg & TIOCM_RI)
                *targ |= CHR_TIOCM_RI;
            if (sarg & TIOCM_DTR)
                *targ |= CHR_TIOCM_DTR;
            if (sarg & TIOCM_RTS)
                *targ |= CHR_TIOCM_RTS;
        }
        break;
    case CHR_IOCTL_SERIAL_SET_TIOCM:
        {
            int sarg = *(int *)arg;
            int targ = 0;
            ioctl(s->fd_in, TIOCMGET, &targ);
            targ &= ~(CHR_TIOCM_CTS | CHR_TIOCM_CAR | CHR_TIOCM_DSR
                     | CHR_TIOCM_RI | CHR_TIOCM_DTR | CHR_TIOCM_RTS);
            if (sarg & CHR_TIOCM_CTS)
                targ |= TIOCM_CTS;
            if (sarg & CHR_TIOCM_CAR)
                targ |= TIOCM_CAR;
            if (sarg & CHR_TIOCM_DSR)
                targ |= TIOCM_DSR;
            if (sarg & CHR_TIOCM_RI)
                targ |= TIOCM_RI;
            if (sarg & CHR_TIOCM_DTR)
                targ |= TIOCM_DTR;
            if (sarg & CHR_TIOCM_RTS)
                targ |= TIOCM_RTS;
            ioctl(s->fd_in, TIOCMSET, &targ);
        }
        break;
    default:
        return -ENOTSUP;
    }
    return 0;
}

static CharDriverState *qemu_chr_open_tty(const char *filename, struct io_handler_queue *iohq)
{
    CharDriverState *chr;
    int fd;

    fd = open(filename, O_RDWR | O_NONBLOCK);
    tty_serial_init(fd, 115200, 'N', 8, 1);
    chr = qemu_chr_open_fd(fd, fd, iohq);
    if (!chr) {
        close(fd);
        return NULL;
    }
    chr->chr_ioctl = tty_serial_ioctl;
    qemu_chr_reset(chr);
    return chr;
}
#elif defined(CONFIG_STUBDOM)
#include <fcntl.h>
static CharDriverState *qemu_chr_open_pty(struct io_handler_queue *iohq)
{
    CharDriverState *chr;
    int fd;

    fd = posix_openpt(O_RDWR|O_NOCTTY);
    if (fd < 0)
        return NULL;

    chr = qemu_chr_open_fd(fd, fd, iohq);
    if (!chr) {
        close(fd);
        return NULL;
    }

    qemu_chr_reset(chr);
    return chr;
}
#else  /* ! __linux__ && ! __sun__ */
static CharDriverState *qemu_chr_open_pty(void)
{
    return NULL;
}
#endif /* __linux__ || __sun__ */
#endif

#else /* _WIN32 */

typedef struct WinCharState {
    int max_size;
    int is_overlapped;
    HANDLE hcom, hrecv;
    OVERLAPPED orecv;
    BOOL fpipe;
    DWORD len;
    uint8_t pipebuf[1];
    CharDriverState *chr;
    char *openname;
    int server_mode;
} WinCharState;

#define NPDEBUG() do { } while(0)
// #define NPDEBUG() asm("int $3\n")

static int win_chr_pipe_create(WinCharState *s);
static void win_chr_pipe_connect(void *opaque);
static void win_chr_pipe_read(void *opaque);

#define NSENDBUF 2048
#define NRECVBUF 2048
#define MAXCONNECT 1
#define NTIMEOUT 5000

static void win_chr_close(CharDriverState *chr)
{
    WinCharState *s = chr->opaque;
    DWORD size;

    if (s->fpipe) {
        NPDEBUG();
        if (s->hcom) {
            if (CancelIoEx(s->hcom, &s->orecv) ||
                (GetLastError() != ERROR_NOT_FOUND))
                    GetOverlappedResult(s->hcom, &s->orecv, &size, TRUE);
        }
        if (s->hrecv)
            ioh_set_np_handler2(s->hrecv, NULL, NULL, NULL, NULL, chr->iohq);
    }

    s->is_overlapped = 0;

    if (s->hrecv) {
        CloseHandle(s->hrecv);
        s->hrecv = NULL;
    }
    if (s->hcom) {
        CloseHandle(s->hcom);
        s->hcom = NULL;
    }
}

static int win_chr_write(CharDriverState *chr, const uint8_t *buf, int len1)
{
    WinCharState *s = chr->opaque;
    DWORD len, ret, size;
    OVERLAPPED o;
    HANDLE e = NULL;

    len = len1;

    if (s->is_overlapped) {
        e = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!e)
	    return 0;
    }


    while (len > 0) {
	
	if (e) {
           ZeroMemory(&o, sizeof(o));
           o.hEvent = e;
        }

	ret = WriteFile(s->hcom, buf, len, &size, e ? &o : NULL);
        if (!ret) {
            if (e && (GetLastError() == ERROR_IO_PENDING))
                ret = GetOverlappedResult(s->hcom, &o, &size, TRUE);
	    if (!ret)
                break;
        }
	buf += size;
	len -= size;
    }

    if (e)
	CloseHandle(e);

    return len1 - len;
}

static int win_chr_read_poll(CharDriverState *chr)
{
    WinCharState *s = chr->opaque;

    s->max_size = qemu_chr_can_read(chr);
    return s->max_size;
}

static void
win_chr_pipe_reopen(void *opaque)
{
    CharDriverState *chr = opaque;
    WinCharState *s = chr->opaque;
    DWORD size;
    int ret;

    if (CancelIoEx(s->hcom, &s->orecv) ||
        (GetLastError() != ERROR_NOT_FOUND))
            GetOverlappedResult(s->hcom, &s->orecv, &size, TRUE);
    CloseHandle(s->hcom);
    s->hcom = NULL;
    if (s->server_mode) {
	qemu_chr_event(chr, CHR_EVENT_RESET);
	ret = win_chr_pipe_create(s);
	ioh_set_np_handler2(s->hrecv, NULL,
			     ret ? NULL : win_chr_pipe_connect,
			     NULL, chr, chr->iohq);
    } else {
        Wwarn("pipe error, shutting down VM");
        vm_set_run_mode(DESTROY_VM);
        ioh_set_np_handler2(s->hrecv, NULL, NULL, NULL, chr, chr->iohq);
    }
}

static void win_chr_pipe_reconnect(void *opaque)
{
    CharDriverState *chr = opaque;
    WinCharState *s = chr->opaque;
    DWORD size;
    int ret;

    if (!s->server_mode)
        return; /* XXX not yet */

    if (CancelIoEx(s->hcom, &s->orecv) ||
        (GetLastError() != ERROR_NOT_FOUND))
            GetOverlappedResult(s->hcom, &s->orecv, &size, TRUE);
    CloseHandle(s->hcom);
    s->hcom = NULL;
    ret = win_chr_pipe_create(s);
    ioh_set_np_handler2(s->hrecv, NULL,
                         ret ? NULL : win_chr_pipe_connect,
                         NULL, chr, chr->iohq);
}

void
win_chr_pipe_disconnect(void *opaque)
{
    CharDriverState *chr = opaque;
    WinCharState *s = chr->opaque;
    DWORD size;

    if (CancelIoEx(s->hcom, &s->orecv) ||
        (GetLastError() != ERROR_NOT_FOUND))
            GetOverlappedResult(s->hcom, &s->orecv, &size, TRUE);
}

static int
win_chr_pipe_read_poll(void *opaque)
{
    CharDriverState *chr = opaque;
    WinCharState *s = chr->opaque;
    int ret;

    s->max_size = qemu_chr_can_read(chr);
    if (s->max_size) {
	ZeroMemory(&s->orecv, sizeof(s->orecv));
	s->orecv.hEvent = s->hrecv;
	ret = ReadFile(s->hcom, &s->pipebuf[0], 1, NULL, &s->orecv);
	if (!ret && GetLastError() != ERROR_IO_PENDING) {
            if (GetLastError() != ERROR_BROKEN_PIPE &&
                GetLastError() != ERROR_INVALID_HANDLE) {
                debug_printf("%s: readfile failed err %ld ?= %ld/%ld\n",
                             __FUNCTION__, GetLastError(), ERROR_BROKEN_PIPE,
                             ERROR_INVALID_HANDLE);
		NPDEBUG();
	    }
	    win_chr_pipe_reopen(opaque);
	    s->max_size = 0;
	}
    } else {
	DWORD size;
	ret = PeekNamedPipe(s->hcom, NULL, 0, NULL, &size, NULL);
	if (!ret) {
            if (GetLastError() != ERROR_BROKEN_PIPE &&
                GetLastError() != ERROR_INVALID_HANDLE) {
                debug_printf("%s: peeknamedpipe failed err %ld ?= %ld/%ld\n",
                             __FUNCTION__, GetLastError(), ERROR_BROKEN_PIPE,
                             ERROR_INVALID_HANDLE);
		NPDEBUG();
	    }
	    win_chr_pipe_reopen(opaque);
	    s->max_size = 0;
	}
    }
    return s->max_size;
}

static void
win_chr_pipe_read(void *opaque)
{
    CharDriverState *chr = opaque;
    WinCharState *s = chr->opaque;
    DWORD size;
    int ret;
    uint8_t buf[1024];

    ret = GetOverlappedResult(s->hcom, &s->orecv, &size, TRUE);
    if (!ret) {
	if (GetLastError() != ERROR_BROKEN_PIPE) {
	    debug_printf("%s:%d: GetOverlappedResult failed err %ld\n",
                         __FUNCTION__, __LINE__, GetLastError());
	    NPDEBUG();
	}
	win_chr_pipe_reopen(opaque);
	return;
    }

    if (size != 1) {
        debug_printf("%s:%d: size != 1\n", __FUNCTION__, __LINE__);
	NPDEBUG();
	return;
    }

    win_chr_read_poll(chr);
    if (s->max_size == 0) {
        debug_printf("%s:%d: max_size == 0\n", __FUNCTION__, __LINE__);
	NPDEBUG();
	return;
    }

    buf[0] = s->pipebuf[0];

    ret = PeekNamedPipe(s->hcom, NULL, 0, NULL, &size, NULL);
    if (!ret) {
        debug_printf("%s:%d: PeekNamedPipe failed err %ld\n",
                     __FUNCTION__, __LINE__, GetLastError());
        NPDEBUG();
    }
    s->len = size;
    if (s->len > s->max_size - 1)
	s->len = s->max_size - 1;
    if (s->len > 1024 - 1)
	s->len = 1024 - 1;
    if (s->len > 0) {
	ZeroMemory(&s->orecv, sizeof(s->orecv));
	s->orecv.hEvent = s->hrecv;
	ret = ReadFile(s->hcom, &buf[1], s->len, &size, &s->orecv);
        if (!ret && GetLastError() != ERROR_IO_PENDING) {
            debug_printf("%s:%d: ReadFile failed err %ld\n",
                         __FUNCTION__, __LINE__, GetLastError());
	    NPDEBUG();
        }
	ret = GetOverlappedResult(s->hcom, &s->orecv, &size, TRUE);
        if (!ret) {
            debug_printf("%s:%d: GetOverlappedResult failed err %ld\n",
                         __FUNCTION__, __LINE__, GetLastError());
	    NPDEBUG();
        }
	size++;
    } else
	size = 1;

    qemu_chr_read(chr, buf, size);
}

static void
win_chr_pipe_connect(void *opaque)
{
    CharDriverState *chr = opaque;
    WinCharState *s = chr->opaque;
    DWORD size;
    int ret;

    ret = GetOverlappedResult(s->hcom, &s->orecv, &size, TRUE);
    if (!ret) {
        debug_printf("%s:%d: GetOverlappedResult failed err %ld\n",
                     __FUNCTION__, __LINE__, GetLastError());
	NPDEBUG();
        return;
    }

    ioh_set_np_handler2(s->hrecv, win_chr_pipe_read_poll, win_chr_pipe_read,
			 NULL, chr, chr->iohq);
    qemu_chr_reset(chr);
}

static int win_chr_pipe_create(WinCharState *s)
{
    int ret;

    if (s->server_mode) {
	s->hcom = CreateNamedPipe(s->openname,
				  PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
				  PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
				  PIPE_WAIT,
				  MAXCONNECT, NSENDBUF, NRECVBUF, NTIMEOUT,
				  NULL);
	if (s->hcom == INVALID_HANDLE_VALUE) {
	    Wwarn("CreateNamedPipe failed");
	    s->hcom = NULL;
	    ret = -1;
	    goto fail;
	}

	ZeroMemory(&s->orecv, sizeof(s->orecv));
	s->orecv.hEvent = s->hrecv;
	ret = ConnectNamedPipe(s->hcom, &s->orecv);
	if (!ret && GetLastError() != ERROR_IO_PENDING) {
	    Wwarn("ConnectNamedPipe failed");
	    ret = -1;
	    goto fail;
	}

	ioh_set_np_handler2(s->hrecv, NULL, win_chr_pipe_connect,
                            NULL, s->chr, s->chr ? s->chr->iohq : NULL);
    } else {
	while (1) {
	    s->hcom = CreateFile(s->openname, GENERIC_READ | GENERIC_WRITE,
				 0, NULL, OPEN_EXISTING,
				 FILE_FLAG_OVERLAPPED, NULL);
	    if (s->hcom != INVALID_HANDLE_VALUE)
		break;
	    if (GetLastError() == ERROR_PIPE_BUSY)
		WaitNamedPipe(s->openname, 1000); /* wait for 1s */
	    else if (GetLastError() == ERROR_FILE_NOT_FOUND)
		Sleep(1000);	/* wait for 1s */
	    else {
		Wwarn("CreateFile(%s) failed", s->openname);
		s->hcom = NULL;
		ret = -1;
		goto fail;
	    }
	}

	ioh_set_np_handler2(s->hrecv, win_chr_pipe_read_poll,
                            win_chr_pipe_read, NULL, s->chr,
                            s->chr ? s->chr->iohq : NULL);
    }

    ret = 0;
  fail:
    return ret;
}

static int win_chr_pipe_init(CharDriverState *chr, const char *filename,
			     int server_mode)
{
    WinCharState *s = chr->opaque;
    int ret;

    s->fpipe = TRUE;
    s->chr = chr;
    asprintf(&s->openname, "\\\\.\\pipe\\%s", filename);
    s->server_mode = server_mode;

    ret = -1;

    s->is_overlapped = 1;

    s->hrecv = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!s->hrecv) {
        Wwarn("CreateEvent failed");
        goto fail;
    }

    ret = win_chr_pipe_create(s);

 fail:
    if (ret)
	win_chr_close(chr);
    return ret;
}


static CharDriverState *qemu_chr_open_win_pipe(const char *_filename,
                                               struct io_handler_queue *iohq)
{
    CharDriverState *chr = NULL;
    WinCharState *s;
    char *ptr;
    char *filename;
    int server_mode = 0;

    filename = strdup(_filename);
    ptr = filename;
    while ((ptr = strchr(ptr, ','))) {
	*ptr = 0;
	ptr++;
	if (!strncmp(ptr, "server", 6))
	    server_mode = 1;
	else {
	    printf("Unknown option: %s\n", ptr);
	    goto out;
	}
    }

    chr = calloc(1, sizeof(CharDriverState));
    if (!chr)
        return NULL;
    chr->refcnt = 1;

    s = calloc(1, sizeof(WinCharState));
    chr->opaque = s;
    chr->chr_write = win_chr_write;
    chr->chr_close = win_chr_close;
    chr->chr_disconnect = win_chr_pipe_disconnect;
    chr->chr_reconnect = win_chr_pipe_reconnect;
    chr->iohq = iohq;

    if (win_chr_pipe_init(chr, filename, server_mode) < 0) {
        free(s);
        free(chr);
	chr = NULL;
	goto out;
    }
    if (!server_mode)
        qemu_chr_reset(chr);

  out:
    free(filename);
    return chr;
}

static CharDriverState *
qemu_chr_open_win_file(HANDLE fd_out, struct io_handler_queue *iohq)
{
    CharDriverState *chr;
    WinCharState *s;

    chr = calloc(1, sizeof(CharDriverState));
    if (!chr)
        return NULL;
    chr->refcnt = 1;

    s = calloc(1, sizeof(WinCharState));
    s->hcom = fd_out;
    chr->opaque = s;
    chr->chr_write = win_chr_write;
    chr->chr_close = win_chr_close;
    chr->iohq = iohq;
    qemu_chr_reset(chr);
    return chr;
}

static CharDriverState *
qemu_chr_open_win_con(const char *filename, struct io_handler_queue *iohq)
{
    return qemu_chr_open_win_file(GetStdHandle(STD_OUTPUT_HANDLE), iohq);
}

static CharDriverState *
qemu_chr_open_win_file_out(const char *file_out, struct io_handler_queue *iohq)
{
    HANDLE fd_out;

    fd_out = CreateFile(file_out, GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fd_out == INVALID_HANDLE_VALUE)
        return NULL;

    /* Move file pointer to end of file, to append if file existed already. */
    SetFilePointer(fd_out, 0, NULL, FILE_END);

    return qemu_chr_open_win_file(fd_out, iohq);
}

static int
qemu_chr_reopen_win_file(WinCharState *s, const char *filename)
{
    HANDLE new_h, old_h;
    new_h = CreateFile(filename, FILE_APPEND_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (new_h == INVALID_HANDLE_VALUE) {
        Wwarn("failed to reopen %s", filename);
        return -1;
    }
    old_h = s->hcom;
    s->hcom = new_h;
    if (old_h != NULL)
        CloseHandle(old_h);
    return 0;
}

HANDLE qemu_chr_dup_win_handle(WinCharState *s, HANDLE handle)
{
    ULONG pid;
    HANDLE proc;
    HANDLE dup;
    if (!GetNamedPipeServerProcessId(s->hcom, &pid)) {
        Wwarn("GetNamedPipeClientProcessId fails");
        return NULL;
    }
    proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!proc) {
        Wwarn("OpenProcess fails");
        return NULL;
    }
    if (!DuplicateHandle(GetCurrentProcess(), handle, proc,
                         &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
        Wwarn("DuplicateHandle fails");
        dup = NULL;
    }
    CloseHandle(proc);
    return dup;
}

#endif /* !_WIN32 */

#if 0
/***********************************************************/
/* UDP Net console */

typedef struct {
    int fd;
    struct sockaddr_in daddr;
    uint8_t buf[1024];
    int bufcnt;
    int bufptr;
    int max_size;
} NetCharDriver;

static int udp_chr_write(CharDriverState *chr, const uint8_t *buf, int len)
{
    NetCharDriver *s = chr->opaque;

    return sendto(s->fd, (char *)buf, len, 0,
                  (struct sockaddr *)&s->daddr, sizeof(struct sockaddr_in));
}

static int udp_chr_read_poll(void *opaque)
{
    CharDriverState *chr = opaque;
    NetCharDriver *s = chr->opaque;

    s->max_size = qemu_chr_can_read(chr);

    /* If there were any stray characters in the queue process them
     * first
     */
    while (s->max_size > 0 && s->bufptr < s->bufcnt) {
        qemu_chr_read(chr, &s->buf[s->bufptr], 1);
        s->bufptr++;
        s->max_size = qemu_chr_can_read(chr);
    }
    return s->max_size;
}

static void udp_chr_read(void *opaque)
{
    CharDriverState *chr = opaque;
    NetCharDriver *s = chr->opaque;

    if (s->max_size == 0)
        return;
    s->bufcnt = recv(s->fd, (char *)s->buf, sizeof(s->buf), 0);
    s->bufptr = s->bufcnt;
    if (s->bufcnt <= 0)
        return;

    s->bufptr = 0;
    while (s->max_size > 0 && s->bufptr < s->bufcnt) {
        qemu_chr_read(chr, &s->buf[s->bufptr], 1);
        s->bufptr++;
        s->max_size = qemu_chr_can_read(chr);
    }
}

static void udp_chr_update_read_handler(CharDriverState *chr)
{
    NetCharDriver *s = chr->opaque;

    if (s->fd >= 0) {
        ioh_set_fd_handler2(s->fd, udp_chr_read_poll,
                             udp_chr_read, NULL, NULL, chr);
    }
}

static void udp_chr_close(CharDriverState *chr)
{
    NetCharDriver *s = chr->opaque;
    if (s->fd >= 0) {
        ioh_set_fd_handler(s->fd, NULL, NULL, NULL);
        closesocket(s->fd);
    }
    free(s);
}

static CharDriverState *qemu_chr_open_udp(const char *def)
{
    CharDriverState *chr = NULL;
    NetCharDriver *s = NULL;
    int fd = -1;
    struct sockaddr_in saddr;

    chr = calloc(1, sizeof(CharDriverState));
    if (!chr)
        return NULL;
    chr->refcnt = 1;
    s = calloc(1, sizeof(NetCharDriver));

    fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket(PF_INET, SOCK_DGRAM)");
        goto return_err;
    }

    if (parse_host_src_port(&s->daddr, &saddr, def) < 0) {
        printf("Could not parse: %s\n", def);
        goto return_err;
    }

    if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
    {
        perror("bind");
        goto return_err;
    }

    s->fd = fd;
    s->bufcnt = 0;
    s->bufptr = 0;
    chr->opaque = s;
    chr->chr_write = udp_chr_write;
    chr->chr_update_read_handler = udp_chr_update_read_handler;
    chr->chr_close = udp_chr_close;
    return chr;

return_err:
    if (chr)
        free(chr);
    if (s)
        free(s);
    if (fd >= 0)
        closesocket(fd);
    return NULL;
}
#endif

/***********************************************************/
/* TCP Net console */

typedef struct {
    int fd, listen_fd;
    int connected;
    int max_size;
    int do_telnetopt;
    int do_nodelay;
    int is_unix;
} TCPCharDriver;

static void tcp_chr_accept(void *opaque);

static int tcp_chr_eof(CharDriverState *chr)
{
    TCPCharDriver *s = chr->opaque;
    struct pollfd pfd = { 0 };

    if (s->fd < 0)
        return 0;

    pfd.events |= POLLRDNORM | POLLRDBAND;
    pfd.fd = s->fd;

    return (1 == poll(&pfd, 1, 0)) && (pfd.revents & POLLHUP);
}

static int tcp_chr_write(CharDriverState *chr, const uint8_t *buf, int len)
{
    TCPCharDriver *s = chr->opaque;
    if (s->connected) {
        return send_all(s->fd, buf, len);
    } else {
        /* XXX: indicate an error ? */
        return len;
    }
}

static int tcp_chr_read_poll(void *opaque)
{
    CharDriverState *chr = opaque;
    TCPCharDriver *s = chr->opaque;
    if (!s->connected)
        return 0;
    s->max_size = qemu_chr_can_read(chr);
    return s->max_size;
}

#define IAC 255
#define IAC_BREAK 243
static void tcp_chr_process_IAC_bytes(CharDriverState *chr,
                                      TCPCharDriver *s,
                                      uint8_t *buf, int *size)
{
    /* Handle any telnet client's basic IAC options to satisfy char by
     * char mode with no echo.  All IAC options will be removed from
     * the buf and the do_telnetopt variable will be used to track the
     * state of the width of the IAC information.
     *
     * IAC commands come in sets of 3 bytes with the exception of the
     * "IAC BREAK" command and the double IAC.
     */

    int i;
    int j = 0;

    for (i = 0; i < *size; i++) {
        if (s->do_telnetopt > 1) {
            if ((unsigned char)buf[i] == IAC && s->do_telnetopt == 2) {
                /* Double IAC means send an IAC */
                if (j != i)
                    buf[j] = buf[i];
                j++;
                s->do_telnetopt = 1;
            } else {
                if ((unsigned char)buf[i] == IAC_BREAK && s->do_telnetopt == 2) {
                    /* Handle IAC break commands by sending a serial break */
                    qemu_chr_event(chr, CHR_EVENT_BREAK);
                    s->do_telnetopt++;
                }
                s->do_telnetopt++;
            }
            if (s->do_telnetopt >= 4) {
                s->do_telnetopt = 1;
            }
        } else {
            if ((unsigned char)buf[i] == IAC) {
                s->do_telnetopt = 2;
            } else {
                if (j != i)
                    buf[j] = buf[i];
                j++;
            }
        }
    }
    *size = j;
}

static void tcp_chr_read(void *opaque)
{
    CharDriverState *chr = opaque;
    TCPCharDriver *s = chr->opaque;
    uint8_t buf[1024];
    int len, size;

    if (!s->connected || s->max_size <= 0)
        return;
    len = sizeof(buf);
    if (len > s->max_size)
        len = s->max_size;
    size = recv(s->fd, (char *)buf, len, 0);
    if (size == 0) {
        /* connection closed */
        s->connected = 0;
        qemu_chr_event(chr, CHR_EVENT_EOF);
        if (s->listen_fd >= 0) {
            ioh_set_read_handler(s->listen_fd, chr->iohq, tcp_chr_accept, chr);
        }
        ioh_set_read_handler(s->fd, chr->iohq, NULL, chr);
        closesocket(s->fd);
        s->fd = -1;
    } else if (size > 0) {
        if (s->do_telnetopt)
            tcp_chr_process_IAC_bytes(chr, s, buf, &size);
        if (size > 0)
            qemu_chr_read(chr, buf, size);
    }
}

static void tcp_chr_connect(void *opaque)
{
    CharDriverState *chr = opaque;
    TCPCharDriver *s = chr->opaque;

    s->connected = 1;
    ioh_set_read_handler2(s->fd, chr->iohq, tcp_chr_read_poll,
                          tcp_chr_read, chr);
    qemu_chr_reset(chr);
}

#define IACSET(x,a,b,c) x[0] = a; x[1] = b; x[2] = c;
static void tcp_chr_telnet_init(int fd)
{
    char buf[3];
    /* Send the telnet negotion to put telnet in binary, no echo, single char mode */
    IACSET(buf, 0xff, 0xfb, 0x01);  /* IAC WILL ECHO */
    send(fd, (char *)buf, 3, 0);
    IACSET(buf, 0xff, 0xfb, 0x03);  /* IAC WILL Suppress go ahead */
    send(fd, (char *)buf, 3, 0);
    IACSET(buf, 0xff, 0xfb, 0x00);  /* IAC WILL Binary */
    send(fd, (char *)buf, 3, 0);
    IACSET(buf, 0xff, 0xfd, 0x00);  /* IAC DO Binary */
    send(fd, (char *)buf, 3, 0);
}

static void socket_set_nodelay(int fd)
{
    int val = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
}

static void tcp_chr_accept(void *opaque)
{
    CharDriverState *chr = opaque;
    TCPCharDriver *s = chr->opaque;
    struct sockaddr_in saddr;
#ifndef NO_UNIX_SOCKETS
    struct sockaddr_un uaddr;
#endif
    struct sockaddr *addr;
    socklen_t len;
    int fd;

    for(;;) {
#ifndef NO_UNIX_SOCKETS
	if (s->is_unix) {
	    len = sizeof(uaddr);
	    addr = (struct sockaddr *)&uaddr;
	} else
#endif
	{
	    len = sizeof(saddr);
	    addr = (struct sockaddr *)&saddr;
	}
        fd = accept(s->listen_fd, addr, &len);
        if (fd < 0 && errno != EINTR) {
            return;
        } else if (fd >= 0) {
            if (s->do_telnetopt)
                tcp_chr_telnet_init(fd);
            break;
        }
    }
    socket_set_nonblock(fd);
    if (s->do_nodelay)
        socket_set_nodelay(fd);
    s->fd = fd;
    ioh_set_read_handler(s->listen_fd, chr->iohq, NULL, chr);
    tcp_chr_connect(chr);
}

static void tcp_chr_close(CharDriverState *chr)
{
    TCPCharDriver *s = chr->opaque;
    if (s->fd >= 0) {
        ioh_set_read_handler(s->fd, chr->iohq, NULL, chr);
        closesocket(s->fd);
    }
    if (s->listen_fd >= 0) {
        ioh_set_read_handler(s->listen_fd, chr->iohq, NULL, chr);
        closesocket(s->listen_fd);
    }
    free(s);
}

static void tcp_chr_reconnect(void *opaque)
{
    CharDriverState *chr = opaque;
    TCPCharDriver *s = chr->opaque;

    s->connected = 0;
    if (s->listen_fd >= 0) {
        ioh_set_read_handler(s->listen_fd, chr->iohq, tcp_chr_accept, chr);
    }
    if (s->fd < 0)
        return;
    qemu_chr_event(chr, CHR_EVENT_EOF);
    ioh_set_read_handler(s->fd, chr->iohq, NULL, chr);
    closesocket(s->fd);
    s->fd = -1;
}

static CharDriverState *qemu_chr_open_tcp(const char *host_str,
                                          int is_telnet,
					  int is_unix,
                                          struct io_handler_queue *iohq)
{
    CharDriverState *chr = NULL;
    TCPCharDriver *s = NULL;
    int fd = -1, offset = 0;
    int is_listen = 0;
    int is_waitconnect = 1;
    int do_nodelay = 0;
    const char *ptr;

    ptr = host_str;
    while((ptr = strchr(ptr,','))) {
        ptr++;
        if (!strncmp(ptr,"server",6)) {
            is_listen = 1;
        } else if (!strncmp(ptr,"nowait",6)) {
            is_waitconnect = 0;
        } else if (!strncmp(ptr,"nodelay",6)) {
            do_nodelay = 1;
        } else if (!strncmp(ptr,"to=",3)) {
            /* nothing, inet_listen() parses this one */;
        } else if (!strncmp(ptr,"ipv4",4)) {
            /* nothing, inet_connect() and inet_listen() parse this one */;
        } else if (!strncmp(ptr,"ipv6",4)) {
            /* nothing, inet_connect() and inet_listen() parse this one */;
        } else {
            printf("Unknown option: %s\n", ptr);
            goto fail;
        }
    }
    if (!is_listen)
        is_waitconnect = 0;

    chr = calloc(1, sizeof(CharDriverState));
    if (!chr)
        return NULL;
    chr->refcnt = 1;
    chr->iohq = iohq;
    s = calloc(1, sizeof(TCPCharDriver));

    if (is_listen) {
        chr->filename = malloc(256);
        if (is_unix) {
            pstrcpy(chr->filename, 256, "unix:");
        } else if (is_telnet) {
            pstrcpy(chr->filename, 256, "telnet:");
        } else {
            pstrcpy(chr->filename, 256, "tcp:");
        }
        offset = strlen(chr->filename);
    }
    if (is_unix) {
        if (is_listen) {
            fd = unix_listen(host_str, chr->filename + offset, 256 - offset);
        } else {
            fd = unix_connect(host_str);
        }
    } else {
        if (is_listen) {
            fd = inet_listen(host_str, chr->filename + offset, 256 - offset,
                             SOCK_STREAM, 0);
        } else {
            fd = inet_connect(host_str, SOCK_STREAM);
        }
    }
    if (fd < 0)
        goto fail;

    if (!is_waitconnect)
        socket_set_nonblock(fd);

    s->connected = 0;
    s->fd = -1;
    s->listen_fd = -1;
    s->is_unix = is_unix;
    s->do_nodelay = do_nodelay && !is_unix;

    chr->opaque = s;
    chr->chr_write = tcp_chr_write;
    chr->chr_close = tcp_chr_close;
    chr->chr_reconnect = tcp_chr_reconnect;
    chr->chr_eof = tcp_chr_eof;

    if (is_listen) {
        s->listen_fd = fd;
        ioh_set_read_handler(s->listen_fd, chr->iohq, tcp_chr_accept, chr);
        if (is_telnet)
            s->do_telnetopt = 1;
    } else {
        s->connected = 1;
        s->fd = fd;
        socket_set_nodelay(fd);
        tcp_chr_connect(chr);
    }

    if (is_listen && is_waitconnect) {
        printf("QEMU waiting for connection on: %s\n",
               chr->filename ? chr->filename : host_str);
        tcp_chr_accept(chr);
        socket_set_nonblock(s->listen_fd);
    }

    return chr;
 fail:
    if (fd >= 0)
        closesocket(fd);
    free(s);
    free(chr);
    return NULL;
}

CharDriverState *qemu_chr_open(const char *label, const char *filename,
                               void (*init)(struct CharDriverState *s),
                               struct io_handler_queue *io_handlers)
{
    const char *p;
    CharDriverState *chr;

#if 0
    if (!strcmp(filename, "vc")) {
        chr = text_console_init(0);
    } else
    if (strstart(filename, "vc:", &p)) {
        chr = text_console_init(p);
    } else
#endif
    if (!strcmp(filename, "null")) {
        chr = qemu_chr_open_null(io_handlers);
    } else
    if (strstart(filename, "tcp:", &p)) {
        chr = qemu_chr_open_tcp(p, 0, 0, io_handlers);
    } else
    if (strstart(filename, "telnet:", &p)) {
        chr = qemu_chr_open_tcp(p, 1, 0, io_handlers);
    } else
#if 0
    if (strstart(filename, "udp:", &p)) {
        chr = qemu_chr_open_udp(p);
    } else
#endif
#ifndef _WIN32
    if (strstart(filename, "unix:", &p)) {
	chr = qemu_chr_open_tcp(p, 0, 1, io_handlers);
    } else if (strstart(filename, "file:", &p)) {
        chr = qemu_chr_open_file_out(p, io_handlers);
    } else if (strstart(filename, "pipe:", &p)) {
        chr = qemu_chr_open_pipe(p, io_handlers);
    } else if (!strcmp(filename, "pty")) {
        chr = qemu_chr_open_pty(io_handlers);
    } else if (strstart(filename, "tty:", &p)) {
        chr = qemu_chr_open_tty(p, io_handlers);
    } else if (!strcmp(filename, "stdio")) {
        chr = qemu_chr_open_stdio(io_handlers);
    } else
#else /* !_WIN32 */
    if (strstart(filename, "pipe:", &p)) {
        chr = qemu_chr_open_win_pipe(p, io_handlers);
    } else
    if (strstart(filename, "con:", NULL)) {
        chr = qemu_chr_open_win_con(filename, io_handlers);
    } else
    if (strstart(filename, "file:", &p)) {
        chr = qemu_chr_open_win_file_out(p, io_handlers);
    } else
#endif
    {
        chr = NULL;
    }

    if (chr) {
        if (!chr->filename)
            chr->filename = strdup(filename);
        chr->init = init;
        chr->label = strdup(label);
        critical_section_enter(&chardevs_lock);
        TAILQ_INSERT_TAIL(&chardevs, chr, next);
        critical_section_leave(&chardevs_lock);
    }
    return chr;
}

void qemu_chr_get(CharDriverState *chr)
{
    atomic_inc(&chr->refcnt);
}

int qemu_chr_put(CharDriverState *chr)
{
    if (!atomic_dec_and_test(&chr->refcnt))
        return -1;

    free(chr->filename);
    free(chr->label);
    free(chr);

    return 0;
}

void qemu_chr_close(CharDriverState *chr)
{
    critical_section_enter(&chardevs_lock);
    if (TAILQ_ACTIVE(chr, next))
        TAILQ_REMOVE(&chardevs, chr, next);
    critical_section_leave(&chardevs_lock);
    if (chr->chr_close)
        chr->chr_close(chr);
    chr->closing = 1;
    qemu_chr_put(chr);
}

void qemu_chr_disconnect(CharDriverState *chr)
{
    if (chr->chr_disconnect)
	chr->chr_disconnect(chr);
}

int qemu_chr_eof(CharDriverState *chr)
{
    if (chr->chr_eof)
        return chr->chr_eof(chr);

    return 0;
}

int qemu_chr_reopen_all(void)
{
    int r = 0;
    CharDriverState *chr;

    critical_section_enter(&chardevs_lock);
    TAILQ_FOREACH(chr, &chardevs, next) {
        const char *p;
        if (strstart(chr->filename, "file:", &p)) {
#ifdef _WIN32
            WinCharState *s = chr->opaque;
            r = qemu_chr_reopen_win_file(s, p);
            if (r)
                break;
#else /* XXX implement reopening for POSIX */
#endif
        }
    }
    critical_section_leave(&chardevs_lock);
    return r;
}

#ifdef _WIN32
HANDLE qemu_chr_dup_handle(CharDriverState *s, HANDLE handle)
{
    return qemu_chr_dup_win_handle(s->opaque, handle);
}
#endif

#ifdef MONITOR
void
ic_chr(Monitor *mon)
{
    CharDriverState *chr;

    critical_section_enter(&chardevs_lock);
    TAILQ_FOREACH(chr, &chardevs, next) {
        monitor_printf(mon, "%s: filename=%s\n", chr->label, chr->filename);
    }
    critical_section_leave(&chardevs_lock);
}
#endif  /* MONITOR */

/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _CHAR_H_
#define _CHAR_H_

#include "bh.h"
#include "file.h"
#include "ioh.h"
#include "queue.h"

struct CharDriverState {
    void (*init)(struct CharDriverState *s);
    int (*chr_write)(struct CharDriverState *s, const uint8_t *buf, int len);
    int (*chr_write_flush)(struct CharDriverState *s);
    void (*chr_update_read_handler)(struct CharDriverState *s);
    int (*chr_ioctl)(struct CharDriverState *s, int cmd, void *arg);
    void (*chr_restore)(struct CharDriverState *s, QEMUFile *f);
    void (*chr_save)(struct CharDriverState *s, QEMUFile *f);
    int  (*chr_save_check)(struct CharDriverState *s);
    IOEventHandler *chr_event;
    IOCanRWHandler *chr_can_read;
    IOCanRWHandler *chr_can_write;
    IOReadHandler *chr_read;
    void *handler_opaque;
    void (*chr_send_event)(struct CharDriverState *chr, int event);
    void (*chr_close)(struct CharDriverState *chr);
    void (*chr_disconnect)(void *);
    void (*chr_reconnect)(void *);
    void (*chr_accept_input)(struct CharDriverState *chr);
    int (*chr_getname)(struct CharDriverState *s, char *buf, size_t buflen);
    int  (*chr_eof)(struct CharDriverState *s);
#ifdef _WIN32
    int (*chr_dup_handle)(struct CharDriverState *s, HANDLE in, HANDLE *out);
#endif
    void *opaque;
    uint32_t events;
    int focus;
    BH *bh;
    char *label;
    char *filename;
    struct io_handler_queue *iohq;
    uint32_t refcnt;
    int reconnect_on_close;
    int closing;
    TAILQ_ENTRY(CharDriverState) next;
};

void chardev_init(void);

CharDriverState *qemu_chr_open(const char *label, const char *filename,
			       void (*init)(struct CharDriverState *s),
                               struct io_handler_queue *io_handlers);
void qemu_chr_close(CharDriverState *s);
void qemu_chr_get(CharDriverState *s);
int qemu_chr_put(CharDriverState *s);
int qemu_chr_can_read(CharDriverState *s);
int qemu_chr_can_write(CharDriverState *s);
void qemu_chr_read(CharDriverState *s, uint8_t *buf, int len);
int qemu_chr_write(CharDriverState *s, const uint8_t *buf, int len);
int qemu_chr_write_flush(CharDriverState *s);
void qemu_chr_send_event(CharDriverState *s, int event);
void qemu_chr_send_event_async(CharDriverState *s, int event);
void qemu_chr_disconnect(CharDriverState *s);
void qemu_chr_add_handlers(CharDriverState *s,
                           IOCanRWHandler *fd_can_read,
                           IOReadHandler *fd_read,
                           IOEventHandler *fd_event,
                           void *opaque);
void qemu_chr_accept_input(CharDriverState *s);
int qemu_chr_reopen_all(void);
int qemu_chr_eof(CharDriverState *chr);
#ifdef _WIN32
HANDLE qemu_chr_dup_handle(CharDriverState *s, HANDLE handle);
#endif

#define qemu_chr_fe_ioctl(s, c, a) qemu_chr_ioctl(s, c, a)
int qemu_chr_ioctl(CharDriverState *s, int cmd, void *arg);

void qemu_chr_initial_reset(void);

/* character device */

#define CHR_EVENT_BREAK   0 /* serial break char */
#define CHR_EVENT_OPENED  2 /* new connection established */
#define CHR_EVENT_CLOSED  5 /* connection closed */
#define CHR_EVENT_RESET   7 /* connection reset */
#define CHR_EVENT_OPENING   8
#define CHR_EVENT_EOF   9

#define CHR_EVENT_BUFFER_CHANGE 0x101 /* possible change of buffer state */
#define CHR_EVENT_UPDATE        0x102

#define CHR_EVENT_NI_CLOSE      0x200
#define CHR_EVENT_NI_RST        0x201
#define CHR_EVENT_NI_REFUSED    0x202

#define CHR_EVT_BIT_READ    0x1
#define CHR_EVT_BIT_WRITE   0x2

#define CHR_IOCTL_SERIAL_SET_PARAMS   1
struct SerialSetParams {
    int speed;
    int parity;
    int data_bits;
    int stop_bits;
};

#define CHR_IOCTL_SERIAL_SET_BREAK    2

#define CHR_IOCTL_SERIAL_SET_TIOCM   13
#define CHR_IOCTL_SERIAL_GET_TIOCM   14

#define CHR_TIOCM_CTS	0x020
#define CHR_TIOCM_CAR	0x040
#define CHR_TIOCM_DSR	0x100
#define CHR_TIOCM_RI	0x080
#define CHR_TIOCM_DTR	0x002
#define CHR_TIOCM_RTS	0x004

#endif	/* _CHAR_H_ */

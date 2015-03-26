/*
 * uXen changes:
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
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

#ifndef _BLOCK_H_
#define _BLOCK_H_

#include <stdbool.h>

#include "iovec.h"
#include "yajl.h"

extern BlockDriver bdrv_raw;
extern BlockDriver bdrv_vhd;
extern BlockDriver bdrv_swap;

struct DriveInfo {
    BlockDriverState *bdrv;
    int media_cd;

    char *serial;
    char *version;
    char *model;

    char *file;
};

typedef struct BlockDriverInfo {
    /* in bytes, 0 if irrelevant */
    int cluster_size;
    /* offset at which the VM state can be saved (0 if not possible) */
    int64_t vm_state_offset;
} BlockDriverInfo;

typedef struct SnapshotInfo {
    char id_str[128]; /* unique snapshot id */
    /* the following fields are informative. They are not needed for
       the consistency of the snapshot */
    char name[256]; /* user choosen name */
    uint32_t vm_state_size; /* VM state info size */
    uint32_t date_sec; /* UTC date of the snapshot */
    uint32_t date_nsec;
    uint64_t vm_clock_nsec; /* VM clock relative to boot */
} SnapshotInfo;

/* Callbacks for block device models */
typedef struct BlockDevOps {
    /*
     * Runs when virtual media changed (monitor commands eject, change)
     * Argument load is true on load and false on eject.
     * Beware: doesn't run when a host device's physical media
     * changes.  Sure would be useful if it did.
     * Device models with removable media must implement this callback.
     */
    void (*change_media_cb)(void *opaque, bool load);
    /*
     * Runs when an eject request is issued from the monitor, the tray
     * is closed, and the medium is locked.
     * Device models that do not implement is_medium_locked will not need
     * this callback.  Device models that can lock the medium or tray might
     * want to implement the callback and unlock the tray when "force" is
     * true, even if they do not support eject requests.
     */
    void (*eject_request_cb)(void *opaque, bool force);
    /*
     * Is the virtual tray open?
     * Device models implement this only when the device has a tray.
     */
    bool (*is_tray_open)(void *opaque);
    /*
     * Is the virtual medium locked into the device?
     * Device models implement this only when device has such a lock.
     */
    bool (*is_medium_locked)(void *opaque);
    /*
     * Runs when the size changed (e.g. monitor command block_resize)
     */
    void (*resize_cb)(void *opaque);
} BlockDevOps;

#define BDRV_O_RDWR        0x0002
#define BDRV_O_NOCACHE     0x0020 /* do not use the host page cache */
#define BDRV_O_CACHE_WB    0x0040 /* use write-back caching */
#define BDRV_O_CACHE_DEF   0x0080 /* use default caching */
#define BDRV_O_CACHE_MASK  (BDRV_O_NOCACHE | BDRV_O_CACHE_WB | BDRV_O_CACHE_DEF)
#define BDRV_O_SPARSE      0x0100 /* open file sparse */

#define BDRV_SECTOR_BITS   9
#define BDRV_SECTOR_SIZE   (1ULL << BDRV_SECTOR_BITS)
#define BDRV_SECTOR_MASK   ~(BDRV_SECTOR_SIZE - 1)

typedef enum {
    BLOCK_ERR_REPORT, BLOCK_ERR_IGNORE, BLOCK_ERR_STOP_ENOSPC,
    BLOCK_ERR_STOP_ANY
} BlockErrorAction;

typedef enum {
    BDRV_ACTION_REPORT, BDRV_ACTION_IGNORE, BDRV_ACTION_STOP
} BlockMonEventAction;

void bdrv_iostatus_enable(BlockDriverState *bs);
void bdrv_iostatus_reset(BlockDriverState *bs);
void bdrv_iostatus_disable(BlockDriverState *bs);
bool bdrv_iostatus_is_enabled(const BlockDriverState *bs);
void bdrv_iostatus_set_err(BlockDriverState *bs, int error);
void bdrv_mon_event(const BlockDriverState *bdrv,
                    BlockMonEventAction action, int is_read);

void bdrv_init(void);
int bdrv_snapshot(BlockDriverState *bs);
int bdrv_prepare(DriveInfo *di);
int bdrv_add(yajl_val arg);
int bdrv_flush(BlockDriverState *bs);
int bdrv_flush_all(int do_close);
BlockDriverState *bdrv_new(const char *device_name);
void bdrv_delete(BlockDriverState *bs);
int bdrv_create(const char* filename, int64_t total_size, int flags);
int bdrv_file_open(BlockDriverState **pbs, const char *filename, int flags);
int bdrv_open(BlockDriverState *bs, const char *filename, int flags);
int bdrv_open2(BlockDriverState *bs, const char *filename, int flags,
               BlockDriver *drv);
int bdrv_attach_dev(BlockDriverState *bs, void *dev);
void bdrv_attach_dev_nofail(BlockDriverState *bs, void *dev);
void bdrv_detach_dev(BlockDriverState *bs, void *dev);
void *bdrv_get_attached_dev(BlockDriverState *bs);
void bdrv_set_dev_ops(BlockDriverState *bs, const BlockDevOps *ops,
                      void *opaque);
bool bdrv_dev_has_removable_media(BlockDriverState *bs);
int bdrv_read(BlockDriverState *bs, int64_t sector_num,
              uint8_t *buf, int nb_sectors);
int bdrv_write(BlockDriverState *bs, int64_t sector_num,
               const uint8_t *buf, int nb_sectors);
int bdrv_check_request(BlockDriverState *bs, int64_t sector_num,
                       int nb_sectors);
int64_t bdrv_getlength(BlockDriverState *bs);
void bdrv_get_geometry(BlockDriverState *bs, uint64_t *nb_sectors_ptr);
void bdrv_guess_geometry(BlockDriverState *bs, int *pcyls, int *pheads, int *psecs);


typedef struct BlockDriverAIOCB BlockDriverAIOCB;
typedef void BlockDriverCompletionFunc(void *opaque, int ret);

BlockDriverAIOCB *bdrv_aio_readv(BlockDriverState *bs, int64_t sector_num,
                                 IOVector *qiov, int nb_sectors,
                                 BlockDriverCompletionFunc *cb, void *opaque);
BlockDriverAIOCB *bdrv_aio_writev(BlockDriverState *bs, int64_t sector_num,
                                  IOVector *iov, int nb_sectors,
                                  BlockDriverCompletionFunc *cb, void *opaque);

BlockDriverAIOCB *bdrv_aio_flush(BlockDriverState *bs,
                                 BlockDriverCompletionFunc *cb, void *opaque);
void bdrv_aio_cancel(BlockDriverAIOCB *acb);

int bdrv_discard(BlockDriverState *bs, int64_t sector_num, int nb_sectors);

#define BIOS_ATA_TRANSLATION_AUTO   0
#define BIOS_ATA_TRANSLATION_NONE   1
#define BIOS_ATA_TRANSLATION_LBA    2
#define BIOS_ATA_TRANSLATION_LARGE  3
#define BIOS_ATA_TRANSLATION_RECHS  4

void bdrv_set_geometry_hint(BlockDriverState *bs,
                            int cyls, int heads, int secs);
void bdrv_set_translation_hint(BlockDriverState *bs, int translation);
void bdrv_get_geometry_hint(BlockDriverState *bs,
                            int *pcyls, int *pheads, int *psecs);
int bdrv_get_translation_hint(BlockDriverState *bs);

BlockErrorAction bdrv_get_on_error(BlockDriverState *bs, int is_read);
int bdrv_is_read_only(BlockDriverState *bs);
int bdrv_enable_write_cache(BlockDriverState *bs);
int bdrv_is_inserted(BlockDriverState *bs);
void bdrv_lock_medium(BlockDriverState *bs, bool locked);
void bdrv_eject(BlockDriverState *bs, int eject_flag);
BlockDriverState *bdrv_find(const char *name);
const char *bdrv_get_device_name(BlockDriverState *bs);

void bdrv_set_buffer_alignment(BlockDriverState *bs, int align);
void *bdrv_blockalign(BlockDriverState *bs, size_t size);

void bdrv_info(void);
void bdrv_info_stats(void);

enum BlockAcctType {
    BDRV_ACCT_READ,
    BDRV_ACCT_WRITE,
    BDRV_ACCT_FLUSH,
    BDRV_MAX_IOTYPE,
};

typedef struct BlockAcctCookie {
    int64_t bytes;
    int64_t start_time_ns;
    enum BlockAcctType type;
} BlockAcctCookie;

void
bdrv_acct_start(BlockDriverState *bs, BlockAcctCookie *cookie, int64_t bytes,
		enum BlockAcctType type);
void
bdrv_acct_done(BlockDriverState *bs, BlockAcctCookie *cookie);

typedef struct BlockConf {
    BlockDriverState *bs;
    uint16_t physical_block_size;
    uint16_t logical_block_size;
    uint16_t min_io_size;
    uint32_t opt_io_size;
    int32_t bootindex;
    uint32_t discard_granularity;
} BlockConf;

static inline unsigned int get_physical_block_exp(BlockConf *conf)
{
    unsigned int exp = 0, size;

    for (size = conf->physical_block_size;
        size > conf->logical_block_size;
        size >>= 1) {
        exp++;
    }

    return exp;
}
int bdrv_is_sg(BlockDriverState *bs);

void blockstats_getabs(uint64_t *rds, uint64_t *rdops,
                       uint64_t *wrs, uint64_t *wrops);
void blockstats_getdelta(uint64_t *rds, uint64_t *rdops,
                         uint64_t *wrs, uint64_t *wrops);

#define DEFINE_BLOCK_PROPERTIES(_state, _conf)                          \
    DEFINE_PROP_DRIVE("drive", _state, _conf.bs),                       \
    DEFINE_PROP_UINT16("logical_block_size", _state,                    \
                       _conf.logical_block_size, 512),                  \
    DEFINE_PROP_UINT16("physical_block_size", _state,                   \
                       _conf.physical_block_size, 512),                 \
    DEFINE_PROP_UINT16("min_io_size", _state, _conf.min_io_size, 0),  \
    DEFINE_PROP_UINT32("opt_io_size", _state, _conf.opt_io_size, 0),    \
    DEFINE_PROP_INT32("bootindex", _state, _conf.bootindex, -1),        \
    DEFINE_PROP_UINT32("discard_granularity", _state, \
                       _conf.discard_granularity, 0)

#endif	/* _BLOCK_H_ */

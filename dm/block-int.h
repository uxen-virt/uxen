
#ifndef _BLOCK_INT_H_
#define _BLOCK_INT_H_

#include "bh.h"
#include "block.h"

#if !defined(ENOTSUP)
#define ENOTSUP 4096
#endif

typedef enum BlockDeviceIoStatus {
    BLOCK_DEVICE_IO_STATUS_OK,
    BLOCK_DEVICE_IO_STATUS_FAILED,
    BLOCK_DEVICE_IO_STATUS_NOSPACE
} BlockDeviceIoStatus;

#define BLOCK_DRIVER_FLAG_EXTENDABLE  0x0001u

struct BlockDriver {
    const char *format_name;
    int instance_size;
    int (*bdrv_probe)(const uint8_t *buf, int buf_size, const char *filename);
    int (*bdrv_open)(BlockDriverState *bs, const char *filename, int flags);
    int (*bdrv_read)(BlockDriverState *bs, int64_t sector_num,
                     uint8_t *buf, int nb_sectors);
    int (*bdrv_write)(BlockDriverState *bs, int64_t sector_num,
                      const uint8_t *buf, int nb_sectors);
    void (*bdrv_close)(BlockDriverState *bs);
    int (*bdrv_create)(const char *filename, int64_t total_sectors,
                       int flags);
    int (*bdrv_remove)(BlockDriverState *bs);
    int (*bdrv_flush)(BlockDriverState *bs);
    int (*bdrv_is_allocated)(BlockDriverState *bs, int64_t sector_num,
                             int nb_sectors, int *pnum);
    int (*bdrv_set_key)(BlockDriverState *bs, const char *key);
    int (*bdrv_make_empty)(BlockDriverState *bs);
    /* aio */
    BlockDriverAIOCB *(*bdrv_aio_read)(BlockDriverState *bs,
        int64_t sector_num, uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque);
    BlockDriverAIOCB *(*bdrv_aio_write)(BlockDriverState *bs,
        int64_t sector_num, const uint8_t *buf, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque);
    BlockDriverAIOCB *(*bdrv_aio_flush)(BlockDriverState *bs,
        BlockDriverCompletionFunc *cb, void *opaque);
#if 0
    BlockDriverAIOCB *(*bdrv_aio_readv)(BlockDriverState *bs,
        int64_t sector_num, IOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque);
    BlockDriverAIOCB *(*bdrv_aio_writev)(BlockDriverState *bs,
        int64_t sector_num, IOVector *qiov, int nb_sectors,
        BlockDriverCompletionFunc *cb, void *opaque);
#endif

    const char *protocol_name;
    int (*bdrv_pread)(BlockDriverState *bs, int64_t offset,
                      uint8_t *buf, int count);
    int (*bdrv_pwrite)(BlockDriverState *bs, int64_t offset,
                       const uint8_t *buf, int count);
    int (*bdrv_truncate)(BlockDriverState *bs, int64_t offset);
    int64_t (*bdrv_getlength)(BlockDriverState *bs);
    int (*bdrv_write_compressed)(BlockDriverState *bs, int64_t sector_num,
                                 const uint8_t *buf, int nb_sectors);

    int (*bdrv_snapshot_create)(BlockDriverState *bs,
                                SnapshotInfo *sn_info);
    int (*bdrv_snapshot_goto)(BlockDriverState *bs,
                              const char *snapshot_id);
    int (*bdrv_snapshot_delete)(BlockDriverState *bs, const char *snapshot_id);
    int (*bdrv_snapshot_list)(BlockDriverState *bs,
                              SnapshotInfo **psn_info);
    int (*bdrv_get_info)(BlockDriverState *bs, BlockDriverInfo *bdi);

    int (*bdrv_put_buffer)(BlockDriverState *bs, const uint8_t *buf,
                           int64_t pos, int size);
    int (*bdrv_get_buffer)(BlockDriverState *bs, uint8_t *buf,
                           int64_t pos, int size);

    /* removable device specific */
    int (*bdrv_is_inserted)(BlockDriverState *bs);
    int (*bdrv_media_changed)(BlockDriverState *bs);
    int (*bdrv_eject)(BlockDriverState *bs, int eject_flag);
    void (*bdrv_lock_medium)(BlockDriverState *bs, bool locked);

    /* to control generic scsi devices */
    int (*bdrv_ioctl)(BlockDriverState *bs, unsigned long int req, void *buf);

    unsigned bdrv_flags;

    SIMPLEQ_ENTRY(BlockDriver) entry;
};

struct BlockDriverState {
    int64_t total_sectors; /* if we are reading a disk image, give its
                              size in sectors */
    int read_only; /* if true, the media is read only */
    int removable; /* if true, the media can be removed */
    int locked;    /* if true, the media cannot temporarily be ejected */
    int encrypted; /* if true, the media is encrypted */
    int valid_key; /* if true, a valid encryption key has been set */
    int sg;        /* if true, the device is a /dev/sg* */
    int extendable;/* if true, we may write out of original range */
    int snapshot;
    /* event callback when inserting/removing */
    void (*change_cb)(void *opaque);
    void *change_opaque;

    BlockDriver *drv; /* NULL means no media */
    void *opaque;

    void *dev;                  /* attached device model, if any */
    /* TODO change to DeviceState when all users are qdevified */
    const BlockDevOps *dev_ops;
    void *dev_opaque;

    char filename[1024];
    int is_temporary;
    int media_changed;

    /* async read/write emulation */

    void *sync_aiocb;

    /* I/O stats (display with "info blockstats"). */
    uint64_t nr_bytes[BDRV_MAX_IOTYPE];
    uint64_t nr_ops[BDRV_MAX_IOTYPE];
    uint64_t total_time_ns[BDRV_MAX_IOTYPE];
    uint64_t wr_highest_sector;

    /* Whether the disk can expand beyond total_sectors */
    int growable;

    /* the memory alignment required for the buffers handled by this driver */
    int buffer_alignment;

    /* do we need to tell the quest if we have a volatile write cache? */
    int enable_write_cache;

    /* NOTE: the following infos are only hints for real hardware
       drivers. They are not used by the block driver */
    int cyls, heads, secs, translation;
    BlockErrorAction on_read_error, on_write_error;
    bool iostatus_enabled;
    BlockDeviceIoStatus iostatus;
    bool media_cd;
    char device_name[32];
    TAILQ_ENTRY(BlockDriverState) entry;
    void *private;
};

struct AIOPool {
    void (*cancel)(BlockDriverAIOCB *acb);
    int aiocb_size;
    BlockDriverAIOCB *free_aiocb;
};

struct BlockDriverAIOCB {
    AIOPool *pool;
    BlockDriverState *bs;
    BlockDriverCompletionFunc *cb;
    void *opaque;
    BlockDriverAIOCB *next;
};

struct BlockDriverAIOCB_sync {
    BlockDriverAIOCB common;
    BH *bh;
    int ret;
};

#endif	/* _BLOCK_INT_H_ */

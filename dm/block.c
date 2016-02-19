/*
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include "config.h"

#include <err.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "aio.h"
#include "block.h"
#include "block-int.h"
#include "clock.h"
#include "compiler.h"
#include "introspection.h"
#include "dm.h"
#include "hw.h"
#include "lib.h"
#include "monitor.h"
#include "os.h"
#include "queue.h"
#include "base64.h"
#include "firmware.h"

#include "qemu_bswap.h"

#include "yajl.h"

#include <libvhd.h>

static SIMPLEQ_HEAD(, BlockDriver) bdrv_all =
    SIMPLEQ_HEAD_INITIALIZER(bdrv_all);

static TAILQ_HEAD(, BlockDriverState) bs_all =
    TAILQ_HEAD_INITIALIZER(bs_all);

DriveInfo drives_table[MAX_IDE_BUS * MAX_IDE_DEVS + MAX_ICH_DEVS];

static void bdrv_close(BlockDriverState *bs);

static void
bdrv_register(BlockDriver *bdrv)
{

    aio_setup_em(bdrv);

    SIMPLEQ_INSERT_TAIL(&bdrv_all, bdrv, entry);
}

void
bdrv_init(void)
{

    bdrv_register(&bdrv_raw);
    bdrv_register(&bdrv_vhd);
#ifdef CONFIG_BLOCK_SWAP
    bdrv_register(&bdrv_swap);
#endif
}

int
bdrv_snapshot(BlockDriverState *bs)
{
#ifndef LIBIMG
    int ret;
    char *snapshot = strchr(bs->filename, ':');
    char *parent;

    if (strlen(bs->filename) + 38 > sizeof(bs->filename))
        errx(1, "%s: snapshot filename too long", __FUNCTION__);

    if (!snapshot)
        errx(1, "bdrv_snapshot: Failed");
    snapshot++;

    parent = strdup(snapshot);

    strcat(snapshot, "-");
    uuid_unparse_lower(vm_uuid, &snapshot[strlen(snapshot)]);

    ret = vhd_snapshot(snapshot, 0, parent, 0, 0);
    if (ret)
        errx(1, "bdrv_snapshot: vhd_snapshot failed");
#endif

    return 0;
}

int
bdrv_prepare(DriveInfo *di)
{
    int bdrv_flags = di->media_cd ? 0 : BDRV_O_RDWR;
    int rc;

    bdrv_flags |= BDRV_O_CACHE_WB;

    rc = bdrv_open2(di->bdrv, di->file,
                    bdrv_flags, NULL);

    return rc;
}

int
bdrv_add(yajl_val arg)
{
    const char *id, *proto, *path;
    int index;
    BlockDriverState *bdrv;
#ifndef LIBIMG
    const char *serial, *model, *version, *properties;
    size_t l;
#endif
    int snapshot;
    int cdrom;

    assert(YAJL_IS_OBJECT(arg));

    id = yajl_object_get_string(arg, "id");
    proto = yajl_object_get_string(arg, "proto") ?: "raw";
    log_swap_fills = yajl_object_get_bool_default(arg, "log-swap-fill-reads", false);
    path = yajl_object_get_string(arg, "path");

#ifndef LIBIMG
    serial = yajl_object_get_string(arg, "serial");
    version = yajl_object_get_string(arg, "version");
    model = yajl_object_get_string(arg, "model");
    properties = yajl_object_get_string(arg, "properties");
#endif

    snapshot = yajl_object_get_bool_default(arg, "snapshot", -1);
    cdrom = yajl_object_get_bool_default(arg, "cdrom", -1);

    if (!id)
	errx(1, "config bdrv_add: id missing");

    if (strlen(id) == 3 && !strncmp(id, "hd", 2) &&
	id[2] >= 'a' && id[2] <= 'd') {
	index = id[2] - 'a';
    } else if (strlen(id) == 4 && !strncmp(id, "ich", 3) &&
	       id[3] >= '0' && id[3] <= '5') {
	index = 4 + id[3] - '0';
    } else if (!strcmp(id, "cdrom")) {
	index = 5;
        cdrom = 1;
    } else
	errx(1, "config bdrv_add: invalid id %s", id);

    if (!drives_table[index].bdrv)
        drives_table[index].bdrv = bdrv_new(id);
    bdrv = drives_table[index].bdrv;

    if (cdrom == -1)
        cdrom = drives_table[index].media_cd;

    if (!bdrv->device_name[0] || cdrom != drives_table[index].media_cd) {
        char *devname = "ide";
        char *mediastr = "-hd";
        int bus_id, unit_id;
        int max_devs = 2;

        if (cdrom)
            mediastr = "-cd";

        if (index < 4) {
            bus_id = index / max_devs;
            unit_id = index % max_devs;
        } else {
            bus_id = index - 4;
            unit_id = 0;
            devname = "ich";
        }

        snprintf(bdrv->device_name, sizeof (bdrv->device_name), "%s%i%s%i",
                 devname, bus_id, mediastr, unit_id);

        drives_table[index].media_cd = cdrom;
        bdrv->removable = cdrom;
    }

    if (path) {
        if (drives_table[index].file)
            free(drives_table[index].file);
        asprintf(&drives_table[index].file, "%s:%s", proto, path);
    }

    if (snapshot != -1)
        bdrv->snapshot = snapshot;

#ifndef LIBIMG
    if (serial) {
        drives_table[index].serial = (char *)base64_decode(serial, &l);
        if (drives_table[index].serial && l != 20)
	    errx(1, "config bdrv_add: Disk serial number must be 20 bytes");
    }

    if (model) {
        drives_table[index].model = (char *)base64_decode(model, &l);
        if (drives_table[index].model && l != 40)
	    errx(1, "config bdrv_add: Disk model identifier must be 40 bytes");
    }

    if (version) {
        drives_table[index].version = (char *)base64_decode(version, &l);
        if (drives_table[index].version && l != 8)
	    errx(1, "config bdrv_add: Disk version identifier must be 8 bytes");
    }

    if (properties) {
        void *data;

        data = base64_decode(properties, &l);
        if (data)
            smbios_add_drive_property(data, l);
        free(data);
    }
#endif

    return 0;
}


int
bdrv_attach_dev(BlockDriverState *bs, void *dev)
/* TODO change to DeviceState *dev when all users are qdevified */
{

    if (bs->dev)
        return -EBUSY;

    bs->dev = dev;

    bdrv_iostatus_reset(bs);

    return 0;
}

/* TODO qdevified devices don't use this, remove when devices are qdevified */
void bdrv_attach_dev_nofail(BlockDriverState *bs, void *dev)
{

    if (bdrv_attach_dev(bs, dev) < 0)
        abort();
}

void
bdrv_detach_dev(BlockDriverState *bs, void *dev)
/* TODO change to DeviceState *dev when all users are qdevified */
{

    assert(bs->dev == dev);

    bs->dev = NULL;
    bs->dev_ops = NULL;
    bs->dev_opaque = NULL;
    bs->buffer_alignment = 512;
}

/* TODO change to return DeviceState * when all users are qdevified */
void *
bdrv_get_attached_dev(BlockDriverState *bs)
{

    return bs->dev;
}

const char *
bdrv_get_device_name(BlockDriverState *bs)
{

    return bs->device_name;
}

void
bdrv_set_dev_ops(BlockDriverState *bs, const BlockDevOps *ops, void *opaque)
{

    bs->dev_ops = ops;
    bs->dev_opaque = opaque;
#if 0
    if (bdrv_dev_has_removable_media(bs) && bs == bs_snapshots) {
        bs_snapshots = NULL;
    }
#endif
}

bool
bdrv_dev_has_removable_media(BlockDriverState *bs)
{

    return !bs->dev || (bs->dev_ops && bs->dev_ops->change_media_cb);
}

void bdrv_dev_eject_request(BlockDriverState *bs, bool force)
{
    if (bs->dev_ops && bs->dev_ops->eject_request_cb) {
        bs->dev_ops->eject_request_cb(bs->dev_opaque, force);
    }
}

bool bdrv_dev_is_tray_open(BlockDriverState *bs)
{
    if (bs->dev_ops && bs->dev_ops->is_tray_open) {
        return bs->dev_ops->is_tray_open(bs->dev_opaque);
    }
    return false;
}

bool bdrv_dev_is_medium_locked(BlockDriverState *bs)
{
    if (bs->dev_ops && bs->dev_ops->is_medium_locked) {
        return bs->dev_ops->is_medium_locked(bs->dev_opaque);
    }
    return false;
}

BlockErrorAction
bdrv_get_on_error(BlockDriverState *bs, int is_read)
{

    return is_read ? bs->on_read_error : bs->on_write_error;
}

int
bdrv_is_inserted(BlockDriverState *bs)
{
    BlockDriver *drv = bs->drv;

    if (!drv)
        return 0;

    if (!drv->bdrv_is_inserted)
        return 1;

    return drv->bdrv_is_inserted(bs);
}

int
bdrv_is_removable(BlockDriverState *bs)
{

    return bs->removable;
}

int
bdrv_is_read_only(BlockDriverState *bs)
{

    return bs->read_only;
}

int
bdrv_is_sg(BlockDriverState *bs)
{

    return bs->sg;
}

int
bdrv_enable_write_cache(BlockDriverState *bs)
{

    return bs->enable_write_cache;
}

void
bdrv_eject(BlockDriverState *bs, int eject_flag)
{
    BlockDriver *drv = bs->drv;
    int ret;

    if (!drv || !drv->bdrv_eject)
        ret = -ENOTSUP;
    else
        ret = drv->bdrv_eject(bs, eject_flag);

    if (ret == -ENOTSUP && eject_flag)
        bdrv_close(bs);
}

BlockDriverState *
bdrv_find(const char *name)
{
    BlockDriverState *bs;

    TAILQ_FOREACH(bs, &bs_all, entry)
        if (!strcmp(name, bs->device_name))
            break;

    return bs;
}

#ifdef _WIN32
static int is_windows_drive_prefix(const char *filename)
{
    return (((filename[0] >= 'a' && filename[0] <= 'z') ||
             (filename[0] >= 'A' && filename[0] <= 'Z')) &&
            filename[1] == ':');
}

static int is_windows_drive(const char *filename)
{
    if (is_windows_drive_prefix(filename) &&
        filename[2] == '\0')
        return 1;
    if (strstart(filename, "\\\\.\\", NULL) ||
        strstart(filename, "//./", NULL))
        return 1;
    return 0;
}
#endif  /* _WIN32 */

static BlockDriver *
find_protocol(const char *filename)
{
    /* Return values:
     *   &bdrv_xxx
     *      filename specifies protocol xxx
     *      caller should use that
     *   NULL
     *      filename does not specify any protocol
     *      caller may apply their own default
     */
    BlockDriver *bdrv;
    char protocol[128];
    int len;
    const char *p;

#ifdef _WIN32
    if (is_windows_drive(filename) || is_windows_drive_prefix(filename))
        return &bdrv_raw;
#endif

    p = strchr(filename, ':');
    if (!p)
        return NULL;

    len = p - filename;
    if (len > sizeof(protocol) - 1)
        len = sizeof(protocol) - 1;

    strncpy(protocol, filename, len);
    protocol[len] = '\0';

    SIMPLEQ_FOREACH(bdrv, &bdrv_all, entry)
        if (bdrv->protocol_name &&
            !strcmp(bdrv->protocol_name, protocol))
            break;

    return bdrv;
}

int
bdrv_file_open(BlockDriverState **pbs, const char *filename, int flags)
{
    BlockDriverState *bs;
    int ret;

    bs = bdrv_new("");

    ret = bdrv_open2(bs, filename, flags, &bdrv_raw);

    if (ret < 0) {
        bdrv_delete(bs);
        return ret;
    }

    bs->growable = 1;

    *pbs = bs;

    return 0;
}

int
bdrv_open(BlockDriverState *bs, const char *filename, int flags)
{

    return bdrv_open2(bs, filename, flags, NULL);
}

int
bdrv_open2(BlockDriverState *bs, const char *filename, int flags,
           BlockDriver *drv)
{
    int ret, open_flags;

    bs->read_only = (flags & BDRV_O_RDWR) ? 0 : 1;
    bs->is_temporary = 0;
    bs->encrypted = 0;
    bs->valid_key = 0;

    if (!filename)
        return -1;

    strncpy(bs->filename, filename, sizeof(bs->filename) - 1);
    bs->filename[sizeof(bs->filename) - 1] = 0;

    if (bs->snapshot)
        bdrv_snapshot(bs);

    if (drv == NULL)
        drv = find_protocol(filename);
    if (drv == NULL)
        drv = &bdrv_raw;
    bs->drv = drv;
    bs->opaque = calloc(1, drv->instance_size);

    open_flags = flags & (BDRV_O_RDWR | BDRV_O_CACHE_MASK);
    ret = drv->bdrv_open(bs, bs->filename, open_flags);
    if ((ret == -EACCES || ret == -EPERM) && (open_flags & BDRV_O_RDWR)) {
        ret = drv->bdrv_open(bs, bs->filename, open_flags & ~BDRV_O_RDWR);
        bs->read_only = 1;
    }

    if (ret < 0) {
        free(bs->opaque);
        bs->opaque = NULL;
        bs->drv = NULL;
        if (bs->is_temporary)
            unlink(bs->filename);
        return ret;
    }

    if (drv->bdrv_getlength)
        bs->total_sectors = bdrv_getlength(bs) >> BDRV_SECTOR_BITS;

#ifndef _WIN32
    if (bs->is_temporary) {
        unlink(bs->filename);
    }
#endif

    /* call the change callback */
    bs->media_changed = 1;
    if (bs->change_cb)
        bs->change_cb(bs->change_opaque);

    return 0;
}

static void
bdrv_close(BlockDriverState *bs)
{
    if (bs->drv) {
        bs->drv->bdrv_close(bs);
        free(bs->opaque);
#ifdef _WIN32
        if (bs->is_temporary) {
            unlink(bs->filename);
        }
#endif
        bs->opaque = NULL;
        bs->drv = NULL;

        /* call the change callback */
        bs->media_changed = 1;
        if (bs->change_cb)
            bs->change_cb(bs->change_opaque);
    }
}

int
bdrv_flush(BlockDriverState *bs)
{
    int ret = 0;

    if (!bs->drv)
        return -EINVAL;

    if (bs->drv->bdrv_flush)
        ret = bs->drv->bdrv_flush(bs);

    return ret;
}

int
bdrv_flush_all(int do_close)
{
    BlockDriverState *bs;
    int ret = 0, ret1;

    TAILQ_FOREACH(bs, &bs_all, entry)
        if (bs->drv && !bdrv_is_read_only(bs) && 
            (!bdrv_is_removable(bs) || bdrv_is_inserted(bs))) {
            ret1 = bdrv_flush(bs);
            if (ret1)
                ret = ret1;
            if (do_close)
                bdrv_close(bs);
        }

    return ret;
}

/* return < 0 if error. See bdrv_write() for the return codes */
int
bdrv_read(BlockDriverState *bs, int64_t sector_num,
          uint8_t *buf, int nb_sectors)
{
    BlockDriver *drv = bs->drv;

    if (!drv)
        return -ENOMEDIUM;
    if (bdrv_check_request(bs, sector_num, nb_sectors))
        return -EIO;

    if (drv->bdrv_pread) {
        int ret, len;

        len = nb_sectors * 512;

        ret = drv->bdrv_pread(bs, sector_num * 512, buf, len);
        if (ret < 0)
            return ret;
        else if (ret != len)
            return -EINVAL;

        bs->nr_bytes[BDRV_ACCT_READ] += len;
        bs->nr_ops[BDRV_ACCT_READ]++;

        return 0;
    }

    return drv->bdrv_read(bs, sector_num, buf, nb_sectors);
}

/* Return < 0 if error. Important errors are:
  -EIO         generic I/O error (may happen for all errors)
  -ENOMEDIUM   No media inserted.
  -EINVAL      Invalid sector number or nb_sectors
  -EACCES      Trying to write a read-only device
*/
int
bdrv_write(BlockDriverState *bs, int64_t sector_num,
           const uint8_t *buf, int nb_sectors)
{
    BlockDriver *drv = bs->drv;

    if (!bs->drv)
        return -ENOMEDIUM;
    if (bs->read_only)
        return -EACCES;
    if (bdrv_check_request(bs, sector_num, nb_sectors))
        return -EIO;

#ifndef LIBIMG
    if (bs->device_name[0]) /* So, guest device, not backing file */
        lava_check_mbr_vbr_write(sector_num);
#endif

    if (drv->bdrv_pwrite) {
        int ret, len, count = 0;

        len = nb_sectors * 512;

        do {
            ret = drv->bdrv_pwrite(bs, sector_num * 512, buf, len - count);
            if (ret < 0) {
                printf("bdrv_write ret=%d\n", ret);
                return ret;
            }
            count += ret;
            buf += ret;
        } while (count != len);

        bs->nr_bytes[BDRV_ACCT_WRITE] += len;
        bs->nr_ops[BDRV_ACCT_WRITE]++;

        return 0;
    }

    return drv->bdrv_write(bs, sector_num, buf, nb_sectors);
}

BlockDriverState *
bdrv_new(const char *device_name)
{
    BlockDriverState *bs;

    bs = calloc(1, sizeof(BlockDriverState));
    if (!bs)
        return NULL;

    strncpy(bs->device_name, device_name, sizeof(bs->device_name) - 1);
    bs->device_name[sizeof(bs->device_name) - 1] = 0;

    if (device_name[0])
        TAILQ_INSERT_TAIL(&bs_all, bs, entry);

    return bs;
}

void bdrv_delete(BlockDriverState *bs)
{
    if (bs->device_name[0])
        TAILQ_REMOVE(&bs_all, bs, entry);

    bdrv_close(bs);
    free(bs);
}

int
bdrv_create(const char* filename, int64_t total_size, int flags)
{
    BlockDriver *bdrv;

    bdrv = find_protocol(filename);
    if (bdrv == NULL)
        bdrv = &bdrv_raw;

    if (!bdrv->bdrv_create)
        return -ENOTSUP;

    return bdrv->bdrv_create(filename, total_size, flags);
}

int bdrv_remove(BlockDriverState *bs)
{
    if (!bs->drv)
        return -EINVAL;

    if (!bs->drv->bdrv_remove)
        return -ENOTSUP;

    return bs->drv->bdrv_remove(bs);
}


static int bdrv_check_byte_request(BlockDriverState *bs, int64_t offset,
                                   size_t size)
{
    int64_t len;

    if (!bdrv_is_inserted(bs))
        return -ENOMEDIUM;

    if (bs->growable)
        return 0;

    len = bdrv_getlength(bs);

    if (offset < 0)
        return -EIO;

    if ((offset > len) || (len - offset < size))
        return -EIO;

    return 0;
}

int
bdrv_check_request(BlockDriverState *bs, int64_t sector_num,
                   int nb_sectors)
{

    if (nb_sectors < 0 || nb_sectors > INT_MAX / BDRV_SECTOR_SIZE ||
        sector_num < 0 || sector_num > INT64_MAX / BDRV_SECTOR_SIZE) {
        debug_printf("bdrv_check_request fail, %d/%"PRId64"\n",
            nb_sectors, sector_num);
        return -EIO;
    }
    return bdrv_check_byte_request(bs, sector_num * BDRV_SECTOR_SIZE,
                                   nb_sectors * BDRV_SECTOR_SIZE);
}

/**
 * Length of a file in bytes. Return < 0 if error or unknown.
 */
int64_t
bdrv_getlength(BlockDriverState *bs)
{
    BlockDriver *drv = bs->drv;

    if (!drv)
        return -ENOMEDIUM;

    if (bs->growable || bdrv_dev_has_removable_media(bs))
        if (drv->bdrv_getlength)
            return drv->bdrv_getlength(bs);

    return bs->total_sectors * BDRV_SECTOR_SIZE;
}

/* return 0 as number of sectors if no device present or error */
void
bdrv_get_geometry(BlockDriverState *bs, uint64_t *nb_sectors_ptr)
{
    int64_t length;

    length = bdrv_getlength(bs);

    if (length < 0)
        length = 0;
    else
        length = length >> BDRV_SECTOR_BITS;

    *nb_sectors_ptr = length;
}

int bdrv_ioctl(BlockDriverState *bs, unsigned long int req, void *buf)
{
    BlockDriver *drv = bs->drv;

    if (!drv)
        return -EINVAL;

    if (!drv->bdrv_ioctl)
        return -ENOTSUP;

    return drv->bdrv_ioctl(bs, req, buf);
}

struct partition {
        uint8_t boot_ind;           /* 0x80 - active */
        uint8_t head;               /* starting head */
        uint8_t sector;             /* starting sector */
        uint8_t cyl;                /* starting cylinder */
        uint8_t sys_ind;            /* What partition type */
        uint8_t end_head;           /* end head */
        uint8_t end_sector;         /* end sector */
        uint8_t end_cyl;            /* end cylinder */
        uint32_t start_sect;        /* starting sector counting from 0 */
        uint32_t nr_sects;          /* nr of sectors in partition */
} __attribute__((packed));

/* try to guess the disk logical geometry from the MSDOS partition
 * table. Return 0 if OK, -1 if could not guess */
static int
guess_disk_lchs(BlockDriverState *bs,
                int *pcylinders, int *pheads, int *psectors)
{
    uint8_t buf[512];
    int ret, i, heads, sectors, cylinders;
    struct partition *p;
    uint32_t nr_sects;
    uint64_t nb_sectors;

    bdrv_get_geometry(bs, &nb_sectors);

    ret = bdrv_read(bs, 0, buf, 1);
    if (ret < 0)
        return -1;
    /* test msdos magic */
    if (buf[510] != 0x55 || buf[511] != 0xaa)
        return -1;
    for(i = 0; i < 4; i++) {
        p = ((struct partition *)(buf + 0x1be)) + i;
        nr_sects = le32_to_cpu(p->nr_sects);
        if (nr_sects && p->end_head) {
            /* We make the assumption that the partition terminates on
               a cylinder boundary */
            heads = p->end_head + 1;
            sectors = p->end_sector & 63;
            if (sectors == 0)
                continue;
            cylinders = nb_sectors / (heads * sectors);
            if (cylinders < 1 || cylinders > 16383)
                continue;
            *pheads = heads;
            *psectors = sectors;
            *pcylinders = cylinders;
#if 0
            printf("guessed geometry: LCHS=%d %d %d\n",
                   cylinders, heads, sectors);
#endif
            return 0;
        }
    }
    return -1;
}

void
bdrv_guess_geometry(BlockDriverState *bs, int *pcyls, int *pheads, int *psecs)
{
    int translation, lba_detected = 0;
    int cylinders, heads, secs;
    uint64_t nb_sectors;

    /* if a geometry hint is available, use it */
    bdrv_get_geometry(bs, &nb_sectors);
    bdrv_get_geometry_hint(bs, &cylinders, &heads, &secs);

    translation = bdrv_get_translation_hint(bs);

    if (cylinders != 0) {
        *pcyls = cylinders;
        *pheads = heads;
        *psecs = secs;
    } else {
        if (guess_disk_lchs(bs, &cylinders, &heads, &secs) == 0) {
            if (heads > 16) {
                /* if heads > 16, it means that a BIOS LBA
                   translation was active, so the default
                   hardware geometry is OK */
                lba_detected = 1;
                goto default_geometry;
            } else {
                *pcyls = cylinders;
                *pheads = heads;
                *psecs = secs;
                /* disable any translation to be in sync with
                   the logical geometry */
                if (translation == BIOS_ATA_TRANSLATION_AUTO) {
                    bdrv_set_translation_hint(bs,
                                              BIOS_ATA_TRANSLATION_NONE);
                }
            }
        } else {
        default_geometry:
            /* if no geometry, use a standard physical disk geometry */
            cylinders = nb_sectors / (16 * 63);

            if (cylinders > 16383)
                cylinders = 16383;
            else if (cylinders < 2)
                cylinders = 2;
            *pcyls = cylinders;
            *pheads = 16;
            *psecs = 63;
            if ((lba_detected == 1) &&
                (translation == BIOS_ATA_TRANSLATION_AUTO)) {
                if ((*pcyls * *pheads) <= 131072) {
                    bdrv_set_translation_hint(bs,
                                              BIOS_ATA_TRANSLATION_LARGE);
                } else {
                    bdrv_set_translation_hint(bs,
                                              BIOS_ATA_TRANSLATION_LBA);
                }
            }
        }
        bdrv_set_geometry_hint(bs, *pcyls, *pheads, *psecs);
    }
}

void
bdrv_set_geometry_hint(BlockDriverState *bs,
                       int cyls, int heads, int secs)
{

    bs->cyls = cyls;
    bs->heads = heads;
    bs->secs = secs;
}

void
bdrv_set_translation_hint(BlockDriverState *bs, int translation)
{

    bs->translation = translation;
}

void
bdrv_get_geometry_hint(BlockDriverState *bs,
                       int *pcyls, int *pheads, int *psecs)
{

    *pcyls = bs->cyls;
    *pheads = bs->heads;
    *psecs = bs->secs;
}

int
bdrv_get_translation_hint(BlockDriverState *bs)
{

    return bs->translation;
}

void
bdrv_mon_event(const BlockDriverState *bdrv,
               BlockMonEventAction action, int is_read)
{
    const char *action_str;

    switch (action) {
    case BDRV_ACTION_REPORT:
        action_str = "report";
        break;
    case BDRV_ACTION_IGNORE:
        action_str = "ignore";
        break;
    case BDRV_ACTION_STOP:
        action_str = "stop";
        break;
    default:
        abort();
    }

    dprintf("%s", action_str);
}

int
bdrv_discard(BlockDriverState *bs, int64_t sector_num, int nb_sectors)
{
    if (!bs->drv) {
        return -ENOMEDIUM;
    } else if (bdrv_check_request(bs, sector_num, nb_sectors)) {
        return -EIO;
    } else if (bs->read_only) {
        return -EROFS;
#if 0
    } else if (bs->drv->bdrv_aio_discard) {
        BlockDriverAIOCB *acb;
        CoroutineIOCompletion co = {
            .coroutine = qemu_coroutine_self(),
        };

        acb = bs->drv->bdrv_aio_discard(bs, sector_num, nb_sectors,
                                        bdrv_co_io_em_complete, &co);
        if (acb == NULL) {
            return -EIO;
        } else {
            qemu_coroutine_yield();
            return co.ret;
        }
#endif
    } else {
        return 0;
    }
}

/**
 * Lock or unlock the media (if it is locked, the user won't be able
 * to eject it manually).
 */
void bdrv_lock_medium(BlockDriverState *bs, bool locked)
{
    BlockDriver *drv = bs->drv;

    if (drv && drv->bdrv_lock_medium)
        drv->bdrv_lock_medium(bs, locked);
}

void bdrv_set_buffer_alignment(BlockDriverState *bs, int align)
{
    bs->buffer_alignment = align;
}

void *bdrv_blockalign(BlockDriverState *bs, size_t size)
{
    return align_alloc((bs && bs->buffer_alignment) ?
		       bs->buffer_alignment : 512, size);
}

void bdrv_iostatus_enable(BlockDriverState *bs)
{
    bs->iostatus_enabled = true;
    bs->iostatus = BLOCK_DEVICE_IO_STATUS_OK;
}

/* The I/O status is only enabled if the drive explicitly
 * enables it _and_ the VM is configured to stop on errors */
bool bdrv_iostatus_is_enabled(const BlockDriverState *bs)
{
    return (bs->iostatus_enabled &&
           (bs->on_write_error == BLOCK_ERR_STOP_ENOSPC ||
            bs->on_write_error == BLOCK_ERR_STOP_ANY    ||
            bs->on_read_error == BLOCK_ERR_STOP_ANY));
}

void bdrv_iostatus_disable(BlockDriverState *bs)
{
    bs->iostatus_enabled = false;
}

void bdrv_iostatus_reset(BlockDriverState *bs)
{
    if (bdrv_iostatus_is_enabled(bs)) {
        bs->iostatus = BLOCK_DEVICE_IO_STATUS_OK;
    }
}

/* XXX: Today this is set by device models because it makes the implementation
   quite simple. However, the block layer knows about the error, so it's
   possible to implement this without device models being involved */
void bdrv_iostatus_set_err(BlockDriverState *bs, int error)
{
    if (bdrv_iostatus_is_enabled(bs) &&
        bs->iostatus == BLOCK_DEVICE_IO_STATUS_OK) {
        assert(error >= 0);
        bs->iostatus = error == ENOSPC ? BLOCK_DEVICE_IO_STATUS_NOSPACE :
                                         BLOCK_DEVICE_IO_STATUS_FAILED;
    }
}

/* bdrv_acct */
void
bdrv_acct_start(BlockDriverState *bs, BlockAcctCookie *cookie, int64_t bytes,
        enum BlockAcctType type)
{
    assert(type < BDRV_MAX_IOTYPE);

    cookie->bytes = bytes;
    cookie->start_time_ns = os_get_clock();
    cookie->type = type;
}

void
bdrv_acct_done(BlockDriverState *bs, BlockAcctCookie *cookie)
{
    assert(cookie->type < BDRV_MAX_IOTYPE);

    bs->nr_bytes[cookie->type] += cookie->bytes;
    bs->nr_ops[cookie->type]++;
    bs->total_time_ns[cookie->type] += os_get_clock() - cookie->start_time_ns;
}

#ifdef MONITOR
void
ic_block(Monitor *mon)
{
    BlockDriverState *bs;

    TAILQ_FOREACH(bs, &bs_all, entry) {
        monitor_printf(mon, "%s:", bs->device_name);

        monitor_printf(mon, " removable=%d", bs->removable);
        if (bs->removable)
            monitor_printf(mon, " locked=%d", bs->locked);

        if (bs->drv) {
            monitor_printf(mon, " file=");
	    monitor_print_filename(mon, bs->filename);
            monitor_printf(mon, " ro=%d", bs->read_only);
            monitor_printf(mon, " drv=%s", bs->drv->format_name);
        } else {
            monitor_printf(mon, " [not inserted]");
        }

        monitor_printf(mon, "\n");
    }
}
#endif  /* MONITOR */

void
blockstats_getabs(uint64_t *readsz, uint64_t *readop,
                  uint64_t *writesz, uint64_t *writeop)
{
    BlockDriverState *bs;
    uint64_t rds, rdops, wrs, wrops;

    rds = 0;
    wrs = 0;
    rdops = 0;
    wrops = 0;

    TAILQ_FOREACH(bs, &bs_all, entry) {
	rds += bs->nr_bytes[BDRV_ACCT_READ];
	wrs += bs->nr_bytes[BDRV_ACCT_WRITE];
	rdops += bs->nr_ops[BDRV_ACCT_READ];
	wrops += bs->nr_ops[BDRV_ACCT_WRITE];
    }

    if (readsz) *readsz = rds;
    if (writesz) *writesz = wrs;
    if (readop) *readop = rdops;
    if (writeop) *writeop = wrops;
}

void
blockstats_getdelta(uint64_t *readsz, uint64_t *readop,
                    uint64_t *writesz, uint64_t *writeop)
{
    uint64_t rds, rdops, wrs, wrops;
    static uint64_t lastrds = 0, lastrdops = 0, lastwrs = 0, lastwrops = 0;

    blockstats_getabs(&rds, &rdops, &wrs, &wrops);

    if (readsz) *readsz = rds - lastrds;
    if (writesz) *writesz = wrs - lastwrs;
    if (readop) *readop = rdops - lastrdops;
    if (writeop) *writeop = wrops - lastwrops;

    lastrds = rds;
    lastrdops = rdops;
    lastwrs = wrs;
    lastwrops = wrops;
}

#ifdef MONITOR
/* The "info blockstats" command. */
void
ic_blockstats(Monitor *mon)
{
    BlockDriverState *bs;

    TAILQ_FOREACH(bs, &bs_all, entry)
	monitor_printf(mon, "%s:"
                       " rd_bytes=%" PRIu64
                       " wr_bytes=%" PRIu64
                       " rd_operations=%" PRIu64
                       " wr_operations=%" PRIu64
                       "\n",
                       bs->device_name,
                       bs->nr_bytes[BDRV_ACCT_READ],
                       bs->nr_bytes[BDRV_ACCT_WRITE],
                       bs->nr_ops[BDRV_ACCT_READ],
                       bs->nr_ops[BDRV_ACCT_WRITE]);
}
#endif  /* MONITOR */

#ifdef MONITOR
static int
eject_device(Monitor *mon, BlockDriverState *bs, int force)
{

    if (!bdrv_dev_has_removable_media(bs)) {
        monitor_printf(mon, "device %s is not removable\n", bs->device_name);
        return -1;
    }
    if (bdrv_dev_is_medium_locked(bs) && !bdrv_dev_is_tray_open(bs)) {
        bdrv_dev_eject_request(bs, force);
        if (!force) {
            monitor_printf(mon, "device %s is locked\n", bs->device_name);
            return -1;
        }
    }
    bdrv_close(bs);
    return 0;
}

void
mc_block_change(Monitor *mon, const dict args)
{
    const char *id, *image;
    BlockDriverState *bs;
    int bdrv_flags;

    id = dict_get_string(args, "id");
    image = dict_get_string(args, "image");

    bs = bdrv_find(id);
    if (!bs) {
        monitor_printf(mon, "device %s does not exist\n", id);
        return;
    }

    if (eject_device(mon, bs, 0) < 0) {
        monitor_printf(mon, "device %s eject failed\n", id);
        return;
    }

    if (image) {
        bdrv_flags = bdrv_is_read_only(bs) ? 0 : BDRV_O_RDWR;
        if (bdrv_open(bs, image, bdrv_flags) < 0) {
            monitor_printf(mon, "device %s image %s open failed\n", id, image);
            return;
        }
    }
}
#endif  /* MONITOR */

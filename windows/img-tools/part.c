/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disklib.h"
#include "partition.h"
#include "disklib-internal.h"

#include <sys/param.h>
#include <sys/time.h>
#include <ntfs-3g/device.h>

#include "cache.h"

#if 1
#define dprintf(x...) LogRel((x))
#else
#define dprintf(x...) do {}while(0);
#endif

#define MBR_NUM_PART         4
#define MBR_SIG_OFFSET       0x1fe
#define MBR_SIG_VALUE        0xaa55
#define MBR_PART_OFFSET      0x1be
#define MBR_SERIAL_OFFSET    0x1b8
#define MBR_PART_SIZE        0x10
#define MBR_CHS_LIMIT        (1024*255*63 - 1)

/* One partition of a disk */
struct _partition {
    struct _ptbl *p_tbl;
    uint8_t p_status;
    uint8_t p_type;
    uint64_t p_lba_start;
    uint64_t p_lba_end;
};

/* A disk with a partition table */
struct _ptbl {
    disk_handle_t pt_hdd;
    struct _partition *pt_part;
    Cache *pt_cache;
    uint64_t cCylinders;
    uint64_t cHeads;
    uint64_t cSectors;
    uint32_t pt_sig;
    uint16_t pt_count;
    uint8_t pt_cache_bypass;
    uint8_t pt_cache_immutable;
    uint8_t pt_bulk_fetch;
};

static uint32_t chs_to_lba(ptbl_t pt, uint8_t *chs)
{
    uint32_t c, h, s, lba;

    c = ((chs[1] & 0xc0) << 2) | chs[2];
    h = chs[0];
    s = chs[1] & 0x3f;

    lba = (c * pt->cHeads + h) * pt->cSectors + s - 1;
    //dprintf("chs2lba: %u/%u/%u = %u\n", c, h, s, lba);
    //if (lba >= MBR_CHS_LIMIT)
    //    dprintf("Reached CHS up limit: %u/%u/%u = %u\n", c, h, s, lba);
    return lba;
}


static int read_pt(ptbl_t pt)
{
    uint8_t buf[SECTOR_SIZE];
    unsigned int i, j;
    uint8_t *ptr;

    pt->pt_count = 0;

    /* Pull in MBR */

    if (!disk_read_sectors(pt->pt_hdd, buf, 0, 1, NULL)) {
        disklib__set_errno(DISKLIB_ERR_IO);
        return 0;
    }
 
    if ( MBR_SIG_VALUE != *(uint16_t *)(buf + MBR_SIG_OFFSET) ) {
        disklib__set_errno(DISKLIB_ERR_BAD_PART_SIG);
        return 0;
    }

    pt->pt_sig = *(uint32_t *)(buf + MBR_SERIAL_OFFSET);

    /* Just count */
    for(ptr = buf + MBR_PART_OFFSET, i = 0; i < 4; i++,
            ptr += MBR_PART_SIZE) {
        uint8_t type = ptr[4];
        switch(type) {
        case PART_TYPE_EMPTY:
            continue;
        case PART_TYPE_EXTENDED:
        case PART_TYPE_EXTENDED_LBA:
            LogAlways((" *** Ignoring extended partition %u\n", i));
            continue;
        default:
            pt->pt_count++;
            break;
        }
    }

    pt->pt_part = RTMemAllocZ(pt->pt_count * sizeof(*pt->pt_part));
    if ( NULL == pt->pt_part ) {
        disklib__set_errno(DISKLIB_ERR_NOMEM);
        return 0;
    }

    for(ptr = buf + MBR_PART_OFFSET, i = j = 0; i < 4; i++,
            ptr += MBR_PART_SIZE) {
        uint8_t status, type;
        uint32_t l_start, l_end;
        uint32_t p_start, p_end;

        status = ptr[0];
        type = ptr[4];

        switch(type) {
        case PART_TYPE_EMPTY:
        case PART_TYPE_EXTENDED:
        case PART_TYPE_EXTENDED_LBA:
            continue;
        default:
            break;
        }

#if 0
        dprintf("part: %u: %spartition type 0x%.2x\n", j,
            (status == 0x80) ? "bootable " : "",
            type);
#endif

        pt->pt_part[j].p_tbl = pt;
        pt->pt_part[j].p_status = status;
        pt->pt_part[j].p_type = type;

        l_start = le32_to_cpu(*(uint32_t *)(ptr + 8));
        l_end = l_start + le32_to_cpu(*(uint32_t *)(ptr + 12));
        p_start = chs_to_lba(pt, ptr + 1);
        p_end = chs_to_lba(pt, ptr + 5);

        if ( p_start < MBR_CHS_LIMIT && p_end < MBR_CHS_LIMIT ) {
            if ( p_start != l_start || p_end != l_end ) {
                Log(("p%u: CHS/LBA mismatch: "
                        "CHS 0x%.8x -> 0x%.8x != "
                        "LBA 0x%.8x -> 0x%.8x\n",
                        j, p_start, p_end, l_start, l_end));
            }
        }

        if ( l_start && l_end > l_start ) {
            pt->pt_part[j].p_lba_start = l_start;
            pt->pt_part[j].p_lba_end = l_end;
            Log(("p%u: using LBA 0x%.8x -> 0x%.8x\n", j, l_start, l_end));
        }else{
            pt->pt_part[j].p_lba_start = p_start;
            pt->pt_part[j].p_lba_end = p_end;
            Log(("p%u: using CHS 0x%.8x -> 0x%.8x\n", j, p_start, p_end));
        }

        if ( pt->pt_part[j].p_lba_start > pt->pt_part[j].p_lba_end ) {
            pt->pt_part[j].p_type = PART_TYPE_EMPTY;
            Log((" *** Bad partition: start > end\n"));
        }

        j++;
    }

    return 1;
}

/* These tools generally rely on having the ptbl_t struct filled out in memory.
 * However, we have moved to a world where we no longer read the host MBR, so
 * we don't have a real partition table available to go from. Instead we fake
 * one from the contents of the .rawvss file. */

static int concoct_pt(ptbl_t pt)
{
    int i;
    pt->pt_count = pt->pt_hdd.num_backings;
    pt->pt_sig = 0;

    pt->pt_part = RTMemAllocZ(pt->pt_count * sizeof(*pt->pt_part));
    if ( NULL == pt->pt_part ) {
        disklib__set_errno(DISKLIB_ERR_NOMEM);
        return 0;
    }

    for (i = 0; i < pt->pt_hdd.num_backings; ++i) {

        backing *b = &pt->pt_hdd.u.backings[i];
        pt->pt_part[i].p_tbl = pt;
        pt->pt_part[i].p_status = 0x80;
        pt->pt_part[i].p_type = PART_TYPE_NTFS;

        pt->pt_part[i].p_lba_start = b->start;
        pt->pt_part[i].p_lba_end = b->end;

    }

    return 1;
}

ptbl_t ptbl_open(disk_handle_t hdd)
{
    ptbl_t pt;
    int rc;

    pt = RTMemAllocZ(sizeof(*pt));
    if ( NULL == pt ) {
        disklib__set_errno(DISKLIB_ERR_NOMEM);
        return pt;
    }

    pt->pt_hdd = hdd;

    if (pt->pt_hdd.type == DISK_TYPE_VBOX) {

        VDGEOMETRY geom;
        rc = VDGetLCHSGeometry(pt->pt_hdd.u.vboxhandle, 0, &geom);
        if (RT_SUCCESS(rc)) {
            pt->cCylinders = geom.cCylinders;
            pt->cHeads = geom.cHeads;
            pt->cSectors = geom.cSectors;
        } else {
            /* hopefully sane defaults */
            pt->cCylinders = 1024;
            pt->cHeads = 255;
            pt->cSectors = 63;
        }

    } else {
        /* Our VMDK parsing code will have put this in the hdd handle
         * struct directly. */
        pt->cCylinders = 16383;
        pt->cHeads = 16;
        pt->cSectors = 63;
    }

#if 0
    dprintf("GEOM: c/h/s = %"PRIu64"/%"PRIu64"/%"PRIu64"\n",
        pt->cCylinders,
        pt->cHeads,
        pt->cSectors);
#endif

    if (pt->pt_hdd.type == DISK_TYPE_RAW) {
        if (!concoct_pt(pt)) {
            LogAlways(("%s: unable to concoct partition table.\n", __FUNCTION__));
            goto err_free;
        }
    }

    else if ( !read_pt(pt) ) {
        LogAlways(("%s: unable to read partition table.\n", __FUNCTION__));
        goto err_free;
    }

    dprintf("Found %d partitions\n", pt->pt_count);
    disklib__set_errno(DISKLIB_ERR_SUCCESS);
    return pt;
err_free:
    RTMemFree(pt);
    return NULL;
}

void ptbl_del_read_cache(ptbl_t pt)
{
    if ( pt->pt_cache ) {
        cacheFree(pt->pt_cache);
        RTMemFree(pt->pt_cache);
        pt->pt_cache = NULL;
    }
}

int ptbl_add_read_cache(ptbl_t pt)
{
    int use_compression = 1;

    Cache *l0;
    Cache *l1 = NULL;

    l0 = (Cache*) RTMemAllocZ(sizeof(Cache));
    if (l0 == NULL) return 0;

    if (use_compression) {
        l1 = (Cache*) RTMemAllocZ(sizeof(Cache));
        if (l1 == NULL) return 0;

        if (!cacheInit(l1, 15, NULL, 1)) return 0;
    }

    if (!cacheInit(l0, 11, l1, 0)) return 0;
    pt->pt_cache = l0;

    return 1;
}
int ptbl_reduce_read_cache(ptbl_t pt)
{
#if 0
    Cache *l1 = pt->pt_cache->next;

    if (l1 != NULL) {
        cacheFree(l1);
        pt->pt_cache->next = NULL;
    }

#endif
    pt->pt_cache_immutable = 1;
    return 1;
}

void ptbl_enable_cache_bypass(ptbl_t pt)
{
    pt->pt_cache_bypass = 1;
    
}

void ptbl_disable_cache_bypass(ptbl_t pt)
{
    pt->pt_cache_bypass = 0;
}

void ptbl_enable_bulk_fetch(ptbl_t pt)
{
    pt->pt_bulk_fetch = 1;
}

void ptbl_disable_bulk_fetch(ptbl_t pt)
{
    pt->pt_bulk_fetch = 0;
}

int ptbl_set_signature(ptbl_t pt, uint32_t sig)
{
    char buf[SECTOR_SIZE];

    if (!disk_read_sectors(pt->pt_hdd, buf, 0, 1, NULL)) {
        disklib__set_errno(DISKLIB_ERR_IO);
        return 0;
    }

    *(uint32_t *)(buf + MBR_SERIAL_OFFSET) = sig;

    if (!disk_write_sectors(pt->pt_hdd, buf, 0, 1)) {
        disklib__set_errno(DISKLIB_ERR_IO);
        return 0;
    }

    pt->pt_sig = sig;
    return 1;
}

uint32_t ptbl_disk_signature(ptbl_t pt)
{
    return pt->pt_sig;
}

unsigned int ptbl_count_partitions(ptbl_t pt)
{
    return pt->pt_count;
}

partition_t ptbl_get_partition(ptbl_t pt, unsigned int idx)
{
    if ( idx < pt->pt_count )
        return pt->pt_part + idx;
    else
        return NULL;
}

void ptbl_close(ptbl_t pt)
{
    if ( pt ) {
        ptbl_del_read_cache(pt);
        RTMemFree(pt->pt_part);
        RTMemFree(pt);
    }
}

uint8_t part_type(partition_t part)
{
    return part->p_type;
}

uint8_t part_status(partition_t part)
{
    return part->p_status;
}

uint64_t part_num_sectors(partition_t part)
{
    return (part->p_lba_end + 1) - part->p_lba_start;
}

uint64_t part_start_sector(partition_t part)
{
    return part->p_lba_start;
}

uint8_t part_fsync(partition_t part)
{
    ptbl_t pt = part->p_tbl;

    if (pt->pt_hdd.type == DISK_TYPE_VBOX) {
        int rc;
        rc = VDFlush(pt->pt_hdd.u.vboxhandle);
        if (!RT_SUCCESS(rc)) {
            disklib__set_errno(DISKLIB_ERR_IO);
            return 0;
        }
    }

    return 1;
}

ptbl_t part_get_ptbl(partition_t part)
{
    return part->p_tbl;
}

uint64_t part_translate_sector(partition_t part, uint64_t sec)
{
    return sec + part->p_lba_start;
}

#define ALIGNMENT (CACHE_SECTORSIZE/SECTOR_SIZE)

int part_read_sectors(partition_t part, char *buf,
            uint64_t sec, unsigned int num_sec)
{
    ptbl_t pt = part->p_tbl;
    uint64_t start;
    uint64_t last;
    uint64_t i;
    Cache *cache = pt->pt_cache;
    uint8_t *tmp;
    int miss = 0;
    size_t len;


    sec += part->p_lba_start;

    if (cache == NULL) {
        int r = disk_read_sectors(pt->pt_hdd, buf, sec, num_sec, NULL);
        if (!r) {
            LogAlways(("uncached part_read_sectors fails, start=%x num_sec=%x!\n",
                        (uint32_t)sec, num_sec));
        }
        return r;
    }

    start = sec / ALIGNMENT;
    last = (sec+num_sec) / ALIGNMENT;

    len = 1 + last - start;
    tmp = malloc(len * CACHE_SECTORSIZE);

    if (tmp == NULL) {
        LogAlways(("%s: out of memory error at line %d\n", __FUNCTION__, __LINE__));
        return 0;
    }

    for (i = start; i <= last; ++i) {
        if (!cacheCheck(cache, i)) {
            miss = 1;
            break;
        }
    }

    if (miss) {

        uint8_t *t;

        if (!disk_read_sectors(pt->pt_hdd, tmp, ALIGNMENT * start, ALIGNMENT * len, NULL)) {
            LogAlways(("part_read_sectors fails, start=%"PRIx64" num_sec=%"PRIxS"!\n", start, len));
            disklib__set_errno(DISKLIB_ERR_IO);
            free(tmp);
            return 0;
        }

        for (i = start, t = tmp; i <= last; ++i) {

            if (!pt->pt_cache_bypass && !pt->pt_cache_immutable) {
                cacheStore(cache, i, t);
            }

            size_t modulo = sec % ALIGNMENT;
            size_t take = (ALIGNMENT - modulo < num_sec) ? ALIGNMENT - modulo : num_sec;

            memcpy(buf, t + SECTOR_SIZE * modulo, SECTOR_SIZE * take);
            sec += take;
            buf += SECTOR_SIZE * take;
            num_sec -= take;

            t += CACHE_SECTORSIZE;
        }

    } else {

        for (i = start; i <= last; ++i) {

            if (cacheLookup(cache, i, tmp)) {
                size_t modulo = sec % ALIGNMENT;
                size_t take = (ALIGNMENT - modulo < num_sec) ? ALIGNMENT - modulo : num_sec;

                memcpy(buf, tmp + SECTOR_SIZE * modulo, SECTOR_SIZE * take);
                sec += take;
                buf += SECTOR_SIZE * take;
                num_sec -= take;

            } else printf("WTF?\n");
        }
    }

    free(tmp);
    disklib__set_errno(DISKLIB_ERR_SUCCESS);
    return 1;
}

int part_write_sectors(partition_t part, const char *buf,
            uint64_t sec, unsigned int num_sec)
{
    ptbl_t pt = part->p_tbl;
    uint64_t ofs;

    ofs = (sec + part->p_lba_start);
    Assert(ofs + num_sec < part->p_lba_end);

    if (!disk_write_sectors(pt->pt_hdd, buf, ofs, num_sec)) {
        LogAlways(("part_write_sectors failed\n"));
        /* invalidate any cached sectors to force a re-read next time */
        //do_cache_drop(pt, buf, ofs, num_sec);
        disklib__set_errno(DISKLIB_ERR_IO);
        return 0;
    }

    //do_cache_update(pt, buf, ofs, num_sec);
    //do_cache_drop(pt, buf, ofs, num_sec);

    disklib__set_errno(DISKLIB_ERR_SUCCESS);
    return 1;
}

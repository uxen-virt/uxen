/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <err.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

#include "libimg.h"

struct gpt_header
{
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_crc32;
    uint32_t reserved1;
    uint64_t header_lba;
    uint64_t alt_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t  disk_guid[16];
    uint64_t partition_entry_lba;
    uint32_t nb_partition_entries;
    uint32_t partition_entry_size;
    uint32_t partition_entry_crc32;
};

struct gpt_partition_entry
{
    uint8_t  type_guid[16];
    uint8_t  partition_guid[16];
    uint64_t start_lba;
    uint64_t end_lba;
    uint64_t attributes;
    uint8_t  name[72];
};

#define GUID_FMT "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"
#define GUID_ARG(x) (x)[3], (x)[2], (x)[1], (x)[0], \
                    (x)[5], (x)[4], \
                    (x)[7], (x)[6], \
                    (x)[9], (x)[8], \
                    (x)[10], (x)[11], (x)[12], (x)[13], (x)[14], (x)[15]

//static const uint8_t UNUSED_PARTITION_GUID[16] = { 0 };
static const uint8_t APPLE_PARTITION_GUID[16] = {
    0x00, 0x53, 0x46, 0x48, 0x00, 0x00, 0xaa, 0x11,
    0xaa, 0x11, 0x00, 0x30, 0x65, 0x43, 0xec, 0xac
};

#define NSECTORS(length) (((length) + (BDRV_SECTOR_SIZE - 1)) >> BDRV_SECTOR_BITS)

static void
usage(const char *progname)
{
    fprintf(stderr, "usage: %s <protocol>:<image> <stage0> <stage1>\n",
            progname);
    exit(-1);
}

static void *
load_file(const char *path, size_t *len)
{
    int fd;
    int rc;
    struct stat st;
    char *buf;
    size_t l;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    rc = fstat(fd, &st);
    if (rc == -1) {
        fprintf(stderr, "Failed to stat %s: %s\n", path, strerror(errno));
        close(fd);
        return NULL;
    }

    buf = malloc(st.st_size);
    if (!buf) {
        fprintf(stderr, "Allocation failed: %s\n", strerror(errno));
        close(fd);
        return NULL;
    }

    l = 0;
    while (l < st.st_size) {
        rc = read(fd, buf + l, st.st_size - l);
        if (rc < 0) {
            fprintf(stderr, "read error: %s\n", strerror(errno));
            close(fd);
            free(buf);
            return NULL;
        }
        if (rc == 0)
            break;
        l += rc;
    }

    if (len)
        *len = l;

    close(fd);
    return buf;
}

static void *
load_sectors(BlockDriverState *bs, uint64_t lba, size_t nsects)
{
    void *buf;
    int rc;

    buf = calloc(nsects, BDRV_SECTOR_SIZE);
    if (!buf)
        return NULL;

    rc = bdrv_read(bs, lba, buf, nsects);
    if (rc < 0) {
        fprintf(stderr, "Failed to read lba=%llu sectors=%zd. rc=%d\n", lba, nsects, rc);
        free(buf);
        return NULL;
    }

    return buf;
}

static int
patch_sectors(BlockDriverState *bs, uint64_t lba, void *data,
              size_t offset, size_t len)
{
    void *buf;
    size_t nsects = NSECTORS(offset + len);
    int rc;

    buf = load_sectors(bs, lba, nsects);
    if (!buf)
        return -1;

    memcpy(buf + offset, data, len);

    rc = bdrv_write(bs, lba, buf, nsects);
    if (rc < 0) {
        fprintf(stderr, "Failed to write %zd sectors at lba=%llu. rc=%d\n",
                nsects, lba, rc);
        return -1;
    }

    free(buf);
    return 0;
}


static int
gpt_check(void *header)
{
    struct gpt_header *hdr = header;

    if (hdr->signature != 0x5452415020494645ULL) { /* "EFI PART" */
        fprintf(stderr, "Wrong GPT header signature: %16llx\n", hdr->signature);
        return -1;
    }

    fprintf(stderr, "Found GPT Header for disk GUID="GUID_FMT"\n", GUID_ARG(hdr->disk_guid));

    return 0;
}

static struct gpt_partition_entry *
gpt_partitions(BlockDriverState *bs, void *header, size_t *nentries)
{
    struct gpt_header *hdr = header;
    size_t nsects;

    assert(hdr->partition_entry_size == sizeof (struct gpt_partition_entry));

    nsects = NSECTORS(hdr->nb_partition_entries * hdr->partition_entry_size);

    if (nentries)
        *nentries = hdr->nb_partition_entries;

    return load_sectors(bs, hdr->partition_entry_lba,
                        NSECTORS(hdr->nb_partition_entries *
                                 hdr->partition_entry_size));
}

static int
gpt_partition_lookup_type(struct gpt_partition_entry *partitions,
                          size_t nents,
                          struct gpt_partition_entry **entry,
                          const uint8_t *type_guid)
{
    struct gpt_partition_entry *cur;
    struct gpt_partition_entry *end = partitions + nents;

    if (*entry)
        cur = *entry + 1;
    else
        cur = partitions;

    while (cur < end) {
        if (!memcmp(cur->type_guid, type_guid, 16)) {
            *entry = cur;
            return cur - partitions;
        }
        cur++;
    }

    return -1;
}

int main(int argc, char **argv)
{
    BlockDriverState *bs;
    const char *img;
    void *boot0;
    size_t boot0_len;
    void *boot1;
    size_t boot1_len;
    int rc;
    void *gpt_hdr;
    void *gpt_parts;
    size_t gpt_nents;
    struct gpt_partition_entry *hfs_partition = NULL;

    rc = -1;

    if (argc != 4)
        usage(argv[0]);
    img = argv[1];
    boot0 = load_file(argv[2], &boot0_len);
    if (!boot0)
        goto fail_boot0;
    boot1 = load_file(argv[3], &boot1_len);
    if (!boot1)
        goto fail_boot1;
    if (boot0_len < 440) {
        fprintf(stderr, "boot0 needs to be at least 440 bytes\n");
        goto fail_boot1;
    }

    bh_init();
    bdrv_init();

    if (!(bs = bdrv_new(""))) {
        fprintf(stderr, "unable to allocate block backend\n");
        goto fail_bs;
    }

    if (bdrv_open(bs, img, BDRV_O_RDWR) < 0) {
        fprintf(stderr, "unable to open %s\n", img);
        goto fail_img;
    }

    gpt_hdr = load_sectors(bs, 1, 1);
    if (!gpt_hdr) {
        fprintf(stderr, "Failed to read GPT header\n");
        goto fail_img;
    }
    if (gpt_check(gpt_hdr)) {
        fprintf(stderr, "GPT checks failed\n");
        free(gpt_hdr);
        goto fail_img;
    }

    gpt_parts = gpt_partitions(bs, gpt_hdr, &gpt_nents);
    free(gpt_hdr);
    if (!gpt_parts) {
        fprintf(stderr, "Failed to read GPT partition entries\n");
        goto fail_img;
    }

    rc = gpt_partition_lookup_type(gpt_parts, gpt_nents, &hfs_partition,
                                   APPLE_PARTITION_GUID);
    if (rc < 0) {
        fprintf(stderr, "Could not find Apple partition in GPT\n");
        goto fail_part;
    }

    fprintf(stderr, "Found Apple partition at index %d GUID="GUID_FMT"\n",
                     rc, GUID_ARG(hfs_partition->partition_guid));


    fprintf(stderr, "Writing boot0 at sector 0...\n");
    rc = patch_sectors(bs, 0, boot0, 0, 440);
    if (rc < 0) {
        fprintf(stderr, "Failed to patch MBR\n");
        goto fail_patch;
    }
    fprintf(stderr, "Writing boot1 at sector %llu...\n", hfs_partition->start_lba);
    rc = patch_sectors(bs, hfs_partition->start_lba, boot1, 0, boot1_len);
    if (rc < 0) {
        fprintf(stderr, "Failed to patch PBR. rc=%d\n", rc);
        goto fail_patch;
    }

    rc = 0;

fail_patch:
    bdrv_flush(bs);
fail_part:
    free(gpt_parts);
fail_img:
    bdrv_delete(bs);
fail_bs:
    free(boot1);
fail_boot1:
    free(boot0);
fail_boot0:

    return rc;
}

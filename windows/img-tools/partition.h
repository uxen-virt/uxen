/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#ifndef _DISKLIB_PARTITION_H
#define _DISKLIB_PARTITION_H

#ifdef __cplusplus
extern "C" {
#endif

#define SECTOR_SIZE               512ULL

#define PART_TYPE_EMPTY           0x0
#define PART_TYPE_FAT12           0x1
#define PART_TYPE_FAT16           0x4
#define PART_TYPE_EXTENDED        0x5
#define PART_TYPE_FAT16_LARGE     0x6
#define PART_TYPE_NTFS            0x7
#define PART_TYPE_FAT32           0xc
#define PART_TYPE_FAT32_LBA       0xd
#define PART_TYPE_FAT16_LBA       0xe
#define PART_TYPE_EXTENDED_LBA    0xf
#define PART_TYPE_NTFS_HIDDEN     0x17
#define PART_TYPE_NTFS_RE         0x27

typedef struct _ptbl *ptbl_t;
typedef struct _partition *partition_t;

struct disk_handle;

ptbl_t ptbl_open(struct _disk_handle hdd);
uint32_t ptbl_disk_signature(ptbl_t pt);
unsigned int ptbl_count_partitions(ptbl_t pt);
partition_t ptbl_get_partition(ptbl_t pt, unsigned int idx);
int ptbl_set_signature(ptbl_t pt, uint32_t sig);
void ptbl_enable_cache_bypass(ptbl_t pt);
void ptbl_disable_cache_bypass(ptbl_t pt);
void ptbl_enable_bulk_fetch(ptbl_t pt);
void ptbl_disable_bulk_fetch(ptbl_t pt);
void ptbl_close(ptbl_t pt);

ptbl_t part_get_ptbl(partition_t part);
uint8_t part_type(partition_t part);
uint8_t part_status(partition_t part);
uint8_t part_fsync(partition_t part);
uint64_t part_num_sectors(partition_t part);
uint64_t part_start_sector(partition_t part);
uint64_t part_translate_sector(partition_t part, uint64_t sec);
int part_read_sectors(partition_t part, char *buf,
                      uint64_t sec, unsigned int num_sec);
int part_write_sectors(partition_t part, const char *buf,
                       uint64_t sec, unsigned int num_sec);

int ptbl_add_read_cache(ptbl_t pt);
int ptbl_reduce_read_cache(ptbl_t pt);
void ptbl_del_read_cache(ptbl_t pt);

#ifdef __cplusplus
}
#endif

#endif /* _DISKLIB_PARTITION_H */

/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#ifndef _DISK_TOOL_NTDEV_H
#define _DISK_TOOL_NTDEV_H

extern struct ntfs_device_operations part_io_ops;

/* ntfs-extras.c */
struct REPARSE_INDEX {            /* index entry in $Extend/$Reparse */
    INDEX_ENTRY_HEADER header;
    REPARSE_INDEX_KEY key;
    le32 filling;
};

#define IO_REPARSE_TAG_DFS         const_cpu_to_le32(0x8000000A)
#define IO_REPARSE_TAG_DFSR        const_cpu_to_le32(0x80000012)
#define IO_REPARSE_TAG_HSM         const_cpu_to_le32(0xC0000004)
#define IO_REPARSE_TAG_HSM2        const_cpu_to_le32(0x80000006)
#define IO_REPARSE_TAG_MOUNT_POINT const_cpu_to_le32(0xA0000003)
#define IO_REPARSE_TAG_SIS         const_cpu_to_le32(0x80000007)
#define IO_REPARSE_TAG_SYMLINK     const_cpu_to_le32(0xA000000C)

struct MOUNT_POINT_REPARSE_DATA {      /* reparse data for junctions */
    le16    subst_name_offset;
    le16    subst_name_length;
    le16    print_name_offset;
    le16    print_name_length;
    char    path_buffer[0];      /* above data assume this is char array */
} ;

struct SYMLINK_REPARSE_DATA {          /* reparse data for symlinks */
    le16    subst_name_offset;
    le16    subst_name_length;
    le16    print_name_offset;
    le16    print_name_length;
    le32    flags;             /* 1 for full target, otherwise 0 */
    char    path_buffer[0];      /* above data assume this is char array */
} ;

int ntfsx_set_reparse_data(ntfs_inode *ni, const char *value,
                           size_t size, int addnew);
int ntfsx_is_hole(ntfs_attr *na, s64 cnum);
int ntfsx_is_special_file(ntfs_inode *ni);
int ntfsx_link(ntfs_inode *ni, ntfs_inode *dir_ni, ntfschar *name, u8 name_len);

#endif /* _DISK_TOOL_NTDEV_H */

/*
 * Copyright 2011-2016, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#ifndef _DISKLIB_H
#define _DISKLIB_H

#include "vbox-compat.h"
#include "compat.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _disk_handle {
    PVBOXHDD vboxhandle;
} disk_handle_t;

#define DISKLIB_EXTENT_HOLE     (~0ULL)
struct disklib_extent {
    uint64_t off; /* offset in bytes */
    uint64_t len; /* number of bytes */
};

typedef struct {
  uint64_t creationTime;
  uint64_t lastAccessTime;
  uint64_t lastWriteTime;
  uint64_t changeTime;
  uint32_t attributes;
} SimpleAttributes;

struct disklib_stat {
    uint64_t f_ino;

    uint64_t f_size;

/* file mode flags */
#define DISKLIB_ISDIR           (1<<0)  /* directory */
#define DISKLIB_ISREPARSE       (1<<1)  /* reparse point */
#define DISKLIB_ISLNK           (1<<2)  /* jct or symlink (readlink works) */
#define DISKLIB_ISSPECIAL       (1<<3)  /* is special file */
#define DISKLIB_ISCMP           (1<<4)  /* is compressed */
    uint8_t f_mode;

/* attribute mode flags, only available if queried object is an attribute */
#define DISKLIB_ISATTR          (1<<0)  /* these flags are set? */
#define DISKLIB_ISRESIDENT      (1<<1)  /* resident (extents won't work) */
#define DISKLIB_ISSPARSE        (1<<1)  /* sparse file */
    uint8_t a_mode;

    SimpleAttributes attribs;
};

#define DISKLIB_LINK_SYMBOLIC   1
#define DISKLIB_LINK_SYM_FULL   2
#define DISKLIB_LINK_JUNCTION   3

typedef struct _disklib_fs *disklib_fs_t;
typedef struct _disklib_fd *disklib_fd_t;

#define DISKLIB_FD_READ             (1<<0)
#define DISKLIB_FD_WRITE            (1<<1)
#define DISKLIB_FD_RW               (DISKLIB_FD_READ|DISKLIB_FD_WRITE)
#define DISKLIB_FD_CREAT            (1<<2)
#define DISKLIB_FD_TRUNC            (1<<3)

#define DISKLIB_NAME_DOS            (1<<0)
#define DISKLIB_NAME_WIN32          (1<<1)
#define DISKLIB_NAME_DOS_AND_WIN32  (DISKLIB_NAME_DOS|DISKLIB_NAME_WIN32)
#define DISKLIB_NAME_ALL            (1<<2)
#define DISKLIB_SYMLINK_NOFOLLOW    (1<<3)

/* errors */
#define DISKLIB_ERR_SUCCESS         0
#define DISKLIB_ERR_GENERAL         1
#define DISKLIB_ERR_BAD_CHARS       2

/* lowlevel errors */
#define DISKLIB_ERR_NOMEM           10
#define DISKLIB_ERR_IO              11
#define DISKLIB_ERR_ROFS            12

/* mount errors */
#define DISKLIB_ERR_BAD_MAGIC       20
#define DISKLIB_ERR_CORRUPT         21
#define DISKLIB_ERR_HIBERNATED      22
#define DISKLIB_ERR_UNCLEAN         23
#define DISKLIB_ERR_BUSY            24
#define DISKLIB_ERR_NO_PRIVILEGE    25

/* usual errors in course of operation */
#define DISKLIB_ERR_INVAL           30
#define DISKLIB_ERR_EXIST           31
#define DISKLIB_ERR_NOENT           32
#define DISKLIB_ERR_ISDIR           33
#define DISKLIB_ERR_ACCES           34
#define DISKLIB_ERR_NOTEMPTY        35
#define DISKLIB_ERR_NOTDIR          36
#define DISKLIB_ERR_IS_SPECIAL      37
#define DISKLIB_ERR_NOSPC           38
#define DISKLIB_ERR_ISLNK           39

/* partition table errors */
#define DISKLIB_ERR_BAD_PART_SIG    50
#define DISKLIB_ERR_BAD_PART_TBL    51

/* VSS logical file access wrappers. */
int use_vss_logical_reads(void);
void set_vss_path(const wchar_t *vss_path);
void *open_vss_logical_file(const char *path, int overlapped);
int read_vss_logical_file(void *handle, void *buffer, size_t size, void *o);
void close_vss_logical_file(void *handle);
int vss_check_result(void *file, void *o);

int disklib_truncate(disklib_fd_t fd, uint64_t sz);
int disklib_seek_set(disklib_fd_t fd, uint64_t ofs);
ssize_t disklib_read(disklib_fd_t fd, void *buf, size_t len);
ssize_t disklib_write(disklib_fd_t fd, const void *buf, size_t len);
uint64_t disklib_filesize(disklib_fd_t fd);
void disklib_close(disklib_fd_t fd);
int disk_read_check_result(disk_handle_t dh, void *_o);

void disk_error_context0(const char *function, int line, const char *context_string);
#define disk_error_context(__s) do{ disk_error_context0(__FUNCTION__,__LINE__,__s); }while(0)

void disk_flag_io_error0(const char *function, int line);

#define disk_flag_io_error() do{disk_flag_io_error0(__FUNCTION__, __LINE__);}while(0)

/* retreiving error conditions */
int disklib_errno(void);
void disklib__set_errno(int e);
const char *disklib_strerror(int e);

/* files must be freed with RTMemFree(), returns zero on error */
/* side-effects: path becomes null separated */
int disklib_parse_vdpath(char *path, char ***files, size_t *count);

int disklib_open_image(char *path, int rw, disk_handle_t *hdd);
void disklib_close_image(disk_handle_t hdd);
void disklib_set_slow_flush(disk_handle_t dh);

void set_current_filename(const char *fn, uint64_t file_offset, uint64_t file_id);
void flush_map_to_file(void *f);

int disk_read_sectors(disk_handle_t dh, void *buf, uint64_t sec, unsigned int
        num_sec, void *context);

void fill_with_magic_bytes(char* sector);
int disk_write_sectors(disk_handle_t dh, const void *buf, uint64_t sec, unsigned int num_sec);

uint64_t disk_get_size(disk_handle_t dh);

char *utf8(const wchar_t* ws);
wchar_t *wide(const char* s);

/* handy for debugging... */
void hex_dump(const uint8_t *tmp, size_t len, size_t llen, int depth);

/* registry */

struct reg_key_info {
    size_t ki_max_subkey_len;
    size_t ki_max_value_name_len;
    size_t ki_max_value_len;
    unsigned int ki_subkeys;
    unsigned int ki_values;
};

#ifdef __cplusplus
}
#endif

#endif /* _DISKLIB_H */

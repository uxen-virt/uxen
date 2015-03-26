/*
 * Copyright (c) 2008-2009 Jean-Pierre Andre
 * possibly other ntfs-3g authors.
 *
 * Parts of libntfs either internal or not available in windows port.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/param.h>
#include <sys/time.h>
#include <ntfs-3g/compat.h>
#include <ntfs-3g/device.h>
#include <ntfs-3g/dir.h>
#include <ntfs-3g/attrib.h>

#include <sys/stat.h>

#include "disklib.h"
#include "partition.h"
#include "fs-ntfs.h"
#include "disklib-internal.h"

#include "ntdev.h"

int ntfsx_is_special_file(ntfs_inode *ni)
{
    return (ni->mft_no < FILE_first_user);
}

static int set_reparse_index(ntfs_inode *ni, ntfs_index_context *xr,
            le32 reparse_tag)
{
    struct REPARSE_INDEX indx;
    u64 file_id_cpu;
    le64 file_id;
    le16 seqn;

    seqn = ni->mrec->sequence_number;
    file_id_cpu = MK_MREF(ni->mft_no,le16_to_cpu(seqn));
    file_id = cpu_to_le64(file_id_cpu);
    indx.header.data_offset = const_cpu_to_le16(
                    sizeof(INDEX_ENTRY_HEADER)
                    + sizeof(REPARSE_INDEX_KEY));
    indx.header.data_length = const_cpu_to_le16(0);
    indx.header.reservedV = const_cpu_to_le32(0);
    indx.header.length = const_cpu_to_le16(
                    sizeof(struct REPARSE_INDEX));
    indx.header.key_length = const_cpu_to_le16(
                    sizeof(REPARSE_INDEX_KEY));
    indx.header.flags = const_cpu_to_le16(0);
    indx.header.reserved = const_cpu_to_le16(0);
    indx.key.reparse_tag = reparse_tag;
        /* danger on processors which require proper alignment ! */
    memcpy(&indx.key.file_id, &file_id, 8);
    indx.filling = const_cpu_to_le32(0);
    ntfs_index_ctx_reinit(xr);
    return (ntfs_ie_add(xr,(INDEX_ENTRY*)&indx));
}

static int remove_reparse_index(ntfs_attr *na, ntfs_index_context *xr,
                le32 *preparse_tag)
{
    REPARSE_INDEX_KEY key;
    u64 file_id_cpu;
    le64 file_id;
    s64 size;
    le16 seqn;
    int ret;

    ret = na->data_size;
    if (ret) {
            /* read the existing reparse_tag */
        size = ntfs_attr_pread(na, 0, 4, preparse_tag);
        if (size == 4) {
            seqn = na->ni->mrec->sequence_number;
            file_id_cpu = MK_MREF(na->ni->mft_no,le16_to_cpu(seqn));
            file_id = cpu_to_le64(file_id_cpu);
            key.reparse_tag = *preparse_tag;
        /* danger on processors which require proper alignment ! */
            memcpy(&key.file_id, &file_id, 8);
            if (!ntfs_index_lookup(&key, sizeof(REPARSE_INDEX_KEY), xr)
                && ntfs_index_rm(xr))
                ret = -1;
        } else {
            ret = -1;
            errno = EIO;
        }
    }
    return (ret);
}

static int update_reparse_data(ntfs_inode *ni, ntfs_index_context *xr,
            const char *value, size_t size)
{
    int res;
    int written;
    int oldsize;
    ntfs_attr *na;
    le32 reparse_tag;

    res = 0;
    na = ntfs_attr_open(ni, AT_REPARSE_POINT, AT_UNNAMED, 0);
    if (na) {
            /* remove the existing reparse data */
        oldsize = remove_reparse_index(na,xr,&reparse_tag);
        if (oldsize < 0)
            res = -1;
        else {
            /* resize attribute */
            res = ntfs_attr_truncate(na, (s64)size);
            /* overwrite value if any */
            if (!res && value) {
                written = (int)ntfs_attr_pwrite(na,
                         (s64)0, (s64)size, value);
                if (written != (s64)size) {
                    ntfs_log_error("Failed to update "
                        "reparse data\n");
                    ntfs_set_errno(EIO);
                    res = -1;
                }
            }
            if (!res
                && set_reparse_index(ni,xr,
                ((const REPARSE_POINT*)value)->reparse_tag)
                && (oldsize > 0)) {
                /*
                 * If cannot index, try to remove the reparse
                 * data and log the error. There will be an
                 * inconsistency if removal fails.
                 */
                ntfs_attr_rm(na);
                ntfs_log_error("Failed to index reparse data."
                        " Possible corruption.\n");
            }
        }
        ntfs_attr_close(na);
        NInoSetDirty(ni);
    } else
        res = -1;
    return (res);
}

static ntfschar reparse_index_name[] = { const_cpu_to_le16('$'),
                     const_cpu_to_le16('R') };
static ntfs_index_context *open_reparse_index(ntfs_volume *vol)
{
    u64 inum;
    ntfs_inode *ni;
    ntfs_inode *dir_ni;
    ntfs_index_context *xr;

        /* do not use path_name_to inode - could reopen root */
    dir_ni = ntfs_inode_open(vol, FILE_Extend);
    ni = (ntfs_inode*)NULL;
    if (dir_ni) {
        inum = ntfs_inode_lookup_by_mbsname(dir_ni,"$Reparse");
        if (inum != (u64)-1)
            ni = ntfs_inode_open(vol, inum);
        ntfs_inode_close(dir_ni);
    }
    if (ni) {
        xr = ntfs_index_ctx_get(ni, reparse_index_name, 2);
        if (!xr) {
            ntfs_inode_close(ni);
        }
    } else
        xr = (ntfs_index_context*)NULL;
    return (xr);
}

static BOOL valid_reparse_data(ntfs_inode *ni,
            const REPARSE_POINT *reparse_attr, size_t size)
{
    BOOL ok;
    unsigned int offs;
    unsigned int lth;
    const struct MOUNT_POINT_REPARSE_DATA *mount_point_data;
    const struct SYMLINK_REPARSE_DATA *symlink_data;

    ok = ni && reparse_attr
        && (size >= sizeof(REPARSE_POINT))
        && (((size_t)le16_to_cpu(reparse_attr->reparse_data_length)
                 + sizeof(REPARSE_POINT)) == size);
    if (ok) {
        switch (reparse_attr->reparse_tag) {
        case IO_REPARSE_TAG_MOUNT_POINT :
            mount_point_data = (const struct MOUNT_POINT_REPARSE_DATA*)
                        reparse_attr->reparse_data;
            offs = le16_to_cpu(mount_point_data->subst_name_offset);
            lth = le16_to_cpu(mount_point_data->subst_name_length);
                /* consistency checks */
            if (!(ni->mrec->flags & MFT_RECORD_IS_DIRECTORY)
                || ((size_t)((sizeof(REPARSE_POINT)
                 + sizeof(struct MOUNT_POINT_REPARSE_DATA)
                 + offs + lth)) > size))
                ok = FALSE;
            break;
        case IO_REPARSE_TAG_SYMLINK :
            symlink_data = (const struct SYMLINK_REPARSE_DATA*)
                        reparse_attr->reparse_data;
            offs = le16_to_cpu(symlink_data->subst_name_offset);
            lth = le16_to_cpu(symlink_data->subst_name_length);
            if ((size_t)((sizeof(REPARSE_POINT)
                 + sizeof(struct SYMLINK_REPARSE_DATA)
                 + offs + lth)) > size)
                ok = FALSE;
            break;
        default :
            break;
        }
    }
    if (!ok)
        errno = EINVAL;
    return (ok);
}

/* set or update NTFS reparse data */
int ntfsx_set_reparse_data(ntfs_inode *ni, const char *value,
                           size_t size, int addnew)
{
    int res;
    u8 dummy;
    ntfs_inode *xrni;
    ntfs_index_context *xr;

    res = 0;
    if (ni && valid_reparse_data(ni, (const REPARSE_POINT*)value, size)) {
        xr = open_reparse_index(ni->vol);
        if (xr) {
            if (!ntfs_attr_exist(ni,AT_REPARSE_POINT,
                        AT_UNNAMED,0)) {
                /*
                 * no reparse data attribute : add one,
                 * apparently, this does not feed the new value in
                 * Note : NTFS version must be >= 3
                 */
                if ( addnew ) {
                    if (ni->vol->major_ver >= 3) {
                        res = ntfs_attr_add(ni,
                            AT_REPARSE_POINT,
                            AT_UNNAMED,0,&dummy,
                            (s64)0);
                        if (!res) {
                            ni->flags |= FILE_ATTR_REPARSE_POINT;
                            NInoFileNameSetDirty(ni);
                        }
                        NInoSetDirty(ni);
                    } else {
                        ntfs_set_errno(EINVAL);
                        res = -1;
                    }
                } else {
                    ntfs_set_errno(EIO);
                    res = -1;
                }
            }
            if (!res) {
                    /* update value and index */
                res = update_reparse_data(ni,xr,value,size);
            }
            xrni = xr->ni;
            ntfs_index_entry_mark_dirty(xr);
            NInoSetDirty(xrni);
            ntfs_index_ctx_put(xr);
            ntfs_inode_close(xrni);
        } else {
            res = -1;
        }
    } else {
        ntfs_set_errno(EINVAL);
        res = -1;
    }
    return (res ? -1 : 0);
}

int ntfsx_is_hole(ntfs_attr *na, s64 cnum)
{
    runlist_element *rl;

    if ( !NAttrNonResident(na) || (na->data_flags & ATTR_COMPRESSION_MASK) )
        return 0;

    rl = ntfs_attr_find_vcn(na, cnum);
    if ( rl->lcn == LCN_RL_NOT_MAPPED) {
        rl = ntfs_attr_find_vcn(na, rl->vcn);
        if ( NULL == rl ) {
            return 0;
        }
    }

    if ( rl->length == 0 ) {
        return 0;
    }

    if ( rl->lcn < (LCN)0 ) {
        if ( rl->lcn != (LCN)LCN_HOLE )
            return 0;

        return 1;
    }

    return 0;
}

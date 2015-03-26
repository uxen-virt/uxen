//
//  copy-on-write-shared.h
//  copy-on-write
//
/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Phil Dennis-Jordan <phil@philjordan.eu>
 * SPDX-License-Identifier: ISC
 */

#ifndef Bromium_Copy_On_Write_shared_h
#define Bromium_Copy_On_Write_shared_h

#include <stdint.h>
#include <sys/param.h>

/// Available values for "option" argument to setsockopt/getsockopt
enum copy_on_write_ctl_opts {
    COW_CTL_CopyTargetPath,     // get/set path to directory
    COW_CTL_CNIDWatchList,      // get/set array of uint64_t with inodes/cnids
    COW_CTL_StartReceivingFileEvents,   // "setter" only
    COW_CTL_StopReceivingFileEvents,    // "setter" only
    COW_CTL_WatchedLinkRequest  // getter: wait for file that needs relinking, setter: notify kernel of successful relink
};

enum copy_on_write_msg_type {
    COW_MSG_FileReLinked,
    COW_MSG_FileCopied,
    COW_MSG_FileCopyFailed
};

/// Kernel -> User file operation notification (send through control socket)
struct copy_on_write_msg {
    uint16_t msg_type;          // enum copy_on_write_msg_type
    uint16_t reserved;
    uint32_t dropped_messages;
    uint64_t file_id;
};

typedef struct copy_on_write_file_id {
    uint64_t cnid : 32;         // pretty safe; HFS+ has 32-bit inodes
    uint32_t id : 24;           // we usually have around ~200k files
    uint32_t state : 2;         // only used by kernel module
} copy_on_write_file_id_t;

/* Returned by COW_CTL_WatchedLinkEvent getter, identifies a file to be hardlinked
 * to the target directory. If file_id is 0 and file_path[0] is '\0', the kext
 * is shutting down, worker should disconnect. */
struct copy_on_write_link_request {
    uint64_t file_id;
    char file_path[MAXPATHLEN];
};
typedef struct copy_on_write_link_request copy_on_write_link_request_t;

/* Supplied by a hardlink worker via the COW_CTL_WatchedLinkEvent after responding
 * to a hardlink request. */
struct copy_on_write_link_response {
    uint64_t file_id;
    uint64_t flags;             // 0 = success, 1 = failed
};
typedef struct copy_on_write_link_response copy_on_write_link_response_t;

#define BR_COPY_ON_WRITE_KCONTROL_SOCKET_NAME "com.bromium.copy-on-write"

#endif

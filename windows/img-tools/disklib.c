/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disklib.h"

static int my_errno;

void disklib__set_errno(int e)
{
    my_errno = e;
}

int disklib_errno(void)
{
    return my_errno;
}

const char *disklib_strerror(int e)
{
    switch(e) {
    case DISKLIB_ERR_SUCCESS:
        return "Success";
    case DISKLIB_ERR_GENERAL:
        return "Unspecified failure";
    case DISKLIB_ERR_NOMEM:
        return "Out of memory";
    case DISKLIB_ERR_BAD_CHARS:
        return "Invalid character encoding";
    case DISKLIB_ERR_IO:
        return "I/O Error";
    case DISKLIB_ERR_ROFS:
        return "Read-only filesystem";
    case DISKLIB_ERR_BAD_MAGIC:
        return "Not a valid filesystem";
    case DISKLIB_ERR_CORRUPT:
        return "Corrupt filesystem";
    case DISKLIB_ERR_HIBERNATED:
        return "Filesystem hibernated";
    case DISKLIB_ERR_UNCLEAN:
        return "Filesystem was not cleanly shut down";
    case DISKLIB_ERR_BUSY:
        return "Filesystem busy";
    case DISKLIB_ERR_NO_PRIVILEGE:
        return "No permission to access filesystem media";
    case DISKLIB_ERR_INVAL:
        return "Invalid parameter";
    case DISKLIB_ERR_EXIST:
        return "Name already exists";
    case DISKLIB_ERR_NOENT:
        return "File not found";
    case DISKLIB_ERR_ISDIR:
        return "Is a directory";
    case DISKLIB_ERR_ACCES:
        return "File opened read-only";
    case DISKLIB_ERR_NOTEMPTY:
        return "Directory not empty";
    case DISKLIB_ERR_NOTDIR:
        return "Not a directory";
    case DISKLIB_ERR_IS_SPECIAL:
        return "Is a special file";
    case DISKLIB_ERR_NOSPC:
        return "No space left on device";
    case DISKLIB_ERR_ISLNK:
        return "Is a symbolic link";
    case DISKLIB_ERR_BAD_PART_SIG:
        return "Missing signature on partition table";
    case DISKLIB_ERR_BAD_PART_TBL:
        return "Corrupt partition table";
    default:
        break;
    }
    return "disklib error";
}

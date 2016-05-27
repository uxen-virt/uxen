/*
 * Copyright 2011-2016, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */

#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disklib.h"
#include "partition.h"
#include "fs-ntfs.h"

#if defined(_WIN32)
DECLARE_PROGNAME;
#endif	/* _WIN32 */

static int enum_partitions(char *fn)
{
    uint8_t type, status;
    unsigned int cnt, i;
    disk_handle_t hdd;
    partition_t part;
    ptbl_t ptbl;

    if (!disklib_open_image(fn, 1, &hdd)) {
        return 0;
    }
    
    ptbl = ptbl_open(hdd);
    if ( NULL == ptbl )
        return 0;

    cnt = ptbl_count_partitions(ptbl);
    for(i = 0; i < cnt; i++) {
        part = ptbl_get_partition(ptbl, i);
        type = part_type(part);
        status = part_status(part);

        if ( !disklib_ntfs_partition(type) )
            continue;

        RTPrintf("p%u: %sNTFS partition\n", i,
            (status == 0x80) ? "bootable " : "");

        disklib_ntfsfix(part);
    }

    ptbl_close(ptbl);
    disklib_close_image(hdd);
    return 1;
}

int main(int argc, char **argv)
{
    char *vdfile;

    early_init();

    setprogname(argv[0]);

    RTR3Init();
    RTPrintf("*** NTFS FIX: schedules chkdisk for next boot ***\n");

    if ( argc < 2 ) {
        RTPrintf("Usage: ntfsfix <path-to-vmdk>\n");
        return EXIT_FAILURE;
    }

    vdfile = argv[1];

    if ( !enum_partitions(vdfile) )
        return EXIT_FAILURE;

    VDShutdown();
    return EXIT_SUCCESS;
}

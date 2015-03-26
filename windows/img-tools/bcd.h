/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 */
#ifndef _DISKLIB_BCD_H
#define _DISKLIB_BCD_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _bcd *bcd_t;
typedef struct _bootmgr *bootmgr_t;

/* boot configuration database */
bcd_t bcd_open(rhkey_t key);
bootmgr_t bcd_bootmgr_get_default(bcd_t bcd);
void bcd_close(bcd_t bcd);

/* boot manager objects */
const char *bootmgr_description(bootmgr_t bmgr);
const char *bootmgr_sysroot(bootmgr_t bmgr);
const char *bootmgr_app_path(bootmgr_t bmgr);
const uint8_t *bootmgr_os_device(bootmgr_t bmgr, size_t *sz);
const uint8_t *bootmgr_app_device(bootmgr_t bmgr, size_t *sz);
bootmgr_t bootmgr_next(bootmgr_t bmgr);
void bootmgr_close(bootmgr_t bmgr);

#ifdef __cplusplus
}
#endif

#endif /* _DISKLIB_BCD_H */

/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Kris Uchronski <kuchronski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _DMPDEV_PROT_H_
#define _DMPDEV_PROT_H_

#define DMPDEV_CONTROL_PORT 0x998UL
#define DMPDEV_DATA_PORT    0x999UL

#define DMPDEV_PROTOCOL_VERSION 0x00000002UL

typedef enum _DMPDEV_CTRL_CODE {
    DMPDEV_CTRL_UNINTIALIZED,

    DMPDEV_CTRL_VERSION,
    DMPDEV_CTRL_FAILURE,
    DMPDEV_CTRL_CRASH_INFO,
    DMPDEV_CTRL_MODULE_INFO,
    DMPDEV_CTRL_DUMP_DATA,
    DMPDEV_CTRL_GLOBALS_INFO,

    DMPDEV_CTRL_MAX
} DMPDEV_CTRL_CODE;

typedef struct _DMPDEV_VERSION {
    uint32_t version;
} DMPDEV_VERSION, *PDMPDEV_VERSION;

typedef struct _DMPDEV_CRASH_INFO {
    uint32_t code;
    uint64_t param1;
    uint64_t param2;
    uint64_t param3;
    uint64_t param4;
} DMPDEV_CRASH_INFO, *PDMPDEV_CRASH_INFO;

typedef enum _DMPDRV_FAILURE_TYPE {
    DMPDRV_AUXK_INIT_FAILED     = 0x01,
    DMPDRV_QMODULE_QSIZE_FAILED = 0x02,
    DMPDRV_QMODULE_ALLOC_FAILED = 0x02,
    DMPDRV_QMODULE_FAILED       = 0x03,
    DMPDRV_REG_CRASH_CB_FAILED  = 0x04,
    DMPDRV_QBUGCHECK_FAILED     = 0x05,
    DMPDRV_DUMPDATA_FAILED      = 0x06,
    DMPDRV_STR_CONVERTION_FAILED    = 0x07,
    DMPDRV_IMAGE_LOAD_CB_REG_FAILED = 0x08,
    DMPDRV_DMP_HDR_INIT_1_FAILED    = 0x09,
    DMPDRV_DMP_HDR_ALLOC_FAILED     = 0x0A,
    DMPDRV_DMP_HDR_INIT_2_FAILED    = 0x0B,
} DMPDRV_FAILURE_TYPE;

typedef struct _DMPDRV_FAILURE_INFO {
    uint32_t type; /* DMPDRV_FAILURE_TYPE */
    uint32_t code;
} DMPDRV_FAILURE_INFO, *PDMPDRV_FAILURE_INFO;

typedef struct _DMPDEV_DUMP_DATA {
    uint32_t flags;
    uint64_t phys_addr;
    uint32_t size;
} DMPDEV_DUMP_DATA, *PDMPDEV_DUMP_DATA;

typedef enum _DMPDEV_MODULES_INFO_FLAGS {
    DMPDEV_MIF_X64          = 0x00000001,
    DMPDEV_MIF_VALID_MASK   = 0x00000001,
} DMPDEV_MODULES_INFO_FLAGS;

typedef struct _DMPDEV_MODULES_INFO {
    uint32_t flags; /* DMPDEV_MODULES_INFO_FLAGS */
    uint64_t phys_addr;
    uint32_t size;
    uint32_t entry_size;
} DMPDEV_MODULES_INFO, *PDMPDEV_MODULES_INFO;

typedef struct _DMPDEV_GLOBALS_INFO {
    uint64_t PsLoadedModulesList;
    uint64_t PsActiveProcessHead;
} DMPDEV_GLOBALS_INFO, *PDMPDEV_GLOBALS_INFO;

typedef struct _DMPDEV_MODULE_ENTRY_64 {
    uint64_t base_addr;
    uint32_t size;
    uint16_t name_offset;
    uint8_t full_name[1];
} DMPDEV_MODULE_ENTRY_64, *PDMPDEV_MODULE_ENTRY_64;

typedef struct _DMPDEV_MODULE_ENTRY_32 {
    uint32_t base_addr;
    uint32_t size;
    uint16_t name_offset;
    uint8_t full_name[1];
} DMPDEV_MODULE_ENTRY_32, *PDMPDEV_MODULE_ENTRY_32;

#endif /* _DMPDEV_PROT_H_ */

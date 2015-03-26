/*
 * Copyright 2011-2015, Bromium, Inc.
 * Author: Gianni Tedesco
 * SPDX-License-Identifier: ISC
 *
 * Wrapper API around chntpw registry library.
 */
#ifndef _REGHIVE_H
#define _REGHIVE_H

#ifndef REG_NONE

#define REG_NONE                    0  /* No value type */
#define REG_SZ                      1  /* Unicode nul terminated string */
#define REG_EXPAND_SZ               2  /* Unicode nul terminated string + env */
#define REG_BINARY                  3  /* Free form binary */
#define REG_DWORD                   4  /* 32-bit number */
#define REG_DWORD_BIG_ENDIAN        5  /* 32-bit number */
#define REG_LINK                    6  /* Symbolic Link (unicode) */
#define REG_MULTI_SZ                7  /* Multiple Unicode strings */
#define REG_RESOURCE_LIST           8  /* Resource list in the resource map */
#define REG_FULL_RESOURCE_DESCRIPTOR 9 /* Resource list in the hardware description */
#define REG_RESOURCE_REQUIREMENTS_LIST 10  /* Uh? Rait.. */
#define REG_QWORD                   11 /* Quad word 64 bit, little endian */

#define REG_MAX 12

#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _rhkey *rhkey_t;

struct hive_iops {
    int (*filesize)(void *user, size_t *sz);
    int (*read)(void *user, uint8_t *ptr, size_t len);
    int (*write)(void *user, const uint8_t *ptr, size_t len);
    void (*close)(void *user);
    const char *(*filename)(void *user);
};

const char *reghive_type_name(unsigned int type);

int reghive_open_hive(const struct hive_iops *iops, void *user, rhkey_t *res);
int reghive_open_key(rhkey_t key, const char *path, rhkey_t *res);
void reghive_close_key(rhkey_t key);
int reghive_query_info_key(rhkey_t key, struct reg_key_info *info);
int reghive_enum_key(rhkey_t key, unsigned int index, char *name, size_t nlen);
int reghive_enum_value(rhkey_t key, unsigned int index,
                        char *name, size_t nlen,
                        uint8_t *data, size_t *dlen,
                        unsigned int *type);
int reghive_get_value(rhkey_t key, const char *subkey, const char *val,
                        uint8_t *data, size_t *dlen,
                        unsigned int *type);

#ifdef __cplusplus
}
#endif

#endif /* _REGHIVE_H */

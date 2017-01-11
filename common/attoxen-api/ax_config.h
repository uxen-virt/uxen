/*
 * Copyright 2017, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _AX_CONFIG_H_
#define _AX_CONFIG_H_

typedef enum {
  AX_CONFIG_TYPE_RESERVED = 0,
  AX_CONFIG_TYPE_KEY = 1,
  AX_CONFIG_TYPE_NULL = 2,
  AX_CONFIG_TYPE_BOOLEAN = 3,
  AX_CONFIG_TYPE_INTEGER = 4,
  AX_CONFIG_TYPE_LONG_INTEGER = 5,
  AX_CONFIG_TYPE_STRING = 6,
  AX_CONFIG_TYPE_MAP = 7,
} ax_config_type_t;


typedef struct {
  unsigned up, next, value;
  ax_config_type_t type;
  union {
    int integer;
    int64_t long_integer;
    size_t string_offset;
  };
} ax_config_node_t;


extern const ax_config_node_t *ax_config_tree;
extern size_t ax_config_len;

#define CONFIG_TREE_START   1
#define CONFIG_TREE_MAX_DEPTH 10

#if 0

extern void ax_config_dump (void);

extern unsigned ax_config_get_value (unsigned n, const char *key);

extern unsigned ax_config_get_value2 (unsigned n, const char *key1, const char *key2);
extern unsigned ax_config_get_value3 (unsigned n, const char *key1, const char *key2, const char *key3);

extern int ax_config_get_boolean (unsigned n, const char *key, int *v);
extern int ax_config_get_boolean2 (unsigned n, const char *key1, const char *key2, int *v);
extern int ax_config_get_boolean3 (unsigned n, const char *key1, const char *key2, const char *key3, int *v);

extern int ax_config_get_integer (unsigned n, const char *key, int *v);
extern int ax_config_get_integer2 (unsigned n, const char *key1, const char *key2, int *v);
extern int ax_config_get_integer3 (unsigned n, const char *key1, const char *key2, const char *key3, int *v);

extern const char *ax_config_get_string (unsigned n, const char *key, const char **str);
extern const char *ax_config_get_string2 (unsigned n, const char *key1, const char *key2, const char **str);
extern const char *ax_config_get_string3 (unsigned n, const char *key1, const char *key2, const char *key3, const char **str);

#endif

#endif

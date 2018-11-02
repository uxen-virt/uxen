/*
 * Copyright 2018, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __AX_GA_TYPES_H__
#define __AX_GA_TYPES_H__


typedef enum {
  AX_GA_TYPE_EOL,
  AX_GA_TYPE_INT32,
  AX_GA_TYPE_UINT32,
  AX_GA_TYPE_INT64,
  AX_GA_TYPE_UINT64,
  AX_GA_TYPE_ATOMIC,
  AX_GA_TYPE_STRING,
  AX_GA_TYPE_INT8,
  AX_GA_TYPE_UINT8,
  AX_GA_TYPE_INT16,
  AX_GA_TYPE_UINT16,
  AX_GA_TYPE_PE_IMAGE
} ga_type_t;

#define AX_GA_TYPE_FAIL_DATA 0x80000000UL

#endif /* __AX_GA_TYPES_H__ */

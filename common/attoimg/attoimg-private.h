/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef ATTOIMG_PRIVATE_H_
#define ATTOIMG_PRIVATE_H_

#define ATTOIMG_AXAPI

#include <stdint.h>
#include <inttypes.h>

#include <attoxen-api/ax_attovm.h>


#define PERROR perror

#define PAGE_SHIFT  12
#define PAGE_SIZE   4096

#define ATTOVM_IMAGE_MAGIC 0x4d565841
#define ATTOVM_IMAGE_VERSION 1

typedef uint64_t pfn_t;

struct attoimg_image_hdr {
  uint32_t magic;
  uint32_t version;
  struct attovm_definition_v1 definition;
  /* page contents follow */
} __attribute__((packed));

void create_mp_tables(uint32_t addr, void *_mpfps, int vcpus, int flags);

#endif

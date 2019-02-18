/*
 * Copyright 2019, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef ATTOIMG_H_
#define ATTOIMG_H_

/* in attoxen-api/ax_structures.h */
struct attovm_definition_v1;

#define ATTOIMG_ROOTHASH_BYTES 32
#define ATTOIMG_SIGNKEY_BYTES 256

typedef void (*attoimg_error_log_fun_t)(const char *msg);

struct attoimg_initial_image_info {
  const char *trampoline; /* raw image loaded at address 0 */
  const char *kernel; /* kernel elf image */
  const char *initramfs; /* initramfs image (cpio.gz) */

  uint8_t roothash[ATTOIMG_ROOTHASH_BYTES]; /* dm verity hash */

  /* other build parameters */
  uint32_t memsize_mb;
  uint32_t nr_vcpus;
  uint32_t flags;
};

struct attoimg_image_sign_data {
  uint8_t private_key[ATTOIMG_SIGNKEY_BYTES];
};

struct attoimg_guest_mapper {
    void *opaque;

    void* (*map)   (struct attoimg_guest_mapper *, uint64_t addr, uint64_t size);
    void  (*unmap) (struct attoimg_guest_mapper *, void *ptr, uint64_t size);
};

void attoimg_set_error_log_fun(attoimg_error_log_fun_t f);

/* create simple mapper which allocates clear memory on-demand when
 * map operation comes up */
struct attoimg_guest_mapper *attoimg_create_simple_mapper(void);
void attoimg_free_simple_mapper(struct attoimg_guest_mapper *m);

/* create attoimg based on memory/vcpu information specified in 'def' and
 * mapper object able to access that memory */
int attoimg_image_create(
  struct attovm_definition_v1 *def,
  struct attoimg_guest_mapper *mapper,
  const char *filename);

/* create initial image from kernel images, dm verity hash etc */
int attoimg_image_create_from_kernel_image(
  struct attoimg_image_sign_data *sign,
  struct attoimg_initial_image_info *info,
  const char *filename);

/* sign existing image file */
int attoimg_image_sign_existing(
  struct attoimg_image_sign_data *sign,
  const char *input_file,
  const char *output_file
);

/* load image file into memory, using the mapper */
int attoimg_image_read(
    const char *filename,
    struct attovm_definition_v1 *out_def,
    struct attoimg_guest_mapper *mapper);

#endif


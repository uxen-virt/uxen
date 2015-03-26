/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _IOMEM_H_
#define _IOMEM_H_

typedef void (IOMemWriteFunc)(void *opaque, uint64_t addr, uint32_t value);
typedef uint32_t (IOMemReadFunc)(void *opaque, uint64_t addr);

int register_iomem(int index, IOMemReadFunc *mem_read[],
		   IOMemWriteFunc *mem_write[], void *opaque);
void unregister_iomem(int index);

IOMemWriteFunc **get_iomem_write(int index);

void mmio_init(void);
void register_mmio(uint64_t addr, uint64_t size, int index);
int mmio_index(uint64_t addr);
void unregister_mmio(uint64_t addr);
int mmio_write(uint64_t addr, uint32_t val, uint32_t width);
int mmio_read(uint64_t addr, uint32_t width, uint32_t *val);

struct iomem_region {
    IOMemReadFunc *read[3];
    IOMemWriteFunc *write[3];
    void *opaque;
};

#endif	/* _IOMEM_H_ */


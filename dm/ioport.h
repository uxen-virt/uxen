/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _IOPORT_H_
#define _IOPORT_H_

#define MAX_IOPORTS 65536

typedef void (IOPortWriteFunc)(void *opaque, uint32_t address, uint32_t data);
typedef uint32_t (IOPortReadFunc)(void *opaque, uint32_t address);

typedef struct IOPortOps {
    IOPortWriteFunc *write;
    IOPortReadFunc *read;
} IOPortOps;

struct ioport_region {
    uint32_t offset;
    uint32_t len;
    unsigned int size;
    IOPortReadFunc *read;
    IOPortWriteFunc *write;
};

struct ioport_region_list {
    const struct ioport_region *ports;
    MemoryRegion *address_space;
    unsigned int nr;
    MemoryRegion *regions;
    void *opaque;
    const char *name;
};

typedef enum ioport_width { IOPORT_WIDTH0 = 0, IOPORT_WIDTH1 = 1,
			    IOPORT_WIDTH2 = 2 } ioport_width_t;

void ioport_init(void);
uint32_t ioport_read(ioport_width_t width, uint32_t address);
void ioport_write(ioport_width_t width, uint32_t address, uint32_t data);

int register_ioport_ops(uint32_t start, uint32_t length, uint32_t size,
			IOPortOps *ops, void *opaque);
void unregister_ioport_ops(uint32_t start, uint32_t length);
int register_ioport_read(uint32_t start, uint32_t length, uint32_t size,
			 IOPortReadFunc func, void *opaque);
int register_ioport_write(uint32_t start, uint32_t length, uint32_t size,
			  IOPortWriteFunc func, void *opaque);
int register_ioport_list(uint32_t base, const struct ioport_region *list,
			 void *opaque);
void unregister_ioport(uint32_t start, uint32_t length);

ioport_width_t ioport_width(int size, char *errmsg, ...);

void
ioport_region_list_init(struct ioport_region_list *list,
			const struct ioport_region *ports,
			void *opaque, const char *name);
void
ioport_region_list_map(const struct ioport_region_list *list,
		       MemoryRegion *space, uint32_t offset);
void
ioport_region_list_set(const struct ioport_region_list *list,
		       MemoryRegion *space, uint32_t offset);

#endif	/* _IOPORT_H_ */

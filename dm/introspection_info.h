/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _INTROSPECTION_INFO_H_
#define _INTROSPECTION_INFO_H_

struct immutable_range {
    uint64_t base;
    uint64_t size;
};

struct guest_introspect_info_header {
    uint64_t PsLoadedModulesList;
    uint64_t PsActiveProcessHead;
    uint64_t reserved_and_alignment;
    uint64_t n_immutable_ranges;
};

struct guest_introspect_info_t {
    struct guest_introspect_info_header hdr;
    struct immutable_range *ranges;
};

struct guest_introspect_info_t *get_guest_introspect_info(void);

#endif  /* _INTROSPECTION_INFO_H_ */


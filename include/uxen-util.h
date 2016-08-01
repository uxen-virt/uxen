/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#ifndef _UXENL_UTIL_H_
#define _UXENL_UTIL_H_

#define virtual_to_pfn(v) page_to_pfn(is_vmalloc_addr(v) ? vmalloc_to_page(v) : virt_to_page(v))

#endif

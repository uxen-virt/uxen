/*
 * Copyright 2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef _FINGERPRINT_H_
#define _FINGERPRINT_H_

struct page_fingerprint {
    uint64_t hash;
    uint32_t pfn;
    uint16_t rotate;
} __attribute__((__packed__));

uint64_t page_fingerprint(const uint8_t *_page, uint16_t *rotate);

#endif  /* _FINGERPRINT_H_ */

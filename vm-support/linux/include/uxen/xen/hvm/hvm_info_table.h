/******************************************************************************
 * hvm/hvm_info_table.h
 * 
 * HVM parameter and information table, written into guest memory map.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef __XEN_PUBLIC_HVM_HVM_INFO_TABLE_H__
#define __XEN_PUBLIC_HVM_HVM_INFO_TABLE_H__

#define HVM_INFO_PFN         0x09F
#define HVM_INFO_OFFSET      0x800
#define HVM_INFO_PADDR       ((HVM_INFO_PFN << 12) + HVM_INFO_OFFSET)

/* Maximum we can support with current vLAPIC ID mapping. */
#define HVM_MAX_VCPUS        128

struct hvm_oem_info {
    char        oem_id[6];
    char        oem_table_id[8];
    uint32_t    oem_revision;
    char        creator_id[4];
    uint32_t    creator_revision;
    uint8_t     smbios_version_major;
    uint8_t     smbios_version_minor;
};

struct hvm_info_table {
    char        signature[8]; /* "HVM INFO" */
    uint32_t    length;
    uint8_t     checksum;

    /* Should firmware build APIC descriptors (APIC MADT / MP BIOS)? */
    uint8_t     apic_mode;

    /* How many CPUs does this domain have? */
    uint32_t    nr_vcpus;

    /*
     * MEMORY MAP provided by HVM domain builder.
     * Notes:
     *  1. page_to_phys(x) = x << 12
     *  2. If a field is zero, the corresponding range does not exist.
     */
    /*
     *  0x0 to page_to_phys(low_mem_pgend)-1:
     *    RAM below 4GB (except for VGA hole 0xA0000-0xBFFFF)
     */
    uint32_t    low_mem_pgend;
    /*
     *  page_to_phys(reserved_mem_pgstart) to 0xFFFFFFFF:
     *    Reserved for special memory mappings
     */
    uint32_t    reserved_mem_pgstart;
    /*
     *  0x100000000 to page_to_phys(high_mem_pgend)-1:
     *    RAM above 4GB
     */
    uint32_t    high_mem_pgend;

    /* Bitmap of which CPUs are online at boot time. */
    uint8_t     vcpu_online[(HVM_MAX_VCPUS + 7)/8];

    /* Physical address of hvmloader modules */
    uint32_t    mod_base;

    /* OEM info */
    struct hvm_oem_info oem_info;
};

/* HVMLOADER module structures and definitions */
#define HVM_MODULE_SIGNATURE                "_HVMMOD_"
#define HVM_MODULE_INFO_SIGNATURE           "_HVM_MI_"
#define HVM_MODULE_REVISION1                0x01
#define HVM_MODULE_INFO_REVISION1           0x01

/* Header for individual firmware entries (tables etc) */
struct hvm_module_entry {
    /* Length of the current entry */
    uint32_t     length;
    /* Flags to further identify entry */
    uint32_t     flags;
};

#define HVM_MODULE_SMBIOS                   0x00000001
#define HVM_MODULE_ACPI                     0x00000002

/* Main module header */
struct hvm_module {
    /* "_HVMMOD_" */
    char         signature[8];
    /* Type of firmware entries in module */
    uint32_t     type;
    /* Length of entire module including this header */
    uint32_t     length;
    /* Number of entries that follow */
    uint32_t     count;
    /* Current revision */
    uint8_t      revision;
    /* Modular checksum over entire module */
    uint8_t      checksum;

    char         align[2];

    /* Type specific bits start here */
};

/* The primary meta structure that defines the set of
 * HVM modules that follow.
 */
struct hvm_module_info {
    /* "_HVM_MI_" */
    char         signature[8];
    /* Length of this module info structure */
    uint32_t     length;
    /* Count of modules */
    uint32_t     count;
    /* Current revision */
    uint8_t      revision;
    /* Modular checksum over info structure */
    uint8_t      checksum;

    char         align[6];

    /* List of 64b offsets to the modules */
};

#endif /* __XEN_PUBLIC_HVM_HVM_INFO_TABLE_H__ */

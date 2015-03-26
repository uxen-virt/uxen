#ifndef __PE_H
#define __PE_H

#define PE_DOSSTUB_MAGIC 0x5a4d
#define PE_NTSIGN_PTR    0x3c
#define PE_NTSIGN_MAGIC  0x00004550
#define PE_FHDR_OFFSET   0x4
#define PE_OPTHDR_OFFSET 0x18
#define PE_OPTHDR_PE32   0x10b
#define PE_OPTHDR_PE32P  0x20b

/* Useful shortcut */
#define PEOFF_TIMEDATESTAMP			\
    (PE_FHDR_OFFSET + 4)
#define PEOFF_OSVER_MAJOR			\
    (PE_OPTHDR_OFFSET + 40)
#define PEOFF_OSVER_MINOR			\
    (PE_OPTHDR_OFFSET + 42)
#define PEOFF_IMAGESIZE				\
    (PE_OPTHDR_OFFSET + 56)
#define PEOFF_EXPORTTBL_PE32			\
    (PE_OPTHDR_OFFSET + 96)
#define PEOFF_EXPORTTBL_PE32P			\
    (PE_OPTHDR_OFFSET + 112)
#define EXPORTTBLOFF_NAME 12
    
struct coff_fhdr {
#define MACH_X64 0x8664
#define MACH_X86 0x14c
    uint16_t machine;
    uint16_t sections;
    uint32_t timedatestamp;
    uint32_t off_symtable;
    uint32_t symbols;
    uint16_t sz_opthdr;
    uint16_t chars;
} PACKED;

struct coff_opthdr_pe32 {
    uint16_t magic;
    uint16_t lnk_mjr;
    uint16_t lnk_mnr;
    uint32_t sz_code;
    uint32_t sz_data;
    uint32_t sz_bss;
    uint32_t addr_entry;
    uint32_t addr_codebase;

    uint32_t addr_database;
    uint32_t imagebase;
    uint32_t sectionalignment;
    uint32_t filealignment;
    uint16_t osver_mjr;
    uint16_t osver_mnr;
    uint16_t imgver_mjr;
    uint16_t imgver_mnr;
    uint16_t subsys_mjr;
    uint16_t subsys_mnr;
    uint32_t win32ver;
    uint32_t sz_img;
    uint32_t sz_hdrs;
    uint32_t chksum;
    uint32_t subsystem;
    uint32_t dll_chars;
    uint32_t sz_stack_res;
    uint32_t sz_stack_com;
    uint32_t sz_heap_res;
    uint32_t sz_heap_com;
    uint32_t loader_flags;
    uint32_t rvas;

    /* RVA + SIZE */
    uint64_t export_table;
    uint64_t import_table;
    uint64_t rsrc_table;
    uint64_t xcpt_table;
    uint64_t cert_table;
    uint64_t baserec_table;
    uint64_t debug;
    uint64_t arch;
    uint64_t global_ptr;
    uint64_t tls_table;
    uint64_t ldcfg_table;
    uint64_t bound_import;
    uint64_t iat;
    uint64_t dly_import_desc;
    uint64_t clr_rtm_hdr;
    uint64_t reserved;
} PACKED;

struct coff_opthdr_pe32p {
    uint16_t magic;
    uint16_t lnk_mjr;
    uint16_t lnk_mnr;
    uint32_t sz_code;
    uint32_t sz_data;
    uint32_t sz_bss;
    uint32_t addr_entry;
    uint32_t addr_codebase;

    uint64_t imagebase;
    uint32_t sectionalignment;
    uint32_t filealignment;
    uint16_t osver_mjr;
    uint16_t osver_mnr;
    uint16_t imgver_mjr;
    uint16_t imgver_mnr;
    uint16_t subsys_mjr;
    uint16_t subsys_mnr;
    uint32_t win32ver;
    uint32_t sz_img;
    uint32_t sz_hdrs;
    uint32_t chksum;
    uint32_t subsystem;
    uint32_t dll_chars;
    uint64_t sz_stack_res;
    uint64_t sz_stack_com;
    uint64_t sz_heap_res;
    uint64_t sz_heap_com;
    uint32_t loader_flags;
    uint32_t rvas;

    /* RVA + SIZE */
    uint64_t export_table;
    uint64_t import_table;
    uint64_t rsrc_table;
    uint64_t xcpt_table;
    uint64_t cert_table;
    uint64_t baserec_table;
    uint64_t debug;
    uint64_t arch;
    uint64_t global_ptr;
    uint64_t tls_table;
    uint64_t ldcfg_table;
    uint64_t bound_import;
    uint64_t iat;
    uint64_t dly_import_desc;
    uint64_t clr_rtm_hdr;
    uint64_t reserved;
} PACKED;

struct export_directory_table {
    uint32_t export_flgs;
    uint32_t timestamp;
    uint16_t vers_mjr;
    uint16_t vers_mnr;
    uint32_t name_rva;
    uint32_t ordinal_base;
    uint32_t addrtbl_entries;
    uint32_t nameptrs;
    uint32_t exportaddrs_rva;
    uint32_t nameptrs_rva;
    uint32_t ordtbl_rva;
} PACKED;

#endif

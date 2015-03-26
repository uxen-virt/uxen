#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include "xenctrl.h"
#include <xen/hvm/save.h>

int xc_get_pfn_type_batch(xc_interface *xch, uint32_t dom,
                          unsigned int num, xen_pfn_t *);

#ifdef _WIN32
#include <windows.h>
#endif



#define Wwarn(fmt, ...) fprintf(stderr, fmt "\n", __VA_ARGS__)
#define APRINTF(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define EPRINTF(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#if VERBOSE_SAVE
#define SAVE_DPRINTF(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#else
#define SAVE_DPRINTF(...)
#endif

#define PAGE_SHIFT 12
#define PAGE_SIZE (1 << 12)

#define SAVE_FORMAT_VERSION 2

#define XC_SAVE_ID_VCPU_INFO          -2 /* Additional VCPU info */
#define XC_SAVE_ID_HVM_IDENT_PT       -3 /* (HVM-only) */
#define XC_SAVE_ID_HVM_VM86_TSS       -4 /* (HVM-only) */
#define XC_SAVE_ID_TSC_INFO           -7
#define XC_SAVE_ID_HVM_CONSOLE_PFN    -8 /* (HVM-only) */
#define XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION -10
#define XC_SAVE_ID_HVM_MAGIC_PFNS     -11
#define XC_SAVE_ID_HVM_CONTEXT        -12
#define XC_SAVE_ID_HVM_DM             -13
#define XC_SAVE_ID_VM_UUID            -14
#define XC_SAVE_ID_VM_TEMPLATE_UUID   -15
#define XC_SAVE_ID_VERSION            -16
#define XC_SAVE_ID_HVM_INTROSPEC      -17

struct xc_save_version_info {
    int marker;
    uint32_t version;
};

struct xc_save_tsc_info {
    int marker;
    uint32_t tsc_mode;
    uint64_t nsec;
    uint32_t khz;
    uint32_t incarn;
};

struct xc_save_vcpu_info {
    int marker;
    int max_vcpu_id;
    uint64_t vcpumap;
};

struct xc_save_hvm_generic_chunk {
    int marker;
    uint32_t pad;
    uint64_t data;
};

struct xc_save_hvm_magic_pfns {
    int marker;
    uint64_t magic_pfns[3];
};

struct xc_save_hvm_context {
    int marker;
    uint32_t size;
    uint8_t context[];
};

struct xc_save_hvm_dm {
    int marker;
    uint32_t size;
    uint8_t state[];
};

struct xc_save_vm_uuid {
    int marker;
    uint8_t uuid[16];
};

struct xc_save_vm_template_uuid {
    int marker;
    uint8_t uuid[16];
};

#define MAX_BATCH_SIZE 1023

typedef struct FileBuffer {
#ifdef _WIN32
    HANDLE file;
#else
    int file;
#endif
    uint8_t *buffer;
    size_t buffered;
    size_t consumed;
    int writable;
    int eof;
} FileBuffer;

const size_t buffer_max = 1<<20;

static FileBuffer *uxenvm_open(const char *fn, const char *mode)
{
    FileBuffer *fb;

    fb = calloc(1, sizeof(FileBuffer));
    if (!fb)
        return NULL;

    fb->buffer = malloc(buffer_max);
    if (!fb->buffer) {
        free(fb);
        return NULL;
    }

    fb->writable = (*mode == 'w');

#ifdef _WIN32
    fb->file = CreateFile(fn,
                          fb->writable ? GENERIC_WRITE : GENERIC_READ,
                          fb->writable ? 0 : FILE_SHARE_READ, NULL,
                          fb->writable ? CREATE_ALWAYS : OPEN_EXISTING,
                          FILE_FLAG_SEQUENTIAL_SCAN
                          /* | FILE_FLAG_NO_BUFFERING */
                          /* | FILE_FLAG_WRITE_THROUGH */
                          , NULL);
#else
    fb->file = open(fn, fb->writable ? O_RDWR | O_CREAT : O_RDONLY, 0644);
#endif

#ifdef _WIN32
    if (fb->file == INVALID_HANDLE_VALUE) {
#else
    if (fb->file < 0) {
#endif
        free(fb->buffer);
        free(fb);
        fb = NULL;
    }
    return fb;
}

static int
uxenvm_flush(FileBuffer *fb)
{
#ifdef _WIN32
    DWORD wrote;

    if (!WriteFile(fb->file, fb->buffer, fb->buffered, &wrote, NULL)) {
        Wwarn("%s: WriteFile failed", __FUNCTION__);
        return -1;
    }
#else
    ssize_t ret;

    do {
        ret = write(fb->file, fb->buffer, fb->buffered);
    } while (ret < 0 && errno == EINTR);
    if (ret < 0) {
        warn("%s: write failed", __FUNCTION__);
        return -1;
    }
#endif
    fb->buffered = 0;
    return 0;
}

static void
uxenvm_close(FileBuffer *fb)
{

    if (fb->writable)
        uxenvm_flush(fb);
#ifdef _WIN32
    CloseHandle(fb->file);
#else
    close(fb->file);
#endif
    free(fb->buffer);
    free(fb);
}

static int
uxenvm_write(FileBuffer *fb, void *buf, size_t size)
{
    uint8_t *b = buf;

    while (size) {
        size_t n = size;

        if (n > buffer_max - fb->buffered)
            n = buffer_max - fb->buffered;
        memcpy(fb->buffer + fb->buffered, b, n);
        fb->buffered += n;
        b += n;
        size -= n;

        if (fb->buffered == buffer_max) {
            if (uxenvm_flush(fb) < 0)
                return -1;
        }
    }
    return b - (uint8_t *) buf;
}

static int
uxenvm_savevm_execute(xc_interface *xc_handle, FileBuffer *f,
                      uint8_t *vm_uuid, int domid)
{
    int32_t hvm_buf_size;
    uint8_t *hvm_buf = NULL;
    xc_dominfo_t dom_info[1];
    xc_vcpuinfo_t vcpu_info;
    struct xc_save_version_info s_version_info;
    struct xc_save_tsc_info s_tsc_info;
    struct xc_save_vcpu_info s_vcpu_info;
    struct xc_save_hvm_generic_chunk s_hvm_ident_pt;
    struct xc_save_hvm_generic_chunk s_hvm_vm86_tss;
    struct xc_save_hvm_generic_chunk s_hvm_console_pfn;
    struct xc_save_hvm_generic_chunk s_hvm_acpi_ioports_location;
    struct xc_save_hvm_magic_pfns s_hvm_magic_pfns;
    struct xc_save_hvm_context s_hvm_context;
    struct xc_save_vm_uuid s_vm_uuid;
    int p2m_size;
    unsigned int pfn, batch, _batch, run, b_run, rezero;
    int total_pages = 0, total_rezero = 0, total_clone = 0;
    int j;
    xen_pfn_t *pfn_type = NULL;
    int *pfn_err = NULL;
    int *pfn_zero = NULL;
    int zero_batch = 0;
    int map_err;
    uint8_t *mem = NULL;
    int mem_nr;
    int ret;

    s_version_info.marker = XC_SAVE_ID_VERSION;
    s_version_info.version = SAVE_FORMAT_VERSION;
    uxenvm_write(f, &s_version_info, sizeof(s_version_info));

    s_tsc_info.marker = XC_SAVE_ID_TSC_INFO;
    ret = xc_domain_get_tsc_info(xc_handle, domid, &s_tsc_info.tsc_mode,
				 &s_tsc_info.nsec, &s_tsc_info.khz,
				 &s_tsc_info.incarn);
    if (ret < 0) {
	fprintf(stderr, "xc_domain_get_tsc_info() failed");
	ret = -EPERM;
	goto out;
    }
    APRINTF("tsc info: mode %d nsec %"PRIu64" khz %d incarn %d",
	    s_tsc_info.tsc_mode, s_tsc_info.nsec, s_tsc_info.khz,
	    s_tsc_info.incarn);
    uxenvm_write(f, &s_tsc_info, sizeof(s_tsc_info));

    ret = xc_domain_getinfo(xc_handle, domid, 1, dom_info);
    if (ret != 1 || dom_info[0].domid != domid) {
	fprintf(stderr, "xc_domain_getinfo(%d) failed", domid);
	ret = -EPERM;
	goto out;
    }
    s_vcpu_info.marker = XC_SAVE_ID_VCPU_INFO;
    s_vcpu_info.max_vcpu_id = dom_info[0].max_vcpu_id;
    s_vcpu_info.vcpumap = 0ULL;
    for (j = 0; j <= s_vcpu_info.max_vcpu_id; j++) {
	ret = xc_vcpu_getinfo(xc_handle, domid, j, &vcpu_info);
	if (ret == 0 && vcpu_info.online)
	    s_vcpu_info.vcpumap |= 1ULL << j;
    }
    APRINTF("vcpus %d online %"PRIx64, s_vcpu_info.max_vcpu_id,
	    s_vcpu_info.vcpumap);
    uxenvm_write(f, &s_vcpu_info, sizeof(s_vcpu_info));

    s_hvm_ident_pt.marker = XC_SAVE_ID_HVM_IDENT_PT;
    s_hvm_ident_pt.data = 0;
    xc_get_hvm_param(xc_handle, domid, HVM_PARAM_IDENT_PT,
		     &s_hvm_ident_pt.data);
    APRINTF("ident_pt %"PRIx64, s_hvm_ident_pt.data);
    if (s_hvm_ident_pt.data)
	uxenvm_write(f, &s_hvm_ident_pt, sizeof(s_hvm_ident_pt));

    s_hvm_vm86_tss.marker = XC_SAVE_ID_HVM_VM86_TSS;
    s_hvm_vm86_tss.data = 0;
    xc_get_hvm_param(xc_handle, domid, HVM_PARAM_VM86_TSS,
		     &s_hvm_vm86_tss.data);
    APRINTF("vm86_tss %"PRIx64, s_hvm_vm86_tss.data);
    if (s_hvm_vm86_tss.data)
	uxenvm_write(f, &s_hvm_vm86_tss, sizeof(s_hvm_vm86_tss));

    s_hvm_console_pfn.marker = XC_SAVE_ID_HVM_CONSOLE_PFN;
    s_hvm_console_pfn.data = 0;
    xc_get_hvm_param(xc_handle, domid, HVM_PARAM_CONSOLE_PFN,
		     &s_hvm_console_pfn.data);
    APRINTF("console_pfn %"PRIx64, s_hvm_console_pfn.data);
    if (s_hvm_console_pfn.data)
	uxenvm_write(f, &s_hvm_console_pfn, sizeof(s_hvm_console_pfn));

    s_hvm_acpi_ioports_location.marker = XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION;
    s_hvm_acpi_ioports_location.data = 0;
    xc_get_hvm_param(xc_handle, domid, HVM_PARAM_ACPI_IOPORTS_LOCATION,
		     &s_hvm_acpi_ioports_location.data);
    APRINTF("acpi_ioports_location %"PRIx64, s_hvm_acpi_ioports_location.data);
    if (s_hvm_acpi_ioports_location.data)
	uxenvm_write(f, &s_hvm_acpi_ioports_location,
		     sizeof(s_hvm_acpi_ioports_location));

    s_hvm_magic_pfns.marker = XC_SAVE_ID_HVM_MAGIC_PFNS;
    memset(s_hvm_magic_pfns.magic_pfns, 0, sizeof(s_hvm_magic_pfns.magic_pfns));
    xc_get_hvm_param(xc_handle, domid, HVM_PARAM_IO_PFN_FIRST,
		     &s_hvm_magic_pfns.magic_pfns[0]);
    xc_get_hvm_param(xc_handle, domid, HVM_PARAM_IO_PFN_LAST,
		     &s_hvm_magic_pfns.magic_pfns[1]);
    xc_get_hvm_param(xc_handle, domid, HVM_PARAM_SHARED_INFO_PFN,
		     &s_hvm_magic_pfns.magic_pfns[2]);
    APRINTF("ioreq pfn %"PRIx64" bufioreq pfn %"PRIx64
            " shared info pfn %"PRIx64, s_hvm_magic_pfns.magic_pfns[0],
            s_hvm_magic_pfns.magic_pfns[1], s_hvm_magic_pfns.magic_pfns[2]);
    uxenvm_write(f, &s_hvm_magic_pfns, sizeof(s_hvm_magic_pfns));

    hvm_buf_size = xc_domain_hvm_getcontext(xc_handle, domid, 0, 0);
    if (hvm_buf_size == -1) {
	fprintf(stderr, "xc_domain_hvm_getcontext(0, 0) failed");
	ret = -EPERM;
	goto out;
    }
    APRINTF("hvm_buf_size is %d", hvm_buf_size);

    hvm_buf = malloc(hvm_buf_size);
    if (hvm_buf == NULL) {
	fprintf(stderr, "hvm_buf = malloc(%d) failed", hvm_buf_size);
	ret = -ENOMEM;
	goto out;
    }

    s_hvm_context.marker = XC_SAVE_ID_HVM_CONTEXT;
    s_hvm_context.size = xc_domain_hvm_getcontext(xc_handle, domid,
						  hvm_buf, hvm_buf_size);
    if (s_hvm_context.size == -1) {
	fprintf(stderr, "xc_domain_hvm_getcontext(%d) failed", hvm_buf_size);
	ret = -EPERM;
	goto out;
    }
    APRINTF("hvm rec size %d", s_hvm_context.size);
    uxenvm_write(f, &s_hvm_context, sizeof(s_hvm_context));
    uxenvm_write(f, hvm_buf, s_hvm_context.size);

    s_vm_uuid.marker = XC_SAVE_ID_VM_UUID;
    memcpy(s_vm_uuid.uuid, vm_uuid, sizeof(s_vm_uuid.uuid));
    uxenvm_write(f, &s_vm_uuid, sizeof(s_vm_uuid));

    p2m_size = xc_domain_maximum_gpfn(xc_handle, domid);
    if (p2m_size < 0) {
	fprintf(stderr, "xc_domain_maximum_gpfn() failed");
	ret = -EPERM;
	goto out;
    }
    p2m_size++;
    /* Do not try to save a MMIO range of a running guest */
    if (p2m_size > 0xe0000)
	p2m_size = 0xdffff;

    APRINTF("p2m_size: 0x%x", p2m_size);
    pfn_type = malloc(MAX_BATCH_SIZE * sizeof(*pfn_type));
    if (pfn_type == NULL) {
	fprintf(stderr, "pfn_type = malloc(%"PRId64") failed",
                (uint64_t)MAX_BATCH_SIZE * sizeof(*pfn_type));
	ret = -ENOMEM;
	goto out;
    }

    pfn_err = malloc(MAX_BATCH_SIZE * sizeof(*pfn_err));
    if (pfn_err == NULL) {
	fprintf(stderr, "pfn_err = malloc(%"PRId64") failed",
                (uint64_t)MAX_BATCH_SIZE * sizeof(*pfn_err));
	ret = -ENOMEM;
	goto out;
    }

    pfn_zero = malloc(MAX_BATCH_SIZE * sizeof(*pfn_zero));
    if (pfn_zero == NULL) {
        fprintf(stderr, "pfn_zero = malloc(%"PRId64") failed",
                (uint64_t)MAX_BATCH_SIZE * sizeof(*pfn_zero));
        ret = -ENOMEM;
        goto out;
    }

    mem = NULL;
    pfn = 0;
    while (pfn < p2m_size) {
	batch = 0;
	while ((pfn + batch) < p2m_size && batch < MAX_BATCH_SIZE) {
	    pfn_type[batch] = pfn + batch;
	    batch++;
	}
	if (mem)
	    xc_munmap(xc_handle, domid, mem, mem_nr * PAGE_SIZE);
	mem = xc_map_foreign_bulk(xc_handle, domid, PROT_WRITE,
				  pfn_type, pfn_err, batch);
	if (mem == NULL) {
	    fprintf(stderr, "xc_map_foreign_bulk(%d, %d) failed",
		     pfn, batch);
	    ret = -EPERM;
	    goto out;
	}
	mem_nr = batch;
	ret = xc_get_pfn_type_batch(xc_handle, domid, batch, pfn_type);
	if (ret) {
	    fprintf(stderr, "xc_get_pfn_type_batch(%d, %d) failed",
		     pfn, batch);
	    ret = -EPERM;
	    goto out;
	}
	rezero = 0;
        _batch = 0;
	for (j = 0; j < batch; j++) {
	    map_err = pfn_err[j];
	    if (!map_err && !pfn_type[j]) {
		uint64_t *p = (uint64_t *)&mem[j << PAGE_SHIFT];
		int i = 0;
		while (i < (PAGE_SIZE >> 3) && !p[i])
		    i++;
		if (i == (PAGE_SIZE >> 3)) {
		    pfn_type[j] = XEN_DOMCTL_PFINFO_XALLOC;
		    rezero++;
                    total_rezero++;
                    map_err = 1;
		}
            }
            if (!map_err && !pfn_type[j]) {
                pfn_err[_batch] = pfn + j;
                _batch++;
            } else if (map_err && pfn_type[j] == XEN_DOMCTL_PFINFO_XALLOC) {
		map_err = 0;
                pfn_zero[zero_batch] = pfn_type[j] | (pfn + j);
                zero_batch++;
                if (zero_batch == MAX_BATCH_SIZE) {
                    int _zero_batch = zero_batch + 2 * MAX_BATCH_SIZE;
                    uxenvm_write(f, &_zero_batch, sizeof(zero_batch));
                    uxenvm_write(f, &pfn_zero[0],
                                 zero_batch * sizeof(pfn_zero[0]));
                    zero_batch = 0;
                }
            } else if (pfn_type[j] == XEN_DOMCTL_PFINFO_XPOD) {
		/* Save cloned pages as well */
                map_err = 0;
		pfn_err[_batch] = pfn + j;
		_batch++;
		total_clone++;
            }
	    if (map_err) {
		if (pfn_type[j] == XEN_DOMCTL_PFINFO_XTAB)
		    continue;
		EPRINTF("map fail: gpfn %08x err %d type %"PRIx64, pfn + j,
			map_err, pfn_type[j]);
		pfn_type[j] = XEN_DOMCTL_PFINFO_XTAB;
		continue;
	    }
	    if (pfn_type[j] == XEN_DOMCTL_PFINFO_XTAB) {
		EPRINTF("type fail: gpfn %08x", pfn + j);
		continue;
	    }
	}
        if (_batch) {
            SAVE_DPRINTF("page batch %08x:%08x = %03x pages,"
                         " rezero %03x, clone %03x",
                         pfn, pfn + batch, _batch, rezero, clone);
            uxenvm_write(f, &_batch, sizeof(_batch));
            uxenvm_write(f, pfn_err, _batch * sizeof(pfn_err[0]));
            j = 0;
            while (j != batch) {
                while (j != batch && pfn_type[j])
                    j++;
                run = j;
                while (j != batch && !pfn_type[j])
                    j++;
                if (run != j) {
                    b_run = j - run;
                    SAVE_DPRINTF(
                        "     write %08x:%08x = %03x pages",
                        pfn + run, pfn + j, b_run);
		    uxenvm_write(f, &mem[run << PAGE_SHIFT],
				 b_run << PAGE_SHIFT);
                    run += b_run;
                    _batch -= b_run;
                    total_pages += b_run;
		}
            }
	}
	pfn += batch;
    }

    if (zero_batch) {
        int _zero_batch = zero_batch + 2 * MAX_BATCH_SIZE;
        uxenvm_write(f, &_zero_batch, sizeof(zero_batch));
        uxenvm_write(f, &pfn_zero[0],
                     zero_batch * sizeof(pfn_zero[0]));
    }

    /* 0: end marker */
    batch = 0;
    uxenvm_write(f, &batch, sizeof(batch));

    APRINTF("memory: pages %d rezero %d clone %d", total_pages, total_rezero,
            total_clone);

    ret = 0;
  out:
    if (mem)
	xc_munmap(xc_handle, domid, mem, mem_nr * PAGE_SIZE);
    free(pfn_zero);
    free(pfn_err);
    free(pfn_type);
    free(hvm_buf);
    return ret;
}

void
do_save(xc_interface *xch, char *filename, uint8_t *uuid, int domid)
{
    int ret;
    struct FileBuffer *fb;

    fb = uxenvm_open(filename, "w");
    if (!fb) {
	fprintf(stderr, "Could not open file %s\n", filename);
	return;
    }

    ret = uxenvm_savevm_execute(xch, fb, uuid, domid);
    if (ret)
	fprintf(stderr, "Could not save vm\n");

    uxenvm_close(fb);
}

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <compiler.h>
#include <xenctrl.h>
#include "kdd-savefile.h"
#include <vm-savefile.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1U << PAGE_SHIFT)

#define SKIP_MARKER_STRUCT(f, sz) do { \
        fseek(f, (sz) - sizeof(int32_t), SEEK_CUR); \
    } while (1 == 0)
#define SKIP_GENERIC_STRUCT(f, _log, _out) do {         \
        int32_t size;                                   \
        if (fread(&size, sizeof(size), 1, f) != 1) {    \
            if (_log)                                   \
                fprintf(_log, "error reading size\n");  \
            goto _out;                                  \
        }                                               \
        fseek(f, size, SEEK_CUR);                       \
    } while (0)

enum batch_type_e {
    BATCH_UNKNOWN = 0,
    BATCH_ZERO,
    BATCH_COMPRESSED,
    BATCH_UNCOMPRESSED
};

struct page_node {
    int64_t pos;
    void *ptr;
};

/* backwards compatibility */
struct xc_save_hvm_magic_pfns_v2 {
    int32_t marker;
    uint64_t magic_pfns[3];
};

struct xc_save_hvm_magic_pfns_v4 {
    int32_t marker;
    uint64_t magic_pfns[5];
};

struct xc_save_hvm_generic_chunk_v4 {
    int32_t marker;
    uint32_t pad;
    uint64_t data;
};

#define XC_SAVE_ID_HVM_IDENT_PT_v4       -3 /* (HVM-only) */
#define XC_SAVE_ID_HVM_VM86_TSS_v4       -4 /* (HVM-only) */
#define XC_SAVE_ID_HVM_CONSOLE_PFN_v4    -8 /* (HVM-only) */
#define XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION_v4 -10
#define XC_SAVE_ID_HVM_MAGIC_PFNS_v4     -11
/* end backwards compatibility */

#define PGS_ALLOC_GRAN  1024

struct savefile_ctx {
    FILE *f;
    FILE *log;
    int verbosity;
    struct page_node *pgs;
    uint8_t *zero_page;
    uint32_t pgs_pfncap;
    uint32_t pgs_maxpfn;

    struct xc_save_hvm_context *hvm_ctx;
};

struct savefile_ctx *
svf_init(const char *save_file, FILE *log, int verbosity)
{
    struct savefile_ctx *svf = NULL;
    int32_t marker;
    struct xc_save_version_info version_info;
    struct xc_save_hvm_context s_hvm_context;
    int end_marker = 0;
    int batch_type;
    int32_t batch;
    int32_t *pfn_info = NULL;
    size_t i;
    int64_t pos;
    uint32_t nzero = 0, npages = 0;
    int magic_pfns_v2 = 0;
    int chunks_v4 = 0;

    pfn_info = malloc(MAX_BATCH_SIZE * sizeof(*pfn_info));

    if (!pfn_info)
        goto mem_err;

    svf = calloc(1, sizeof(*svf));
    if (!svf)
        goto mem_err;

    svf->log = log;
    svf->verbosity = verbosity;

    svf->f = fopen(save_file, "rb");
    if (!svf->f) {
        if (log)
            fprintf(log, "error opening file %s\n", save_file);
        goto err;
    }

    if (svf->log)
        fprintf(log, "using save file %s\n", save_file);

    if (fread(&version_info, sizeof(version_info), 1, svf->f) != 1) {
        if (log)
            fprintf(log, "error reading version info\n");
        goto err;
    }

    switch (version_info.version) {
    case 2:
        magic_pfns_v2 = 1;
    case 3:
    case 4:
        chunks_v4 = 1;
        break;
    case SAVE_FORMAT_VERSION:
        break;
    default:
        fprintf(log, "error, unknown savefile version %d \n",
               (int) version_info.version);
        goto err;
    }

    if (version_info.marker != XC_SAVE_ID_VERSION) {
        if (log)
            fprintf(log, "error, wrong version marker %dn",
                    (int) version_info.marker);
        goto err;
    }

    while (!end_marker) {

        if (fread(&marker, sizeof(marker), 1, svf->f) != 1) {
            if (log)
                fprintf(log, "error on reading marker\n");
            goto err;
        }

        if (svf->verbosity > 1 && svf->log)
            fprintf(svf->log, "reading marker %d\n", (int) marker);

        switch (marker) {
        case 0:
            end_marker = 1;
            break;
        case XC_SAVE_ID_TSC_INFO:
            SKIP_MARKER_STRUCT(svf->f, sizeof(struct xc_save_tsc_info));
            break;
        case XC_SAVE_ID_VCPU_INFO:
            SKIP_MARKER_STRUCT(svf->f, sizeof(struct xc_save_vcpu_info));
            break;
        case XC_SAVE_ID_HVM_PARAMS:
            SKIP_GENERIC_STRUCT(svf->f, log, err);
            break;
        case XC_SAVE_ID_HVM_CONTEXT:
            fseek(svf->f, - (long) sizeof(int32_t), SEEK_CUR);
            if (fread(&s_hvm_context, sizeof(s_hvm_context), 1, svf->f) != 1) {
                if (log)
                    fprintf(log, "error reading hvm context struct\n");
                goto err;
            }
            svf->hvm_ctx = calloc(1, sizeof(s_hvm_context) + s_hvm_context.size);
            if (!svf->hvm_ctx)
                goto mem_err;
            memcpy(svf->hvm_ctx, &s_hvm_context, sizeof(s_hvm_context));
            if (fread(&svf->hvm_ctx->context, s_hvm_context.size, 1, svf->f) != 1) {
                if (log)
                    fprintf(log, "error reading hvm context data\n");
                goto err;
            }
            break;
        case XC_SAVE_ID_VM_UUID:
            SKIP_MARKER_STRUCT(svf->f, sizeof(struct xc_save_vm_uuid));
            break;
        default:
            if (marker < 0) {
                if (log)
                    fprintf(log, "error, unknown marker type %d\n", (int) marker);
                goto err;
            }

            /* mem pages */
            batch_type = BATCH_UNKNOWN;
            if (marker > 2 * MAX_BATCH_SIZE) {
                marker -= 2 * MAX_BATCH_SIZE;
                batch_type = BATCH_ZERO;
            } else if (marker > MAX_BATCH_SIZE) {
                if (log)
                    fprintf(log, "error, compressed batch type not supported\n");
                goto err;
            } else {
                batch_type = BATCH_UNCOMPRESSED;
            }
            batch = marker;
            if (batch > MAX_BATCH_SIZE) {
                if (log)
                    fprintf(log, "errror, batch %lu > MAX_BATCH_SIZE\n",
                            (unsigned long) batch);
                goto err;
            }

            if (batch_type != BATCH_ZERO && batch_type != BATCH_UNCOMPRESSED) {
                if (log)
                    fprintf(log, "unsupported batch type %d\n", (int) batch_type);
                goto err;
            }

            if (fread(pfn_info, batch * sizeof(pfn_info[0]), 1, svf->f) != 1) {
                if (log)
                    fprintf(log, "error on loading pfn_info for batch %d\n", (int) batch);
                goto err;
            }

            pos = -1;
            if (batch_type == BATCH_ZERO)
                nzero += batch;
            else
                npages += batch;
            for (i = 0; i < batch; i++) {
                uint32_t pfn;

                pfn = ((uint32_t) pfn_info[i]) &
                      ((uint32_t) (1 << XEN_DOMCTL_PFINFO_LTAB_SHIFT) - 1);

                if (!svf->pgs || svf->pgs_pfncap <= pfn) {
                    void *tmp;

                    tmp = realloc(svf->pgs, (pfn + PGS_ALLOC_GRAN) * sizeof(svf->pgs[0]));
                    if (!tmp)
                        goto mem_err;
                    svf->pgs = tmp;
                    memset(&svf->pgs[svf->pgs_pfncap], 0,
                           (pfn + PGS_ALLOC_GRAN - svf->pgs_pfncap) * sizeof(svf->pgs[0]));
                    svf->pgs_pfncap = pfn + PGS_ALLOC_GRAN;
                }

                if (svf->pgs_maxpfn < pfn)
                    svf->pgs_maxpfn = pfn;

                if (batch_type == BATCH_ZERO) {
                    svf->pgs[pfn].pos = -1;
                    if (!svf->zero_page) {
                        svf->zero_page = calloc(1, PAGE_SIZE);
                        if (!svf->zero_page)
                            goto mem_err;
                    }
                } else {
                    if (pos < 0)
                        pos = ftello(svf->f);
                    if (pos < 0) {
                        if (log)
                            fprintf(log, "error on ftello\n");
                        goto err;
                    }
                    svf->pgs[pfn].pos = pos + (((int64_t) i) << PAGE_SHIFT);
                }
            }

            if (batch_type == BATCH_UNCOMPRESSED && fseek(svf->f, ((long) batch) << PAGE_SHIFT,
                                                          SEEK_CUR)) {
                if (log)
                    fprintf(log, "fseek error\n");
                goto err;
            }
            break;
            /* backwards compatibility */
        case XC_SAVE_ID_HVM_IDENT_PT_v4:
        case XC_SAVE_ID_HVM_VM86_TSS_v4:
        case XC_SAVE_ID_HVM_CONSOLE_PFN_v4:
        case XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION_v4:
            if (!chunks_v4) {
                if (log)
                    fprintf(log, "savefile v%d: chunk %d unexpected\n",
                            version_info.version, marker);
                goto err;
            }
            SKIP_MARKER_STRUCT(svf->f,
                               sizeof(struct xc_save_hvm_generic_chunk_v4));
            break;
         case XC_SAVE_ID_HVM_MAGIC_PFNS_v4:
            if (!chunks_v4) {
                if (log)
                    fprintf(log, "savefile v%d: "
                            "XC_SAVE_ID_HVM_MAGIC_PFNS unexpected\n",
                            version_info.version);
                goto err;
            }
            if (magic_pfns_v2)
                SKIP_MARKER_STRUCT(svf->f,
                                   sizeof(struct xc_save_hvm_magic_pfns_v2));
            else
                SKIP_MARKER_STRUCT(svf->f,
                                   sizeof(struct xc_save_hvm_magic_pfns_v4));
            break;
            /* end backwards compatibility */
        }
    }

    if (svf->log)
        fprintf(log, "max pfn 0x%x #zero %u #nonzero %u\n", (unsigned) svf->pgs_maxpfn,
                nzero, npages);

out:
    free(pfn_info);
    return svf;
err:
    if (svf)
        svf_free(svf);
    svf = NULL;
    goto out;
mem_err:
    if (svf && svf->log)
        fprintf(svf->log, "memory allocation error\n");
    goto err;
}

void svf_free(struct savefile_ctx *svf)
{
    if (!svf)
        return;

    svf_reset_mappings(svf);
    free(svf->zero_page);
    free(svf->pgs);

    if (svf->f)
        fclose(svf->f);
    free(svf);
}


void *svf_map_foreign_page(struct savefile_ctx *svf, uint32_t dom,
                            int prot,
                            unsigned long mfn)
{
    void *ptr = NULL;

    if (!svf->pgs || mfn > svf->pgs_maxpfn)
        goto out;

    if (svf->pgs[mfn].pos < 0) {
        if (svf->zero_page)
            ptr = svf->zero_page;
        if (svf->verbosity > 1 && svf->log)
            fprintf(svf->log, " mapping mfn 0x%x, returning zero page\n", (unsigned) mfn);
        goto out;
    }

    if (svf->pgs[mfn].ptr) {
        ptr = svf->pgs[mfn].ptr;
        goto out;
    }

    if (fseeko(svf->f, svf->pgs[mfn].pos, SEEK_SET))
        goto out;
    svf->pgs[mfn].ptr = malloc(PAGE_SIZE);
    if (!svf->pgs[mfn].ptr)
        goto out;
    if (fread(svf->pgs[mfn].ptr, PAGE_SIZE, 1, svf->f) != 1) {
        free(svf->pgs[mfn].ptr);
        svf->pgs[mfn].ptr = NULL;
    }

    ptr = svf->pgs[mfn].ptr;

out:
    if (!ptr && svf->verbosity && svf->log)
        fprintf(svf->log, "cannot map mfn 0x%x\n", (unsigned) mfn);
    return ptr;
}

void svf_munmap_page(struct savefile_ctx *svf, uint32_t dom, void *addr)
{
}

void svf_reset_mappings(struct savefile_ctx *svf)
{
    size_t i;

    if (!svf || !svf->pgs)
        return;

    for (i = 0; i <= svf->pgs_maxpfn; i++) {
        free(svf->pgs[i].ptr);
        svf->pgs[i].ptr = NULL;
    }
}

int svf_domain_pause(struct savefile_ctx *svf, uint32_t domid)
{
    return 0;
}

int svf_domain_unpause(struct savefile_ctx *svf, uint32_t domid)
{
    return 0;
}

int svf_domain_hvm_getcontext(struct savefile_ctx *svf,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size)
{
    if (!svf->hvm_ctx)
        return -1;
    if (!ctxt_buf)
        return svf->hvm_ctx->size;
    if (size > svf->hvm_ctx->size)
        size = svf->hvm_ctx->size;
    memcpy(ctxt_buf, &svf->hvm_ctx->context, size);
    return size;
}

int svf_domain_hvm_setcontext(struct savefile_ctx *svf,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size)
{
    return -1;
}

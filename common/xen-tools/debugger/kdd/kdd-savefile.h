#ifndef _KDD_SAVEFILEH_
#define _KDD_SAVEFILEH_

struct savefile_ctx;

struct savefile_ctx *
svf_init(const char *save_file, FILE *log, int verbosity);

void svf_free(struct savefile_ctx *svf);

void svf_munmap_page(struct savefile_ctx *svf, uint32_t dom, void *addr);
void *svf_map_foreign_page(struct savefile_ctx *svf, uint32_t dom,
                            int prot,
                            unsigned long mfn);
int svf_domain_pause(struct savefile_ctx *svf, uint32_t domid);
int svf_domain_unpause(struct savefile_ctx *svf, uint32_t domid);
int svf_domain_hvm_getcontext(struct savefile_ctx *svf,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size);
int svf_domain_hvm_setcontext(struct savefile_ctx *svf,
                             uint32_t domid,
                             uint8_t *ctxt_buf,
                             uint32_t size);
void svf_reset_mappings(struct savefile_ctx *svf);
#endif

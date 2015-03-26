int winsym_init(void *winsymid,
                char *modname, uint32_t timestamp, uint32_t imagesize,
                char *symsrvpath, uint64_t vabase);
int winsym_resolve(void *winsymid, char *sym, uint64_t *addr);
int winsym_fin(void *winsymid);


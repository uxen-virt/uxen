/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

struct iat_hook {
    const char *mod_name;
    const char *fn_name;

    void *orig_fn;
    void *hook_fn;

    struct iat_hook *next;
    struct iat_hook **pprev;
};

int iat_hook_init(HMODULE thismodule);
void iat_hook_cleanup(void);
int iat_hook_add(struct iat_hook *h,
                 const char *module_name,
                 const char *func_name,
                 void *func);
void iat_hook_remove(struct iat_hook *h);

static inline void dbgprint(const char *fmt, ...)
{
    char buf[4096];
    va_list args;

    va_start(args, fmt);
    vsnprintf(buf, sizeof (buf), fmt, args);
    OutputDebugStringA(buf);
    va_end(args);
}

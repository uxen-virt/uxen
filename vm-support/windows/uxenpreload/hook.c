/*
 * Copyright 2014-2015, Bromium, Inc.
 * Author: Julian Pidancet <julian@pidancet.net>
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>
#include <psapi.h>

#include <stdlib.h>
#include <stdio.h>

#include "hook.h"

//#define HOOK_DEBUG 1

static char progname[512] = "";

#ifdef HOOK_DEBUG
#define HOOKDBG(fmt, ...) \
    dbgprint("%s:%s:%d: "fmt"\n", \
             progname, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define HOOKDBG(fmt, ...)
#endif

static HMODULE hook_mod = NULL;
static struct iat_hook *hook_list = NULL;

static IMAGE_IMPORT_DESCRIPTOR *
iat_get_import_desc(HMODULE module)
{
    size_t base = (size_t)module;
    IMAGE_DOS_HEADER *dos_header;
    IMAGE_NT_HEADERS *nt_header;
    IMAGE_OPTIONAL_HEADER *opt_header;
    IMAGE_IMPORT_DESCRIPTOR *iid;

    dos_header = (IMAGE_DOS_HEADER*)module;
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    nt_header = (IMAGE_NT_HEADERS*)(dos_header->e_lfanew + base);
    if (nt_header->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    opt_header = &nt_header->OptionalHeader;
    if (opt_header->Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        return NULL;
    if (!opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        return NULL;
    if (!opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
        return NULL;

    iid = (IMAGE_IMPORT_DESCRIPTOR*)(base +
            opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    return iid;
}

static int
iat_patch(void **entry, void *func)
{
    DWORD newrights = PAGE_EXECUTE_READWRITE;
    DWORD oldrights;

    VirtualProtect(entry, sizeof (void *), newrights, &oldrights);
    *entry = func;
    VirtualProtect(entry, sizeof (void *), oldrights, &newrights);

    return 0;
}

static int
iat_hook_module(HMODULE _module, struct iat_hook *h, void *old_func, void *func)
{
    HMODULE module;
    size_t base;
    IMAGE_IMPORT_DESCRIPTOR *iid;
    char mod_name[512];
    int ret = -1;

    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                           (void *)_module, &module))
        return -1;

    base = (size_t)module;

    if (!GetModuleBaseName(GetCurrentProcess(),
                           module, mod_name, sizeof (mod_name)))
        goto out;

    iid = iat_get_import_desc(module);
    if (!iid)
        goto out;

    while (iid->Name) {
        const char *imgname = (const char *)(iid->Name + base);
        IMAGE_THUNK_DATA *thunk = (IMAGE_THUNK_DATA *)
            (iid->FirstThunk + base);
        IMAGE_THUNK_DATA *othunk = (IMAGE_THUNK_DATA *)
            (iid->OriginalFirstThunk + base);

        while (thunk->u1.Function) {
            IMAGE_IMPORT_BY_NAME *import = (IMAGE_IMPORT_BY_NAME *)
                ((char *)othunk->u1.AddressOfData + base);

            if (othunk->u1.AddressOfData & IMAGE_ORDINAL_FLAG)
                goto skip;

            if (!stricmp(imgname, h->mod_name) &&
                !strcmp((char *)import->Name, h->fn_name)) {
                HOOKDBG("%s!%s: replacing IAT entry in module %s"
                        " for %s!%s (name match)",
                        h->mod_name, h->fn_name, mod_name,
                        imgname, import->Name);
                iat_patch((void **)&thunk->u1.Function, func);
            } else if ((void *)thunk->u1.Function == old_func) {
                HOOKDBG("%s!%s: replacing IAT entry in module %s"
                        " for %s!%s (address match)",
                        h->mod_name, h->fn_name, mod_name,
                        imgname, import->Name);
                iat_patch((void **)&thunk->u1.Function, func);
            }

skip:
            thunk++;
            othunk++;
        }

        iid++;
    }

    ret = 0;
  out:
    FreeLibrary(module);
    return ret;
}

static int
iat_hook_all_modules(struct iat_hook *h, void *old_func, void *func)
{
    DWORD buf_len;
    HMODULE *modules = NULL;
    DWORD i;
    BOOL rc;

    rc = EnumProcessModules(GetCurrentProcess(), NULL, 0, &buf_len);
    if (!rc)
        return -1;

    modules = alloca(buf_len);

    rc = EnumProcessModules(GetCurrentProcess(), modules, buf_len,
                            &buf_len);
    if (!rc)
        return -1;

    for (i = 0; i < (buf_len / sizeof (HMODULE)); i++) {
        if (modules[i] == hook_mod)
            continue;

        iat_hook_module(modules[i], h, old_func, func);
    }

    return 0;
}

void
iat_hook_remove(struct iat_hook *h)
{
    HOOKDBG("removing hook %s!%s", h->mod_name, h->fn_name);

    if (h->orig_fn) {
        iat_hook_all_modules(h, h->hook_fn, h->orig_fn);
        h->orig_fn = NULL;
    }

    h->hook_fn = NULL;

    *h->pprev = h->next;
    if (h->next)
        h->next->pprev = h->pprev;
    h->next = NULL;
    h->pprev = NULL;
}

int
iat_hook_add(struct iat_hook *h,
             const char *module_name,
             const char *func_name,
             void *func)
{
    HMODULE module;

    HOOKDBG("adding hook %s!%s", module_name, func_name);

    h->mod_name = module_name;
    h->fn_name = func_name;
    h->hook_fn = func;
    h->orig_fn = NULL;

    if (hook_list)
        hook_list->pprev = &h->next;
    h->next = hook_list;
    h->pprev = &hook_list;
    hook_list = h;

    module = GetModuleHandleA(module_name);
    if (module) {
        h->orig_fn = GetProcAddress(module, func_name);
        HOOKDBG("%s is loaded, original proc @ %p, hooking...",
                module_name, h->orig_fn);
        iat_hook_all_modules(h, h->orig_fn, func);
    } else
        HOOKDBG("%s is not yet loaded, skipping...", module_name);

    return 0;
}

static int
fixup_module(HMODULE module, DWORD flags)
{
    struct iat_hook *h;
    char mod_name[512];

    if (module == hook_mod)
        return -1;
    if ((flags & LOAD_LIBRARY_AS_DATAFILE) ||
        (flags & LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE) ||
        (flags & LOAD_LIBRARY_AS_IMAGE_RESOURCE))
        return -1;

    GetModuleBaseName(GetCurrentProcess(),
                      module, mod_name, sizeof (mod_name));
    HOOKDBG("%s loaded, fixing up...", mod_name);

    h = hook_list;
    while (h) {
        HMODULE m;

        if (h->orig_fn)
            iat_hook_module(module, h, h->orig_fn, h->hook_fn);
        else if ((m = GetModuleHandleA(h->mod_name)) &&
                 (h->orig_fn = GetProcAddress(m, h->fn_name)))
            iat_hook_all_modules(h, h->orig_fn, h->hook_fn);

        h = h->next;
    }

    return 0;
}

static struct iat_hook LoadLibraryExA_hook;
static struct iat_hook LoadLibraryExW_hook;
static struct iat_hook GetProcAddress_hook;

static HMODULE WINAPI
hLoadLibraryExA(PCSTR filename, HANDLE file, DWORD flags)
{
    HMODULE module;
    HMODULE WINAPI (*origLoadLibraryExA)(PCSTR, HANDLE, DWORD);

    origLoadLibraryExA = LoadLibraryExA_hook.orig_fn;
    module = origLoadLibraryExA(filename, file, flags);
    if (module)
        fixup_module(module, flags);

    return module;
}

static HMODULE WINAPI
hLoadLibraryExW(PCWSTR filename, HANDLE file, DWORD flags)
{
    HMODULE module;
    HMODULE WINAPI (*origLoadLibraryExW)(PCWSTR, HANDLE, DWORD);

    origLoadLibraryExW = LoadLibraryExW_hook.orig_fn;
    module = origLoadLibraryExW(filename, file, flags);
    if (module)
        fixup_module(module, flags);

    return module;
}

static FARPROC WINAPI
hGetProcAddress(HMODULE module, PCSTR name)
{
    FARPROC WINAPI (*origGetProcAddress)(HMODULE, PCSTR);
    FARPROC proc;

    origGetProcAddress = GetProcAddress_hook.orig_fn;
    proc = origGetProcAddress(module, name);

    if (proc) {
        struct iat_hook *h;

        h = hook_list;
        while (h) {
            if (proc == h->orig_fn) {
                HOOKDBG("returning %s!%s hook", h->mod_name, h->fn_name);
                return h->hook_fn;
            }
            h = h->next;
        }
    }

    return proc;
}

int
iat_hook_init(HMODULE thismodule)
{
    hook_mod = thismodule;
    GetModuleBaseName(GetCurrentProcess(),
                      GetModuleHandleA(NULL),
                      progname, sizeof (progname));

    HOOKDBG("init");

    iat_hook_add(&LoadLibraryExA_hook, "kernelbase.dll", "LoadLibraryExA",
                 hLoadLibraryExA);
    iat_hook_add(&LoadLibraryExW_hook, "kernelbase.dll", "LoadLibraryExW",
                 hLoadLibraryExW);
    iat_hook_add(&GetProcAddress_hook, "kernelbase.dll", "GetProcAddress",
                 hGetProcAddress);

    return 0;
}

void
iat_hook_cleanup(void)
{
    HOOKDBG("cleanup");

    iat_hook_remove(&LoadLibraryExA_hook);
    iat_hook_remove(&LoadLibraryExW_hook);
    iat_hook_remove(&GetProcAddress_hook);
}

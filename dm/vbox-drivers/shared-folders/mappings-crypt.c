/*
 * Copyright 2015, Bromium, Inc.
 * Author: Tomasz Wroblewski <tomasz.wroblewski@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <dm/config.h>
#include <dm/qemu_glue.h>
#include <dm/os.h>
#include <dm/debug.h>
#include <dm/queue.h>

#include <err.h>

#define SUBFOLDER_PATHMAX 256
#define PATH_SEP '\\'
#define PATH_SEP_ALT '/'

typedef struct crypt_mode_entry {
    TAILQ_ENTRY(crypt_mode_entry) entry;

    wchar_t mapname[SUBFOLDER_PATHMAX];
    wchar_t subfolder[SUBFOLDER_PATHMAX];
    int mode;
} crypt_mode_entry_t;

static critical_section crypt_mode_lock;
static TAILQ_HEAD(, crypt_mode_entry) crypt_mode_entries;

static void
clear_crypt_entries(void)
{
    crypt_mode_entry_t *e, *next;

    TAILQ_FOREACH_SAFE(e, &crypt_mode_entries, entry, next) {
        TAILQ_REMOVE(&crypt_mode_entries, e, entry);
        free(e);
    }
}

static void
put_wstr(QEMUFile *f, wchar_t *s)
{
    int len = wcslen(s);

    qemu_put_be32(f, len);
    qemu_put_buffer(f, (uint8_t*)s, len*2);
}

static void
get_wstr(QEMUFile *f, wchar_t *s)
{
    int len = qemu_get_be32(f);

    if (len < SUBFOLDER_PATHMAX) {
        memset(s, 0, SUBFOLDER_PATHMAX * 2);
        qemu_get_buffer(f, (uint8_t*)s, len*2);
    }
}

static void
state_save(QEMUFile *f, void *opaque)
{
    crypt_mode_entry_t *e;
    uint32_t count = 0;

    critical_section_enter(&crypt_mode_lock);
    TAILQ_FOREACH(e, &crypt_mode_entries, entry)
        ++count;
    qemu_put_be32(f, count);
    TAILQ_FOREACH(e, &crypt_mode_entries, entry) {
        put_wstr(f, e->mapname);
        put_wstr(f, e->subfolder);
        qemu_put_be32(f, e->mode);
    }
    critical_section_leave(&crypt_mode_lock);
}

static int
state_load(QEMUFile *f, void *opaque, int version_id)
{
    uint32_t count;

    critical_section_enter(&crypt_mode_lock);
    clear_crypt_entries();
    count = qemu_get_be32(f);
    while (count--) {
        crypt_mode_entry_t *e = calloc(1, sizeof(*e));

        get_wstr(f, e->mapname);
        get_wstr(f, e->subfolder);
        e->mode = qemu_get_be32(f);
        TAILQ_INSERT_TAIL(&crypt_mode_entries, e, entry);

        debug_printf("shared-folders: loaded crypt mode override entry (%ls, %ls, %d)\n",
                     e->mapname, e->subfolder, e->mode);
    }
    critical_section_leave(&crypt_mode_lock);
    return 0;
}

void
sf_crypt_mapping_init(void)
{
    critical_section_init(&crypt_mode_lock);
    TAILQ_INIT(&crypt_mode_entries);
    register_savevm(NULL, "shared-folders-cryptmapping", 0, 0,
                    state_save, state_load, NULL);
}

static int
is_sep(wchar_t c)
{
    return (c == PATH_SEP || c == PATH_SEP_ALT);
}

static int
is_path_prefixof(wchar_t *prefix, wchar_t *path)
{
    while (is_sep(*prefix)) ++prefix;
    while (is_sep(*path)) ++path;

    while (*path && *prefix) {
        if (*path != *prefix)
            return 0;
        ++path;
        ++prefix;
    }

    return ((is_sep(*path) || *path == 0) && *prefix == 0);
}

static void
catpath(wchar_t *buf, wchar_t *path)
{
    int buflen = wcslen(buf);
    wchar_t *p = buf + buflen;

    if (buflen && buf[buflen-1] != PATH_SEP)
        *p++ = PATH_SEP;
    while (*path == PATH_SEP)
        ++path;
    while (*path)
        *p++ = *path++;
}

void
sf_override_crypt_mode(wchar_t *mapname, wchar_t *rootpath, wchar_t *path, int *mode)
{
    crypt_mode_entry_t *e;

    critical_section_enter(&crypt_mode_lock);
    TAILQ_FOREACH(e, &crypt_mode_entries, entry) {
        wchar_t subfolder_fullpath[SUBFOLDER_PATHMAX] = { 0 };

        if (wcslen(rootpath) + wcslen(e->subfolder) >= SUBFOLDER_PATHMAX) {
            warnx("shared-folders: path too long");
            continue;
        }

        catpath(subfolder_fullpath, rootpath);
        catpath(subfolder_fullpath, e->subfolder);

        if (!wcsncmp(mapname, e->mapname, SUBFOLDER_PATHMAX) &&
             is_path_prefixof(subfolder_fullpath, path))
        {
            *mode = e->mode;
            break;
        }
    }
    critical_section_leave(&crypt_mode_lock);
}

static void
to_widestr(char *s, wchar_t *d, int maxchars)
{
    int size = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);

    if (!size || size > maxchars)
        return;
    MultiByteToWideChar(CP_UTF8, 0, s, -1, d, size);
}

static void
del_subfolder_crypt(char *mapname, char *subfolder, int lock)
{
    crypt_mode_entry_t *e, *next;
    wchar_t mapname_w[SUBFOLDER_PATHMAX];
    wchar_t subfolder_w[SUBFOLDER_PATHMAX];
    
    to_widestr(mapname, mapname_w, SUBFOLDER_PATHMAX);
    to_widestr(subfolder, subfolder_w, SUBFOLDER_PATHMAX);

    if (lock)
        critical_section_enter(&crypt_mode_lock);
    TAILQ_FOREACH_SAFE(e, &crypt_mode_entries, entry, next) {
        if (!wcsncmp(mapname_w, e->mapname, SUBFOLDER_PATHMAX) &&
            !wcsncmp(subfolder_w, e->subfolder, SUBFOLDER_PATHMAX))
        {
            TAILQ_REMOVE(&crypt_mode_entries, e, entry);
            free(e);
        }
    }
    if (lock)
        critical_section_leave(&crypt_mode_lock);
}

void
sf_add_subfolder_crypt(char *mapname, char *subfolder, int crypt_mode)
{
    crypt_mode_entry_t *m;

    m = calloc(1, sizeof(*m));
    if (!m)
        errx(1, "out of memory");
    to_widestr(mapname, m->mapname, sizeof(m->mapname) / sizeof(wchar_t));
    to_widestr(subfolder, m->subfolder, sizeof(m->subfolder) / sizeof(wchar_t));
    m->mode = crypt_mode;

    critical_section_enter(&crypt_mode_lock);
    del_subfolder_crypt(mapname, subfolder, 0);
    TAILQ_INSERT_TAIL(&crypt_mode_entries, m, entry);
    critical_section_leave(&crypt_mode_lock);

    debug_printf(
        "shared-folders: subfolder crypt override ADDED (folder %s subfolder %s mode %d)\n",
        mapname, subfolder, crypt_mode);
}

void
sf_del_subfolder_crypt(char *mapname, char *subfolder)
{
    del_subfolder_crypt(mapname, subfolder, 1);
    debug_printf(
        "shared-folders: subfolder crypt override REMOVED (folder %s subfolder %s)\n",
        mapname, subfolder);
}

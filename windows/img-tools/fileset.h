/*
 * This file is part of atg
 * Copyright (c) 2007 Gianni Tedesco
 * Released under the terms of the GNU GPL version 2
*/

#ifndef _FILESET_HEADER_INCLDUED_
#define _FILESET_HEADER_INCLUDED_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fileset *fileset_t;
typedef struct _fsent *fsent_t;

#define FILESET_VOL_BOOT        0
#define FILESET_VOL_SYS         1
#define FILESET_VOL_MAX         2

const char *fsent_path(fsent_t f);
unsigned int fsent_vol(fsent_t f);
unsigned int fsent_prio(fsent_t f);
unsigned int fsent_nlnk(fsent_t f);
const char *fsent_get_link(fsent_t f, unsigned int i, unsigned int *prio);
void fsent_stat(fsent_t f, struct disklib_stat *st);
void fsent_runlist(fsent_t f, const struct disklib_extent **rl,
                   unsigned int *cnt);
void *fsent_get_priv(fsent_t f);
void fsent_set_priv(fsent_t f, void *priv);

int fileset_new(fileset_t *ret, ntfs_fs_t bootvol, ntfs_fs_t sysvol);
ntfs_fs_t fileset_bootvol(fileset_t fs);
ntfs_fs_t fileset_sysvol(fileset_t fs);
fsent_t fileset_insert(fileset_t fs, unsigned int vol, const char *name);
fsent_t fileset_insert_prio(fileset_t fs, unsigned int vol,
                            const char *name, unsigned int prio);
int fileset_manifest(fileset_t fs, fsent_t **man, unsigned int *nmemb);
int fileset_manifest_stable(fileset_t fs, fsent_t **man, unsigned int *nmemb);
void fileset_free(fileset_t fs);

#ifdef __cplusplus
}
#endif

#endif /* _FILESET_HEADER_INCLUDED_ */

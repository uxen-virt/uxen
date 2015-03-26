/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "hfs/hfsplus.h"

#define MAX_PATH_LEN 2048

/* Simple linked-list queue. */
typedef struct QE {
    struct QE *next;
    char name[0];
} QE;

QE *mk_qe(const char *n)
{
    QE *q = malloc(sizeof(QE) + strlen(n) + 1);
    assert(q);
    q->next = NULL;
    strcpy(q->name, n);
    return q;
}

/* Options */
typedef struct {
    bool fail_on_error;
    off_t max_file_size;
    FILE *input_file;
    FILE *output_file;
} Options;

/* Helpers */
static inline void handle_error(const Options *opt, char *message, int err) {
    perror(message);
    if (opt->fail_on_error && ENOENT != err && EBADF != err) {
        exit(err);
    }
}

static inline int valid_name(const char *fn)
{
    for (;*fn; ++fn) {
        if (*fn == '{' || *fn == '}')
            return 0;
    }
    return 1;
}

static inline int list_file(const Options *opt, const char *fn, struct stat *st)
{
    assert(valid_name(fn));

    int type = st->st_mode & 0770000;
    if (type == S_IFCHR || type == S_IFBLK) {
        fprintf(opt->output_file,
                "%o %llu %u %u %u  {%s}\n",
                st->st_mode,
                st->st_ino,
                st->st_uid,
                st->st_gid,
                st->st_rdev,
                fn);
    } else if (type == S_IFLNK) {

        ssize_t len;
        char ln[MAX_PATH_LEN];
        char link[MAX_PATH_LEN];

        char dir[MAX_PATH_LEN];
        strcpy(dir, fn);

        size_t l = strlen(dir);
        while (l > 0 && dir[--l] != '/') {
            dir[l] = '\0';
        }

        if ((len = readlink(fn, ln, sizeof(ln))) >= 0) {
            ln[len] = '\0';

            assert(valid_name(ln));

            if (ln[0] == '/') {
                strcpy(link, ln);
            } else {
                strcpy(link, dir);
                if (link[strlen(link) - 1] != '/') {
                    strcat(link, "/");
                }
                strcat(link, ln);
            }
        } else {
            handle_error(opt, "readlink", errno);
        }

        fprintf(opt->output_file,
                "%o %llu %u %u %llu {%s} -> {%s}\n",
                st->st_mode,
                st->st_ino,
                st->st_uid,
                st->st_gid,
                st->st_size,
                fn,
                link);
    } else {
        if (opt->max_file_size && S_ISREG(st->st_mode) && st->st_size > opt->max_file_size) {
            fprintf(stderr,
                    "warning: ignoring file '%s' whose size %lld "
                    "is above the threshold of %lld.\n",
                    fn,
                    st->st_size,
                    opt->max_file_size);
        } else {
            fprintf(opt->output_file,
                    "%o %llu %u %u %llu {%s}\n",
                    st->st_mode,
                    st->st_ino,
                    st->st_uid,
                    st->st_gid,
                    st->st_size,
                    fn);
        }
    }

    return 0;
}


/* Breadth-first search directory scan. This is faster than DFS due to better
 * access locality. The tools that consume output from BFS also expect all
 * files in a directory to get listed right after the directory's entry, to
 * optimize file creation. */

int bfs(const Options *opt, const char *dn)
{
    QE *q = mk_qe(dn);
    QE *tail = q;

    while (q) {
        struct stat st;
        struct dirent *ent;
        DIR *dir;

        if (lstat(q->name, &st) >= 0) {
            list_file(opt, q->name, &st);

            if ((st.st_mode & 0770000) == S_IFDIR) {
               /* directory */
                if (NULL != (dir = opendir(q->name))) {
                    /* We use chdir here to be able to do local lookups. */
                    if(0 != chdir(q->name)) {
                        handle_error(opt, q->name, errno);
                    }

                    while ((ent = readdir(dir))) {
                        char full_name[MAX_PATH_LEN];

                        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
                            continue;

                        if (lstat(ent->d_name, &st) < 0) {
                            fprintf(stderr, "dir=%s\n", q->name);

                            handle_error(opt, ent->d_name, errno);
                            continue;
                        }
                        sprintf(full_name, "%s/%s", q->name, ent->d_name);

                        if ((st.st_mode & 0770000) == S_IFDIR) {

                            char name[MAX_PATH_LEN];
                            sprintf(name, "%s/%s", q->name, ent->d_name);
                            tail->next = mk_qe(name);
                            tail = tail->next;

                        } else {
                            list_file(opt, full_name, &st);
                        }
                    }
                    closedir(dir);
                } else {
                    handle_error(opt, q->name, errno);
                }
            }
        } else {
            handle_error(opt, q->name, errno);
        }

        QE *p = q;
        q = q->next;
        free(p);
    }

    return 0;
}

static void usage(char **argv)
{
    fprintf(stderr, "Usage: %s [-h|-e] [INPUT-FILE [OUTPUT-FILE]]\n", argv[0]);
    fprintf(stderr, "        -h: Print this message and exit.\n");
    fprintf(stderr, "        -e: Exit on errors (except ENOENT and EBADF).\n");
}

int main(int argc, char **argv)
{
    /* Consume a whitelist of dir names from stdin. Output a list of file
     * meta-data suitable for passing to img-shallow on stdout. */

    int r = 0;
    char fn[MAX_PATH_LEN];
    Options opt = {0};
    int option = 0;

    opt.fail_on_error = FALSE;
    opt.input_file = stdin;
    opt.output_file = stdout;
    opt.max_file_size = 0; /* 0 means no maximum file size */

    while ((option = getopt(argc, argv, "em:h")) != -1) {
        switch (option) {
            case 'e':
                opt.fail_on_error = TRUE;
                break;
            case 'm': {
                opt.max_file_size = (off_t)atol(optarg);
                break;
            }
            case 'h':
            default:
                usage(argv);
                exit(1);
                break;
        }
    }

    if (optind < argc) {
        char *arg = argv[optind++];

        if (0 != strcmp(arg, "-")) { /* "-" means stdin */
            opt.input_file = fopen(arg, "r");
            if (!opt.input_file) {
                perror(arg);
                exit(1);
            }
        }
    }

    if (optind < argc) {
        char *arg = argv[optind++];

        if (strcmp(arg, "-") != 0) { /* "-" means stdout */
            opt.output_file = fopen(arg, "w");
            if (!opt.output_file) {
                perror(arg);
                exit(1);
            }
        }
    }

    /*
    fprintf(stdout, "Options: fail_on_error: %s, stdin: %s, stdout: %s\n",
            opt.fail_on_error         ? "YES" : "NO",
            stdin == opt.input_file   ? "YES":  "NO",
            opt.output_file == stdout ? "YES" : "NO");
     */

    while (fgets(fn, sizeof(fn), opt.input_file) && r >= 0) {
        size_t l = strlen(fn);
        if (fn[l - 1] == '\n') {
            fn[l - 1] = '\0';
        }
        if (fn[0] && fn[0] != '#') {
            r = bfs(&opt, fn);
        }
    }
    if (r < 0) {
        fprintf(stderr, "%s exiting with error %d\n", argv[0], r);
    }
    return r;
}

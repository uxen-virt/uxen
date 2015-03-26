/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <assert.h>
#include <dirent.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <unistd.h>
#include <getopt.h>

#include "abstractfile.h"
#include "hfs/hfslib.h"
#include "hfs/hfsplus.h"
#include "shallow.h"

#define MAX_PATH_LEN 2048
char endianness;

void TestByteOrder()
{
    short int word = 0x0001;
    char *byte = (char *) &word;
    endianness = byte[0] ? IS_LITTLE_ENDIAN : IS_BIG_ENDIAN;
}

typedef struct ShallowInfo {
    size_t size;
    off_t offset;
    uint64_t inode;
    char filename[];
} ShallowInfo;

size_t shallowRead(AbstractFile* af, void* data, size_t len) {
    ShallowInfo *si = (ShallowInfo*) af->data;
    sprintf(data, "%s%llu-%llu-%s", shallow_get_magic(), si->offset,
            si->inode, si->filename);
    si->offset += len;
    return len;
}

size_t shallowWrite(AbstractFile* af, const void* data, size_t len) {
    assert(0);
    return len;
}

int shallowSeek(AbstractFile* af, off_t offset) {
    assert(0);
    return 0;
}

off_t shallowTell(AbstractFile* af) {
    ShallowInfo *si = (ShallowInfo*) af->data;
    return si->offset;
}

void shallowClose(AbstractFile* af) {
    free(af->data);
    free(af);
}

off_t shallowGetLength(AbstractFile* af)
{
    ShallowInfo *si = (ShallowInfo*) af->data;
    return si->size;
}

AbstractFile* createShallowFile(const char *filename, size_t size, uint64_t inode)
{
    AbstractFile* af;
    ShallowInfo *si;
    af = (AbstractFile*) malloc(sizeof(AbstractFile));
    si = malloc(sizeof(ShallowInfo) + strlen(filename) + 1);
    assert(si);
    strcpy(si->filename, filename);
    si->size = size;
    si->inode = inode;
    si->offset = 0;

    af->data = (void*) si;
    af->read = shallowRead;
    af->write = shallowWrite;
    af->seek = shallowSeek;
    af->tell = shallowTell;
    af->getLength = shallowGetLength;
    af->close = shallowClose;
    af->type = AbstractFileTypeDummy;
    return af;
}

int make_dir(char* dn, Volume *volume, int mode, int line)
{
    if (!newFolder(dn, volume, mode, 0, 0)) {
        /* fall back to mkdir -p only if needed */
        char *part;
        char *c;

        for (part = dn; *part; part = c + 1) {
            c = part;
            while (*c && *c != '/') {
                ++c;
            }
            char old = *c;
            *c = '\0';
            if (!newFolder(dn, volume, mode, 0, 0)) {
                fprintf(stderr, "line %d: can't mkdir %s\n", line, dn);
                exit(-1);
            }
            *c = old;
        }
    }
    return 0;
}

static void usage(char **argv)
{
    fprintf(stderr, "usage: %s [-d|--deep] [-p|--progress PROGRESS-FILE] [-m|--manifest MANIFEST] IMAGE-NAME\n", argv[0]);
    fprintf(stderr, "If no MANIFEST is given, stdin is used instead.\n");
}

int main(int argc, char **argv)
{
	io_func* io;
	Volume* volume;
	TestByteOrder(); /* HFS+ lib needs this. */
    char dir[MAX_PATH_LEN] = "";
    HFSPlusCatalogFolder* parentFolder = NULL;
    FILE *manifestFile = stdin;
    char *manifestPath = NULL;
    FILE *progressFile = NULL;
    char *progressFilePath = NULL;
    int line;
    int deep = 0;

    while (1) {
        int c, index = 0;

        static struct option long_options[] = {
            {"help",          no_argument,       NULL, 'h'},
            {"deep",          no_argument,       NULL, 'd'},
            {"shallow",       no_argument,       NULL, 's'},
            {"progress",      required_argument, NULL, 'p'},
            {"manifest",      required_argument, NULL, 'm'},
            {NULL,            0,                 NULL,  0 },
        };

        c = getopt_long(argc, argv, "hdsp:m:", long_options, &index);

        if (c == -1) {
            break;
        }

        switch (c) {
            case '?':
            case -1:
            case 'h':
                usage(argv);
                exit(1);
                break;
            case 'd':
                deep = 1;
                break;
            case 's':
                deep = 0;
                break;
            case 'p':
                progressFilePath = optarg;
                break;
            case 'm':
                manifestPath = optarg;
                break;
        }
    }

    if (argc - optind != 1) {
        usage(argv);
        exit(-1);
    }

	io = openFlatFile(argv[optind]);
	if(io == NULL) {
		fprintf(stderr, "error: Cannot open image-file `%s'.\n", argv[optind]);
		return 1;
	}

	volume = openVolume(io); 
	if(volume == NULL) {
		fprintf(stderr, "error: Cannot open volume.\n");
		CLOSE(io);
		return 1;
	}

    if (progressFilePath) {
        progressFile = fopen(progressFilePath, "w");

        if (!progressFile) {
            perror(progressFilePath);
            exit(-1);
        }
    }

    if (manifestPath) {
        manifestFile = fopen(manifestPath, "r");

        if (!manifestFile) {
            perror(manifestPath);
            exit(-1);
        }
    }

    /* Loop over the manifest file. Count lineno from 1, as this is
     * what editors (at least VI) expect. */

    for (line = 1; ; ++line) {
        int mode;
        uint16_t uid, gid;
        size_t size;
        uint64_t inode;
        char fn[MAX_PATH_LEN];
        char dest[MAX_PATH_LEN];
        int stop = 0;

        if (!(line & 0xfff)) {
            fprintf(stderr, "line=%d\n", line);
            if (progressFile) {
                fprintf(progressFile, "%d\n", line);
                fflush(progressFile);
            }
        }

        /* The dest argument is optional, only needed for symlinks. */
        dest[0] = '\0';
        if (fscanf(manifestFile, "%o %llu %hu %hu %zu {%[^}]} -> {%[^}]}\n",
                   &mode, &inode, &uid, &gid, &size, fn, dest) < 5) {
            if (feof(manifestFile)) {
                fprintf(stderr, "EOF on line %d\n", line);
                stop = 1;
            } else {
                fprintf(stderr, "error: invalid input in line %d\n", line);
                return 1;
            }
        }

        int type = mode & 0770000;

        if (stop || type == S_IFDIR) {

            /* This is either a directory, an absolute path file, or manifest
             * EOF. In all cases we need to finish the currently active
             * directory. */

            if (parentFolder) {
                updateCatalog(volume, (HFSPlusCatalogRecord*) parentFolder);
                free(parentFolder);
                parentFolder = NULL;
                dir[0] = '\0';
            }

            if (stop)
                break;
        }

        if (type == S_IFLNK) {

            makeSymlink(fn, dest, volume);

        } else if (type == S_IFDIR) {

            strcpy(dir, fn);
            make_dir(fn, volume, mode, line);
            parentFolder = (HFSPlusCatalogFolder*) getRecordFromPath(fn, volume, NULL, NULL);
            assert(parentFolder);

        } else if (type != S_IFIFO && type != S_IFSOCK) {

            AbstractFile *af;

            if (deep) {
                FILE *f = fopen(fn, "rb");
                if (!f) {
                    perror(fn);
                    continue;
                }
                af = createAbstractFileFromFile(f);
            } else {
                af = createShallowFile(fn, size, inode);
            }
            assert(af);

            char *c;
            char *slash;
            for (c = fn, slash = NULL; *c; ++c) {
                if (*c == '/')
                    slash = c;
            }
            assert(slash);
            assert(dir);

            if (parentFolder && slash != fn && strncmp(fn, dir, MAX(strlen(dir), slash-fn)) == 0) {
                uint32_t rdev = 0;
                if (type == S_IFCHR || type == S_IFBLK) {
                    rdev = (uint32_t) size;
                    size = 0;
                }

                HFSPlusCatalogFile *file = newFileInFolder(slash + 1, volume, parentFolder, mode, uid, gid, rdev);
                assert(file);

                if (rdev == 0) {
                    writeToHFSFile(file, af, volume);
                }
                free(file);
                af->close(af);

            } else {
                fprintf(stderr, "line %d: directly adding %s\n", line, fn);
                add_hfs(volume, af, fn);
                chmodFile(fn, mode, false, volume);
            }

        }
    }

    if (progressFile) {
        fclose(progressFile);
    }
	closeVolume(volume);
	CLOSE(io);
    return 0;
}

/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <hfs/hfsplus.h>
#include <dirent.h>

#include <hfs/hfslib.h>
#include "common.h"
#include "abstractfile.h"
#include <inttypes.h>

char endianness;


static int cmd_ls(Volume* volume, int argc, const char *argv[]) {
	if(argc > 1)
		hfs_ls(volume, argv[1]);
	else
		hfs_ls(volume, "/");
	return 0;
}

static int cmd_find(Volume* volume, int argc, const char *argv[]) {
	if(argc > 1)
		hfs_find(volume, argv[1]);
	else
		hfs_find(volume, "/");
	return 0;
}

static int cmd_cat(Volume* volume, int argc, const char *argv[]) {
	int ret;
	HFSPlusCatalogRecord* record;
	AbstractFile* stdoutFile;

	record = getRecordFromPath(argv[1], volume, NULL, NULL);

	stdoutFile = createAbstractFileFromFile(stdout);
	if(record != NULL) {
		if(record->recordType == kHFSPlusFileRecord) {
			writeToFile((HFSPlusCatalogFile*)record, stdoutFile, volume);
			ret = 0;
		} else {
			printf("Not a file\n");
			ret = -ENOENT;
		}
	} else {
		printf("No such file or directory\n");
		ret = -ENOENT;
	}

	free(record);
	free(stdoutFile);
	return ret;
}

static int cmd_extract(Volume* volume, int argc, const char *argv[]) {
	int ret;
	HFSPlusCatalogRecord* record;
	AbstractFile *outFile;

	if(argc < 3) {
		printf("Not enough arguments");
		return -EINVAL;
	}

	outFile = createAbstractFileFromFile(fopen(argv[2], "wb"));

	if(outFile == NULL) {
		printf("cannot create file");
		return -EINVAL;
	}

	record = getRecordFromPath(argv[1], volume, NULL, NULL);

	if(record != NULL) {
		if(record->recordType == kHFSPlusFileRecord) {
			writeToFile((HFSPlusCatalogFile*)record, outFile, volume);
			ret = 0;
		} else {
			printf("Not a file\n");
			ret = -ENOENT;
		}
	} else {
		printf("No such file or directory\n");
		ret = -ENOENT;
	}

	outFile->close(outFile);
	free(record);
	return ret;
}

static int cmd_mv(Volume* volume, int argc, const char *argv[]) {
	int ret;
	if(argc > 2) {
		ret = (move(argv[1], argv[2], volume) == TRUE) ? 0 : -EACCES;
	} else {
		printf("Not enough arguments");
		ret = -EINVAL;
	}
	return ret;
}

static int cmd_symlink(Volume* volume, int argc, const char *argv[]) {
	int ret;
	if(argc > 2) {
		ret = (makeSymlink(argv[1], argv[2], volume) == TRUE) ? 0 : -EACCES;
	} else {
		printf("Not enough arguments");
		ret = -EINVAL;
	}
	return ret;
}

static int cmd_mkdir(Volume* volume, int argc, const char *argv[]) {
	int ret;
	if(argc > 1) {
		newFolder(argv[1], volume, 0, 0, 0);
		ret = 0;
	} else {
		printf("Not enough arguments");
		ret = -EINVAL;
	}
	return ret;
}

static int cmd_add(Volume* volume, int argc, const char *argv[]) {
	int ret;
	AbstractFile *inFile;

	if(argc < 3) {
		printf("Not enough arguments");
		return -EINVAL;
	}

	inFile = createAbstractFileFromFile(fopen(argv[1], "rb"));

	if (inFile) {
		ret = (add_hfs(volume, inFile, argv[2]) == TRUE) ? 0 : -EACCES;
	} else {
		printf("file to add not found");
		ret = -ENOENT;
	}
	return ret;
}

static int cmd_rm(Volume* volume, int argc, const char *argv[]) {
        int ret = 0;
        char *file = NULL;
        bool ignore_missing_files = FALSE;

        switch(argc) {
            case 2:
                file = (char *)argv[1];
                break;
            case 3:
                if (strcmp(argv[1], "-f")) {
                    fprintf(stderr, "Unrecognised parameter: %s\n", argv[1]);
                    abort();
                }
                ignore_missing_files = TRUE;
                file = (char *)argv[2];
                break;
            default:
                fprintf(stderr, "Unexpected number of arguments: %d\n", argc);
                abort();
        }

        ret = removeFile(file, ignore_missing_files, volume);
        if (ret == FALSE) {
            fprintf(stderr, "removeFile failed for %s\n", file);
            abort();
        }
        return 0; // here ret must be TRUE, so return 0
}

static int cmd_chmod(Volume* volume, bool recurse, int argc, const char *argv[]) {
	int ret;
	int mode;

	if(argc > 2) {
		sscanf(argv[1], "%o", &mode);
		ret = (chmodFile(argv[2], mode, recurse, volume) == TRUE) ? 0 : -EACCES;
	} else {
		printf("Not enough arguments");
		ret = -EINVAL;
	}
	return ret;
}

static int cmd_chown(Volume* volume, bool recurse, int argc, const char *argv[]) {
	int ret;
	uint32_t user_id;
	uint32_t group_id;

	if(argc > 3) {
		sscanf(argv[1], "%d", &user_id);
		sscanf(argv[2], "%d", &group_id);
		ret = (chownFile(argv[3], user_id, group_id, recurse, volume) == TRUE) ? 0 : -EACCES;
	} else {
		printf("Not enough arguments");
		ret = -EINVAL;
	}
	return ret;
}

static int cmd_extractall(Volume* volume, int argc, const char *argv[]) {
	HFSPlusCatalogRecord* record;
	char cwd[1024];
	char* name;
	int ret;

	ASSERT(getcwd(cwd, 1024) != NULL, "cannot get current working directory");

	if(argc > 1)
		record = getRecordFromPath(argv[1], volume, &name, NULL);
	else
		record = getRecordFromPath("/", volume, &name, NULL);

	if(argc > 2) {
		ASSERT(chdir(argv[2]) == 0, "chdir");
	}

	if(record != NULL) {
		if(record->recordType == kHFSPlusFolderRecord) {
			extractAllInFolder(((HFSPlusCatalogFolder*)record)->folderID, volume);
			ret = 0;
		} else {
			printf("Not a folder\n");
			ret = -ENOENT;
		}
	} else {
		printf("No such file or directory\n");
		ret = -ENOENT;
	}
	free(record);

	ASSERT(chdir(cwd) == 0, "chdir");
	return ret;
}


static int cmd_rmall(Volume* volume, int argc, const char *argv[]) {
	HFSPlusCatalogRecord* record;
	char* name;
	char initPath[1024];
	int lastCharOfPath;
	int ret;
	
	if(argc > 1) {
		record = getRecordFromPath(argv[1], volume, &name, NULL);
		strcpy(initPath, argv[1]);
		lastCharOfPath = strlen(argv[1]) - 1;
		if(argv[1][lastCharOfPath] != '/') {
			initPath[lastCharOfPath + 1] = '/';
			initPath[lastCharOfPath + 2] = '\0';
		}
	} else {
		record = getRecordFromPath("/", volume, &name, NULL);
		initPath[0] = '/';
		initPath[1] = '\0';	
	}
	
	if(record != NULL) {
		if(record->recordType == kHFSPlusFolderRecord) {
			removeAllInFolder(((HFSPlusCatalogFolder*)record)->folderID, volume, initPath);
			ret = 0;
		} else {
			printf("Not a folder\n");
			ret = -ENOENT;
		}
	} else {
		printf("No such file or directory\n");
		ret = -ENOENT;
	}
	free(record);
	return ret;
}

static int cmd_addall(Volume* volume, int argc, const char *argv[]) {
	if(argc < 2) {
		printf("Not enough arguments");
		return -EINVAL;
	}

	if(argc > 2) {
		addall_hfs(volume, argv[1], argv[2]);
	} else {
		addall_hfs(volume, argv[1], "/");
	}
	return 0;
}

static int cmd_grow(Volume* volume, int argc, const char *argv[]) {
	uint64_t newSize;

	if(argc < 2) {
		printf("Not enough arguments\n");
		return -EINVAL;
	}
	
	newSize = 0;
	sscanf(argv[1], "%" PRId64, &newSize);

	grow_hfs(volume, newSize);

	printf("grew volume: %" PRId64 "\n", newSize);
	return 0;
}

static void TestByteOrder()
{
	short int word = 0x0001;
	char *byte = (char *) &word;
	endianness = byte[0] ? IS_LITTLE_ENDIAN : IS_BIG_ENDIAN;
}


int main(int argc, const char *argv[]) {
	io_func* io;
	Volume* volume;
	
	TestByteOrder();
	
	if(argc < 3) {
		printf("usage: %s <image-file> <ls|find|cat|mv|mkdir|add|rm|chmod|chmodr|chown|chownr|extract|extractall|rmall|addall|debug> <arguments>\n", argv[0]);
		return 0;
	}
	
	io = openFlatFile(argv[1]);
	if(io == NULL) {
		fprintf(stderr, "error: Cannot open image-file.\n");
		return 1;
	}
	
	volume = openVolume(io); 
	if(volume == NULL) {
		fprintf(stderr, "error: Cannot open volume.\n");
		CLOSE(io);
		return 1;
	}

	int ret;
	if(argc > 1) {
		if(strcmp(argv[2], "ls") == 0) {
			ret = cmd_ls(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "find") == 0) {
			ret = cmd_find(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "cat") == 0) {
			ret = cmd_cat(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "mv") == 0) {
			ret = cmd_mv(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "symlink") == 0) {
			ret = cmd_symlink(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "mkdir") == 0) {
			ret = cmd_mkdir(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "add") == 0) {
			ret = cmd_add(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "rm") == 0) {
			ret = cmd_rm(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "chmod") == 0) {
			ret = cmd_chmod(volume, false, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "chown") == 0) {
			ret = cmd_chown(volume, false, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "chmodr") == 0) {
			ret = cmd_chmod(volume, true, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "chownr") == 0) {
			ret = cmd_chown(volume, true, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "extract") == 0) {
			ret = cmd_extract(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "extractall") == 0) {
			ret = cmd_extractall(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "rmall") == 0) {
			ret = cmd_rmall(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "addall") == 0) {
			ret = cmd_addall(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "grow") == 0) {
			ret = cmd_grow(volume, argc - 2, argv + 2);
		} else if(strcmp(argv[2], "debug") == 0) {
			if(argc > 3 && strcmp(argv[3], "verbose") == 0) {
				ret = debugBTree(volume->catalogTree, TRUE);
			} else {
				ret = debugBTree(volume->catalogTree, FALSE);
			}
		} else {
			fprintf(stderr, "error: unrecognized option %s.\n", argv[2]);
			ret = -EINVAL;
		}
	} else {
		fprintf(stderr, "error: insufficient args.\n");
		ret = -EINVAL;
	}

	closeVolume(volume);
	CLOSE(io);

	return ret;
}

/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

//
//  main.c
//  cow-setting
//
//  Created by Phil Jordan on 19/02/2013.
//  Copyright (c) 2013 Bromium UK Ltd. All rights reserved.
//

#include "cow-user.h"
#include <stdio.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


int main(int argc, const char *argv[])
{
    const char *wd;
    if (argc < 2) {
        wd = getcwd(NULL, 0);
    } else {
        wd = argv[1];
    }

    int fd = cow_connect_socket();
    if (fd < 0) {
        fprintf(stderr, "Failed to connect to kernel control socket\n");
        return 1;
    }

    int err = cow_set_target_path(fd, wd);
    if (err != 0) {
        fprintf(stderr,
                "Failed to set target directory directory: %d (%s)\n", err,
                strerror(err));
        close(fd);
        return 1;
    }

    uint64_t *file_ids = NULL;
    uint32_t num_file_ids = 0;
    char buffer[MAXPATHLEN] = "";
    char *line = NULL;
    do {
        line = fgets(buffer, sizeof(buffer), stdin);

        if (line) {
#if 0
            size_t len = strnlen(buffer, sizeof(buffer));
            if (len > 1) {
                if (buffer[len - 1] == '\n')
                    buffer[len - 1] = '\0';

                struct stat file_stat;
                int check_stat = 0;
                check_stat = stat(buffer, &file_stat);
                long i_node_num = 0;
                if (check_stat == 0) {
                    i_node_num = file_stat.st_ino;
                    file_ids =
                        realloc(file_ids,
                                sizeof(file_ids[0]) * (num_file_ids + 1));
                    file_ids[num_file_ids] = i_node_num;
                    num_file_ids++;
                } else {
                    fprintf(stderr, "stat(%s) error: %d (%s)\n", buffer,
                            errno, strerror(errno));
                }
            }
#endif
            uint64_t inode;
            if (sscanf(line, "%llu\n", &inode) == 1) {
                size_t realloc_size = sizeof(file_ids[0]) * (num_file_ids +1);
                uint64_t *bigger_buffer = realloc(file_ids, realloc_size);
                if (!bigger_buffer) {
                    fprintf(stderr, "Failed file_ids realloc\n");
                    free(file_ids);
                    return 1;
                }
                file_ids = bigger_buffer;
                file_ids[num_file_ids] = inode;
                num_file_ids++;
            }
        }
    } while (line && num_file_ids < UINT32_MAX);

    for (int i = 0; i < num_file_ids; i++) {
        printf("%llu\n", file_ids[i]);
    }

    err = cow_set_watchlist(fd, file_ids, num_file_ids);
    if (err != 0) {
        fprintf(stderr, "Failed to set watch list: %d (%s)\n", err,
                strerror(err));
        close(fd);
        return 1;
    }

    err = cow_start_receiving_file_events(fd);
    if (err != 0) {
        fprintf(stderr,
                "Failed to request file event notifications: %d (%s)\n",
                err, strerror(err));
        close(fd);
        return 1;
    }

    struct copy_on_write_msg msg;
    while (true) {
        ssize_t len = recv(fd, &msg, sizeof(msg), 0);
        if (len < sizeof(msg))
            break;
        printf("Event: %s file with ID %10llu (%u dropped messages)\n",
               msg.msg_type ==
               COW_MSG_FileCopied ? "   copied" : msg.msg_type ==
               COW_MSG_FileReLinked ? " relinked" : "[unknown]",
               msg.file_id, msg.dropped_messages);
    }

    return 0;
}

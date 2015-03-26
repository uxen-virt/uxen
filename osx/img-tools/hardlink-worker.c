/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

//
//  hardlink-worker.c
//  cow-hardlink-worker
//
//  Created by Phillip Jordan on 25/02/2013.
//  Copyright (c) 2013 Bromium UK Ltd. All rights reserved.
//

#include "../img-tools/cow-user.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/errno.h>
#include <stdbool.h>

int main(int argc, const char * argv[])
{
	const char* wd;
	if (argc < 2)
	{
		wd = getcwd(NULL, 0);
	}
	else
	{
		wd = argv[1];
	}
	
	int fd = cow_connect_socket();
	if (fd < 0)
	{
		fprintf(stderr, "Failed to connect to kernel control socket\n");
		return 1;
	}
	
	int result = 0;
	while (true)
	{
		// register to wait for link requests, fulfil them and report success/failure
		copy_on_write_link_request_t rq = {};
		int err = cow_wait_for_link_request(fd, &rq);
		
		if (err != 0)
		{
			if(err != ESHUTDOWN)
			{
				printf("error %d (%s)\n", err, strerror(err));
				result = 1;
			}
			break;
		}
		
		uint64_t fileID = rq.file_id;
		copy_on_write_link_response_t res = { .file_id = rq.file_id };
		char suffix[] = ".link";
		size_t dest_path_len = strlen(wd) + 20 /*id len */ + sizeof(suffix);

		char dest_path[dest_path_len];
		dest_path[0] = '\0';

		snprintf(dest_path, dest_path_len, "%s/%llu%s", wd, fileID, suffix);
		printf("new file path is %s\n", dest_path);

		err = link(rq.file_path, dest_path);
		if (err == 0)
		{
			struct stat dest_stat = {};
			err = stat(dest_path, &dest_stat);
			if (err == 0 /* && dest_stat.st_ino == rq.file_id */)
			{
				//success
				res.flags = 0;
			}
			else
			{
                perror("Failed to stat new hard link");
				//Fail
				res.flags = 1;
			}

		}
		else
		{
			// fail
            perror("Failed to create new hard link");
			res.flags = 1;
		}
		
		err = cow_send_link_response(fd, &res);
	}
	close(fd);
	return 0;
}


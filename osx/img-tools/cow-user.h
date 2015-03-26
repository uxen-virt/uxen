/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

//
//  cow-user.h
//  copy-on-write
//
//  Created by Phillip Jordan on 25/02/2013.
//  Copyright (c) 2013 Bromium UK Ltd. All rights reserved.
//

#ifndef copy_on_write_cow_user_h
#define copy_on_write_cow_user_h

#include "../cow-kext/copy-on-write-shared.h"

int cow_connect_socket(void);
int cow_set_target_path(int fd, const char *path);
int cow_set_watchlist(int fd, const uint64_t * file_ids,
                      uint32_t num_file_ids);
int cow_start_receiving_file_events(int fd);
int cow_stop_receiving_file_events(int fd);

// Returns 0 for valid link request, ESHUTDOWN if kext is shutting down, or other error
int cow_wait_for_link_request(int fd, copy_on_write_link_request_t * rq);

// Returns 0 for valid link response, ESHUTDOWN if kext is shutting down, or other error
int cow_send_link_response(int fd,
                           const copy_on_write_link_response_t * res);


#endif

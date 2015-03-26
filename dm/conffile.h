/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _CONFFILE_H_
#define _CONFFILE_H_

struct conffile;

struct conffile *config_load(const char *name);
struct conffile *config_string(const char *string);
struct conffile *config_default(void);
void config_free_input(struct conffile *cf);
void config_free(struct conffile *cf);
int config_parse(struct conffile *cf);

#endif	/* _CONFFILE_H_ */

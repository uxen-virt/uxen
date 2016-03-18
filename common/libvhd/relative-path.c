/*
 * Copyright (c) 2007, XenSource Inc.
 * Copyright (c) 2010, Citrix Systems, Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2016, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <ctype.h>
#endif  /* _WIN32 */

#include "relative-path.h"
#include "util.h"

#define DELIMITER '/'
#define DELIMITER_STR "/"

#define sfree(ptr)         \
do {                       \
	free(ptr);         \
	ptr = NULL;        \
} while (0)

/*
 * count number of tokens between DELIMETER characters
 */
static int
count_nodes(char *path)
{
	int i = 0;
	char *tmp;

	if (!path)
		return 0;

	if (*path != DELIMITER)
		i++;

	for (tmp = path; *tmp != '\0'; tmp++)
		if (*tmp == DELIMITER)
			i++;

	return i;
}

/*
 * return copy of next node in @path, or NULL
 * @path is moved to the end of the next node
 * @err is set to -errno on failure
 * copy should be freed
 */
static char *
next_node(char **path, int *err)
{
	char *tmp, *start;

	if (!path || !*path) {
		*err = -EINVAL;
		return NULL;
	}

	while (**path == DELIMITER)
		(*path)++;

	*err  = 0;
	start = *path;

	for (tmp = *path; *tmp != '\0'; tmp++)
		if (*tmp == DELIMITER) {
			int size;
			char *node;

			size = tmp - start;
			node = malloc(size + 1);
			if (!node) {
				*err = -ENOMEM;
				return NULL;
			}

			(void)strncpy(node, start, size);
			node[size] = 0;

			*path = tmp;
			return node;
		}

	return NULL;
}

/*
 * count number of nodes in common betwee @to and @from
 * returns number of common nodes, or -errno on failure
 */
static int
count_common_nodes(char *to, char *from)
{
	int err, common;
	char *to_node, *from_node;

	if (!to || !from)
		return -EINVAL;

	err       = 0;
	common    = 0;
	to_node   = NULL;
	from_node = NULL;

	do {
		to_node = next_node(&to, &err);
		if (err || !to_node)
			break;

		from_node = next_node(&from, &err);
		if (err || !from_node)
			break;

		if (strncmp(to_node, from_node, MAX_NAME_LEN))
			break;

		++to;
		++from;
		++common;
		sfree(to_node);
		sfree(from_node);

	} while (1);

	sfree(to_node);
	sfree(from_node);

	if (err)
		return err;

	return common;
}

/*
 * construct path of @count "../", "" if @count is zero, or NULL on error
 * result should be freed
 */
/* static */ char *
up_nodes(int count)
{
	char *path, *tmp;
	int i, ret, len, size;

	if (!count)
		return strdup("");

	len  = strlen(".." DELIMITER_STR);
	size = len * count;
	if (size >= MAX_NAME_LEN)
		return NULL;

	path = malloc(size + 1);
	if (!path)
		return NULL;

	tmp = path;
	for (i = 0; i < count; i++) {
		ret = sprintf(tmp, ".." DELIMITER_STR);
		if (ret < 0 || ret != len) {
			free(path);
			return NULL;
		}
		tmp += ret;
	}

	return path;
}

/*
 * return pointer to @offset'th node of path or NULL on error
 */
static char *
node_offset(char *from, int offset)
{
	char *path;

	if (!from || !offset)
		return NULL;

	if (*from != DELIMITER)
		if (--offset == 0)
			return from;

	for (path = from; *path != '\0'; path++) {
		if (*path == DELIMITER)
			if (--offset == 0)
				return path + 1;
	}

	return NULL;
}

/*
 * return a relative path from @from to @to
 * result should be freed
 */
char *
relative_path_to(char *from, char *to, int *err)
{
	int from_nodes, common;
	char *to_absolute, *from_absolute;
	char *up, *common_target_path, *relative_path;

	*err          = 0;
	up            = NULL;
	to_absolute   = NULL;
	from_absolute = NULL;
	relative_path = NULL;

	if (strnlen(to, MAX_NAME_LEN)   == MAX_NAME_LEN ||
	    strnlen(from, MAX_NAME_LEN) == MAX_NAME_LEN) {
		EPRINTF("invalid input; max path length is %d\n",
			MAX_NAME_LEN);
		*err = -ENAMETOOLONG;
		return NULL;
	}

	to_absolute = realpath_null(to);
	if (!to_absolute) {
		EPRINTF("failed to get absolute path of %s\n", to);
		*err = -errno;
		goto out;
	}

	from_absolute = realpath_null(from);
	if (!from_absolute) {
		EPRINTF("failed to get absolute path of %s\n", from);
		*err = -errno;
		goto out;
	}

	if (strnlen(to_absolute, MAX_NAME_LEN)   == MAX_NAME_LEN ||
	    strnlen(from_absolute, MAX_NAME_LEN) == MAX_NAME_LEN) {
		EPRINTF("invalid input; max path length is %d\n",
			MAX_NAME_LEN);
		*err = -ENAMETOOLONG;
		goto out;
	}

	/* count nodes in source path */
	from_nodes = count_nodes(from_absolute);

	/* count nodes in common */
	common = count_common_nodes(to_absolute, from_absolute);
	if (common < 0) {
		EPRINTF("failed to count common nodes of %s and %s: %d\n",
			to_absolute, from_absolute, common);
		*err = common;
		goto out;
	}

        if (!common) {
#if defined(_WIN32)
            /* on win32, make files relative as long as they have the
             * same drive letter */
            if (to_absolute[1] != ':' || from_absolute[1] != ':' ||
                toupper(from_absolute[0]) != toupper(to_absolute[0]))
#endif  /* _WIN32 */
            {
                relative_path = to_absolute;
                to_absolute = NULL;
                goto out;
            }
        }

	/* move up to common node */
	up = up_nodes(from_nodes - common - 1);
	if (!up) {
		EPRINTF("failed to allocate relative path for %s: %d\n",
			from_absolute, -ENOMEM);
		*err = -ENOMEM;
		goto out;
	}

	/* get path from common node to target */
	common_target_path = node_offset(to_absolute, common + 1);
	if (!common_target_path) {
		EPRINTF("failed to find common target path to %s: %d\n",
			to_absolute, -EINVAL);
		*err = -EINVAL;
		goto out;
	}

	/* get relative path */
	if (asprintf(&relative_path, "%s%s", up, common_target_path) == -1) {
		EPRINTF("failed to construct final path %s%s: %d\n",
			up, common_target_path, -ENOMEM);
		relative_path = NULL;
		*err = -ENOMEM;
		goto out;
	}

out:
	sfree(up);
	sfree(to_absolute);
	sfree(from_absolute);

	return relative_path;
}

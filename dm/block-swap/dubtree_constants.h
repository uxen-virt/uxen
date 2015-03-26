/*
 * Copyright 2013-2015, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#define DUBTREE_M 16ULL /* Level with multiplication factor. */
#define DUBTREE_MAX_LEVELS 16 /* Max depth of tree. We will never hit this. */
#define DUBTREE_BLOCK_SIZE 4096ULL /* Disk sector size. */
#define DUBTREE_MAX_VERSIONS 512 /* How many concurrent versions we support */
#define DUBTREE_TREENODES 10240 /* How many B-tree nodes we have in total. */
#define DUBTREE_CORELIMIT 3 /* Where to draw line between RAM and disk. */

#define SIMPLETREE_NODESIZE 0x8000 /* Same as Windows' paging unit. */
#define SIMPLETREE_INNER_M 2728 /* Inner node width, squeezed just below 8kB. */
#define SIMPLETREE_LEAF_M 2046 /* Leaf node width, squeezed just below 8kB. */

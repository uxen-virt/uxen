/*
 * Copyright 2013-2016, Bromium, Inc.
 * Author: Jacob Gorm Hansen <jacobgorm@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#define DUBTREE_M 16ULL /* Level with multiplication factor. */
#define DUBTREE_MAX_LEVELS 16 /* Max depth of tree. We will never hit this. */
#define DUBTREE_SLOT_SIZE (16ULL<<20ULL) /* Smallest slot size. */
#define DUBTREE_BLOCK_SIZE 4096ULL /* Disk sector size. */

#define SIMPLETREE_NODESIZE 0x8000 /* Same as Windows' paging unit. */
#define SIMPLETREE_INNER_M 3275 /* Inner node width, squeezed just below 8kB. */
#define SIMPLETREE_LEAF_M 2200 /* Leaf node width, squeezed just below 8kB. */

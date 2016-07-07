/*
  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>
  (C) 2002  David Woodhouse <dwmw2@infradead.org>

  Extent tracking and vbox changes
  (c) 2011  Gianni Tedesco <gianni at bromium dot com>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  linux/lib/rbtree.c
*/

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "disklib.h"
#include "partition.h"
#include "fs-ntfs.h"
#include "fnmatch.h"

#include "fileset.h"

struct fileset {
	struct fileset_node *rbt_root;
    RTMEMCACHE fs_mem;
    ntfs_fs_t fs_bootvol;
    ntfs_fs_t fs_sysvol;
    unsigned int fs_num_nodes;
};

struct fsname {
    char *n_path;
    unsigned int n_prio;
};

struct _fsent {
    struct disklib_stat f_st;
    struct fsname f_n;
    struct fsname *f_links;
    void *f_priv;
    struct disklib_extent *f_rl;
    unsigned int f_rl_cnt;
    uint16_t f_nlnk;
    uint8_t f_vol;
    uint8_t f_sorted;
};

const char *fsent_path(fsent_t f)
{
    return f->f_n.n_path;
}

unsigned int fsent_vol(fsent_t f)
{
    return f->f_vol;
}

unsigned int fsent_prio(fsent_t f)
{
    return f->f_n.n_prio;
}

unsigned int fsent_nlnk(fsent_t f)
{
    return f->f_nlnk;
}

const char *fsent_get_link(fsent_t f, unsigned int i, unsigned int *prio)
{
    Assert(i < f->f_nlnk);
    if ( prio )
        *prio = f->f_links[i].n_prio;
    return f->f_links[i].n_path;
}

void fsent_stat(fsent_t f, struct disklib_stat *st)
{
    memcpy(st, &f->f_st, sizeof(*st));
}

struct fileset_node {
	/** Parent node in the tree. */
	struct fileset_node *rb_parent;
#define CHILD_LEFT 0
#define CHILD_RIGHT 1
	/** Child nodes. */
	struct fileset_node *rb_child[2];
#define COLOR_RED 0
#define COLOR_BLACK 1
	/** The red-black tree colour, may be COLOR_RED or COLOR_BLACK. */
	uint32_t rb_color;
    struct _fsent f;
};

struct fileset_node *node_first(struct fileset *t);
struct fileset_node *node_last(struct fileset *t);
struct fileset_node *node_next(struct fileset_node *n);
struct fileset_node *node_prev(struct fileset_node *n);
void rbtree_insert_rebalance(struct fileset *s,
				struct fileset_node *n);
void rbtree_delete_node(struct fileset *s,
				struct fileset_node *n);

/**
 * rbtree_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define rbtree_entry(ptr, type, member) \
	container_of(ptr, type, member)

/* For any given node, find the previous or next node */
static struct fileset_node *node_prev_next(struct fileset_node *n, int prev)
{
	if ( n == NULL )
		return NULL;

	if ( n->rb_child[prev ^ 1] ) {
		n = n->rb_child[prev ^ 1];
		while( n->rb_child[prev ^ 0] )
			n = n->rb_child[prev ^ 0];
		return n;
	}else{
		while(n->rb_parent && n != n->rb_parent->rb_child[prev ^ 0] )
			n = n->rb_parent;

		return n->rb_parent;
	}
}

static struct fileset_node *node_first_last(struct fileset *t, int first)
{
	struct fileset_node *n, *ret;
	for(ret = n = t->rbt_root; n; ret = n, n = n->rb_child[first ^ 1])
		/* nothing */;
	return ret;
}

struct fileset_node *node_first(struct fileset *t)
{
	return node_first_last(t, 1);
}

struct fileset_node *node_last(struct fileset *t)
{
	return node_first_last(t, 0);
}

struct fileset_node *node_next(struct fileset_node *n)
{
	return node_prev_next(n, 0);
}
struct fileset_node *node_prev(struct fileset_node *n)
{
	return node_prev_next(n, 1);
}

/* Here we handle left/right rotations (the 2 are symmetrical) which are
 * sometimes needed to rebalance the tree after modifications
*/
static void do_rotate(struct fileset *s, struct fileset_node *n, int side)
{
	struct fileset_node *opp = n->rb_child[1 ^ side];

	if ( (n->rb_child[1 ^ side] = opp->rb_child[0 ^ side]) )
		opp->rb_child[0 ^ side]->rb_parent = n;
	opp->rb_child[0 ^ side] = n;

	if ( (opp->rb_parent = n->rb_parent) ) {
		if ( n == n->rb_parent->rb_child[0 ^ side] ) {
			n->rb_parent->rb_child[0 ^ side] = opp;
		}else{
			n->rb_parent->rb_child[1 ^ side] = opp;
		}
	}else{
		s->rbt_root = opp;
	}
	n->rb_parent = opp;
}

/* Re-balance the tree after an insertion */
void rbtree_insert_rebalance(struct fileset *s, struct fileset_node *n)
{
	struct fileset_node *parent, *gparent, *uncle;
	int side;

	while ( (parent = n->rb_parent) ) {

		/* Recursion termination, the tree is balanced */
		if ( parent->rb_color == COLOR_BLACK )
			break;

		/* When your structures have symmetry, your code can
		 * be half the size!
		 */
		gparent = parent->rb_parent;
		side = (parent == gparent->rb_child[1]);
		uncle = gparent->rb_child[1 ^ side];

		/* Check to see if we can live with just recoloring */
		if ( uncle && (uncle->rb_color == COLOR_RED) ) {
			gparent->rb_color = COLOR_RED;
			parent->rb_color = COLOR_BLACK;
			uncle->rb_color = COLOR_BLACK;
			n = gparent;
			continue;
		}

		/* Check to see if we need to do double rotation */
		if ( n == parent->rb_child[1 ^ side] ) {
			struct fileset_node *t;

			do_rotate(s, parent, 0 ^ side);
			t = parent;
			parent = n;
			n = t;
		}

		/* If not, we do a single rotation */
		parent->rb_color = COLOR_BLACK;
		gparent->rb_color = COLOR_RED;
		do_rotate(s, gparent, 1 ^ side);
	}

	s->rbt_root->rb_color = COLOR_BLACK;
}

/* Re-balance a tree after deletion, probably the most complex bit... */
static void delete_rebalance(struct fileset *s,
				struct fileset_node *n, struct fileset_node *parent)
{
	struct fileset_node *other;
	int side;

	while ( ((n == NULL) || n->rb_color == COLOR_BLACK) ) {
		if ( n == s->rbt_root)
			break;

		side = (parent->rb_child[1] == n);

		other = parent->rb_child[1 ^ side];

		if ( other->rb_color == COLOR_RED ) {
			other->rb_color = COLOR_BLACK;
			parent->rb_color = COLOR_RED;
			do_rotate(s, parent, 0 ^ side);
			other = parent->rb_child[1 ^ side];
		}

		if ( ((other->rb_child[0 ^ side] == NULL) ||
			(other->rb_child[0 ^ side]->rb_color == COLOR_BLACK)) &&
			((other->rb_child[1 ^ side] == NULL) ||
			(other->rb_child[1 ^ side]->rb_color == COLOR_BLACK)) ) {
			other->rb_color = COLOR_RED;
			n = parent;
			parent = n->rb_parent;
		}else{
			if ( (other->rb_child[1 ^ side] == NULL) ||
			(other->rb_child[1 ^ side]->rb_color == COLOR_BLACK) ) {
				struct fileset_node *opp;

				if ( (opp = other->rb_child[0 ^ side]) )
					opp->rb_color = COLOR_BLACK;

				other->rb_color = COLOR_RED;
				do_rotate(s, other, 0 ^ side);
				other = parent->rb_child[1 ^ side];
			}

			other->rb_color = parent->rb_color;
			parent->rb_color = COLOR_BLACK;
			if ( other->rb_child[1 ^ side] )
				other->rb_child[1 ^ side]->rb_color = COLOR_BLACK;
			do_rotate(s, parent, 0 ^ side);
			n = s->rbt_root;
			break;
		}
	}

	if ( n )
		n->rb_color = COLOR_BLACK;
}

void rbtree_delete_node(struct fileset *s, struct fileset_node *n)
{
	struct fileset_node *child = NULL, *parent;
	int color;

	if ( n->rb_child[0] && n->rb_child[1] ) {
		struct fileset_node *old = n, *lm;

		/* If we have 2 children, go right, and then find the leftmost
		 * node in that subtree, this is the one to swap in to replace
		 * our deleted node
		 */
		n = n->rb_child[1];
		while ( (lm = n->rb_child[0]) != NULL )
			n = lm;

		child = n->rb_child[1];
		parent = n->rb_parent;
		color = n->rb_color;

		if ( child )
			child->rb_parent = parent;

		if ( parent ) {
			if ( parent->rb_child[0] == n )
				parent->rb_child[0] = child;
			else
				parent->rb_child[1] = child;
		}else
			s->rbt_root = child;

		if ( n->rb_parent == old )
			parent = n;

		n->rb_parent = old->rb_parent;
		n->rb_color = old->rb_color;
		n->rb_child[0] = old->rb_child[0];
		n->rb_child[1] = old->rb_child[1];

		if ( old->rb_parent ) {
			if ( old->rb_parent->rb_child[0] == old )
				old->rb_parent->rb_child[0] = n;
			else
				old->rb_parent->rb_child[1] = n;
		}else
			s->rbt_root = n;

		old->rb_child[0]->rb_parent = n;
		if ( old->rb_child[1] )
			old->rb_child[1]->rb_parent = n;

		goto rebalance;
	}

	if ( n->rb_child[0] == NULL ) {
		child = n->rb_child[1];
	}else if ( n->rb_child[1] == NULL ) {
		child = n->rb_child[0];
	}

	parent = n->rb_parent;
	color = n->rb_color;

	if ( child )
		child->rb_parent = parent;

	if ( parent ) {
		if ( parent->rb_child[0] == n )
			parent->rb_child[0] = child;
		else
			parent->rb_child[1] = child;
	}else
		s->rbt_root = child;

rebalance:
	if ( color == COLOR_BLACK )
		delete_rebalance(s, child, parent);
}

int fileset_new(fileset_t *ret, ntfs_fs_t bootvol, ntfs_fs_t sysvol)
{
    struct fileset *fs;
    int rc;

    fs = (struct fileset *)RTMemAllocZ(sizeof(*fs));
    if ( NULL == fs ) {
        rc = VERR_NO_MEMORY;
        goto out;
    }

    rc = RTMemCacheCreate(&fs->fs_mem,
                            sizeof(struct fileset_node),
                            0,
                            UINT32_MAX,
                            NULL, NULL, NULL, 0);
    if ( RT_FAILURE(rc) )
        goto out_free;

    fs->fs_bootvol = bootvol;
    fs->fs_sysvol = sysvol;

    *ret = fs;
    rc = VINF_SUCCESS;
    goto out;

out_free:
    RTMemFree(fs);
out:
    return rc;
}

ntfs_fs_t fileset_bootvol(fileset_t fs)
{
    return fs->fs_bootvol;
}

ntfs_fs_t fileset_sysvol(fileset_t fs)
{
    return fs->fs_sysvol;
}

void fsent_runlist(fsent_t f, const struct disklib_extent **rl,
                   unsigned int *cnt)
{
        *rl = f->f_rl;
        *cnt = f->f_rl_cnt;
}

void *fsent_get_priv(fsent_t f)
{
    return f->f_priv;
}

void fsent_set_priv(fsent_t f, void *priv)
{
    f->f_priv = priv;
}

static int fscmp(struct _fsent *a, struct _fsent *b)
{
    int ret;

    ret = a->f_vol - b->f_vol;
    if ( ret )
        return ret;

    if ( a->f_st.f_ino < b->f_st.f_ino )
        return -1;
    if ( a->f_st.f_ino > b->f_st.f_ino )
        return 1;
    return 0;
}

/* TODO: remember prio */
static int add_link(struct _fsent *orig, struct _fsent *lnk)
{
    struct fsname *new;
    char *p;

    p = RTStrDup(lnk->f_n.n_path);
    if ( NULL == p )
        goto err;

    new = RTMemRealloc(orig->f_links, sizeof(*new) * (orig->f_nlnk + 1));
    if ( NULL == new )
        goto err_free_path;

    orig->f_links = new;
    orig->f_links[orig->f_nlnk].n_path = p;
    orig->f_links[orig->f_nlnk].n_prio = lnk->f_n.n_prio;
    orig->f_nlnk++;

    /* dirty node to be re-sorted */
    orig->f_sorted = 0;

    return 1;

err_free_path:
    RTStrFree(p);
err:
    return 0;
}

static ntfs_fs_t get_vol(struct fileset *fs, unsigned int vol)
{
    switch(vol) {
    case FILESET_VOL_BOOT:
        return fs->fs_bootvol;
    case FILESET_VOL_SYS:
        return fs->fs_sysvol;
    default:
        AssertFailed();
        break;
    }
    return NULL;
}

static fsent_t tree_insert(fileset_t fs, struct _fsent *ent)
{
    struct fileset_node *n, *parent, **p;
    struct fileset_node *ik;
    ntfs_fd_t fd;

    for(p = &fs->rbt_root, n = parent = NULL; *p; ) {
        struct fileset_node *node;
        int ret;
        (void)n;

        parent = *p;
        node = (struct fileset_node *)parent;

        ret = fscmp(&node->f, ent);
        if ( ret < 0 ) {
            p = &(*p)->rb_child[CHILD_LEFT];
        }else if ( ret > 0 ) {
            p = &(*p)->rb_child[CHILD_RIGHT];
        }else{
            /* if path is the same then we just got here by recursing
             * in to same dir multiple times, nothing to do...
             */
            if ( !RTStrICmp(ent->f_n.n_path, node->f.f_n.n_path) )
                return &node->f;

            /* it's a hardlink */
            if ( !add_link(&node->f, ent) )
                return NULL;

            return &node->f;
        }
    }

    ik = (struct fileset_node *)RTMemCacheAlloc(fs->fs_mem);
    if ( NULL == ik )
        return NULL;

    memset(ik, 0, sizeof(*ik));
    ik->rb_parent = parent;

    ik->f.f_n.n_path = RTStrDup(ent->f_n.n_path);
    memcpy(&ik->f.f_st, &ent->f_st, sizeof(ik->f.f_st));
    ik->f.f_vol = ent->f_vol;
    ik->f.f_n.n_prio = ent->f_n.n_prio;
    ik->f.f_nlnk = 0;
    ik->f.f_links = NULL;
    if ( NULL == ik->f.f_n.n_path )
        goto err_free;

    if ( (ik->f.f_st.f_mode == 0) &&
            (ik->f.f_st.a_mode & DISKLIB_ISATTR) &&
            !(ik->f.f_st.a_mode & DISKLIB_ISRESIDENT) ) {

        fd = disklib_ntfs_open(get_vol(fs, ik->f.f_vol),
                                ik->f.f_n.n_path, DISKLIB_FD_READ);
        if ( NULL == fd ) {
            LogRel(("%s: open: %s\n", ik->f.f_n.n_path,
                        disklib_strerror(disklib_errno())));
            goto err_free;
        }

        if ( disklib_ntfs_file_extents(fd, &ik->f.f_rl, &ik->f.f_rl_cnt) ) {
            LogRel(("%s: disklib_ntfs_file_extents error: %s\n", ik->f.f_n.n_path,
                        disklib_strerror(disklib_errno())));
            //goto err_close;
        }

        disklib_ntfs_close(fd);
    }

    *p = ik;
    rbtree_insert_rebalance(fs, ik);
    fs->fs_num_nodes++;

    return &ik->f;
//err_close:
//    disklib_ntfs_close(fd);
err_free:
    RTMemFree(ik->f.f_n.n_path);
    RTMemCacheFree(fs->fs_mem, ik);
    return NULL;
}

fsent_t fileset_insert_prio(fileset_t fs, unsigned int vol,
                            const char *name, unsigned int prio)
{
    struct _fsent ent;

    ent.f_n.n_path = (char *)name;
    ent.f_n.n_prio = prio;
    ent.f_vol = vol;
    if ( disklib_ntfs_stat(get_vol(fs, vol), name, &ent.f_st) ) {
        RTPrintf("%s: stat: %s\n", name,
                 disklib_strerror(disklib_errno()));
        return NULL;
    }

    return tree_insert(fs, &ent);
}

fsent_t fileset_insert(fileset_t fs, unsigned int vol, const char *name)
{
    return fileset_insert_prio(fs, vol, name, fs->fs_num_nodes);
}

#if 0
static fsent_t do_query(fileset_t fs, struct _fsent *ent)
{
    struct fileset_node *n, *parent, **p;

    for(p = &fs->rbt_root, n = parent = NULL; *p; ) {
        struct fileset_node *node;
        int ret;

        parent = *p;
        node = (struct fileset_node *)parent;
        ret = fscmp(&node->f, ent);
        if ( ret < 0 ) {
            p = &(*p)->rb_child[CHILD_LEFT];
        }else if ( ret > 0 ) {
            p = &(*p)->rb_child[CHILD_RIGHT];
        }else{
            return &node->f;
        }
    }

    return NULL;
}

fsent_t fileset_query(fileset_t fs, unsigned int vol, uint64_t ino)
{
    struct _fsent ent;

    ent.f_vol = vol;
    ent.f_ino = ino;

    ent.f_path = NULL;
    ent.f_prio = 0;

    return do_query(fs, &ent);
}
#endif

static void do_free(struct fileset_node *n)
{
    unsigned int i;

    if ( NULL == n )
        return;

    do_free(n->rb_child[CHILD_LEFT]);

    RTStrFree(n->f.f_n.n_path);
    for(i = 0; i < n->f.f_nlnk; i++) {
        RTStrFree(n->f.f_links[i].n_path);
    }
    RTMemFree(n->f.f_links);
    RTMemFree(n->f.f_rl);

    do_free(n->rb_child[CHILD_RIGHT]);
}

void fileset_free(fileset_t fs)
{
    if ( fs ) {
        do_free(fs->rbt_root);
        RTMemCacheDestroy(fs->fs_mem);
        RTMemFree(fs);
    }
}

static int sortfn(const void *A, const void *B)
{
    const struct fsname *a = (const struct fsname *)A;
    const struct fsname *b = (const struct fsname *)B;
    return RTStrICmp(a->n_path, b->n_path);
}

static int stabilize_links(struct _fsent *f)
{
    struct fsname *arr;
    unsigned int nmemb;
    unsigned int i;

    if ( f->f_sorted )
        return 1;
    if ( !f->f_nlnk )
        goto done;

    nmemb = f->f_nlnk + 1;
    arr = RTMemAlloc(nmemb * sizeof(*arr));
    if ( NULL == arr )
        return 0;

    for(i = 0; i < f->f_nlnk; i++ ) {
        arr[i] = f->f_links[i];
    }
    arr[i] = f->f_n;

    qsort(arr, nmemb, sizeof(*arr), sortfn);

    for(i = 0; i < nmemb; i++) {
        if ( i == 0 ) {
            f->f_n = arr[i];
        }else{
            f->f_links[i - 1] = arr[i];
        }
    }

    RTMemFree(arr);
done:
    f->f_sorted = 1;
    return 1;
}

static int do_save(struct fileset_node *n, fsent_t *m,
                   unsigned int *cnt, int stable)
{
    if ( NULL == n )
        return 1;

    if ( !do_save(n->rb_child[CHILD_LEFT], m, cnt, stable) )
        return 0;

    if ( stable && !stabilize_links(&n->f) )
        return 0;
    m[*cnt] = &n->f;
    (*cnt)++;

    if ( !do_save(n->rb_child[CHILD_RIGHT], m, cnt, stable) )
        return 0;

    return 1;
}

static int do_manifest(fileset_t fs, fsent_t **man, unsigned int *nmemb,
                       int stable)
{
    fsent_t *ret = NULL;

    *nmemb = 0;

    if (fs->fs_num_nodes) {
        ret = RTMemAlloc(fs->fs_num_nodes * sizeof(*ret));
        if ( NULL == ret )
            return VERR_NO_MEMORY;

        if ( !do_save(fs->rbt_root, ret, nmemb, stable) ) {
            *nmemb = fs->fs_num_nodes;
            RTMemFree(ret);
            return VERR_NO_MEMORY;
        }
    }

    Assert(*nmemb == fs->fs_num_nodes);
    *man = ret;
    return VINF_SUCCESS;
}

int fileset_manifest(fileset_t fs, fsent_t **man, unsigned int *nmemb)
{
    return do_manifest(fs, man, nmemb, 0);
}

int fileset_manifest_stable(fileset_t fs, fsent_t **man, unsigned int *nmemb)
{
    return do_manifest(fs, man, nmemb, 1);
}

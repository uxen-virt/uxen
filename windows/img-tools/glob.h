/* Copyright (C) 1991,1992,1995-1998,2000,2001,2004,2010,2011,2012
   Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef	_GLOB_H
#define	_GLOB_H	1

#ifdef	__cplusplus
extern "C" {
#endif

/* Bits set in the FLAGS argument to `glob'.  */
#define	GLOB_ERR	(1 << 0)/* Return on read errors.  */
#define	GLOB_MARK	(1 << 1)/* Append a slash to each name.  */
#define	GLOB_NOSORT	(1 << 2)/* Don't sort the names.  */
#define	GLOB_DOOFFS	(1 << 3)/* Insert PGLOB->gl_offs NULLs.  */
#define	GLOB_NOCHECK	(1 << 4)/* If nothing matches, return the pattern.  */
#define	GLOB_APPEND	(1 << 5)/* Append to results of a previous call.  */
#define	GLOB_NOESCAPE	(1 << 6)/* Backslashes don't quote metacharacters.  */
#define	GLOB_PERIOD	(1 << 7)/* Leading `.' can be matched by metachars.  */

# define GLOB_MAGCHAR	 (1 << 8)/* Set in gl_flags if any metachars seen.  */
# define GLOB_BRACE	 (1 << 10)/* Expand "{a,b}" to "a" "b".  */
# define GLOB_NOMAGIC	 (1 << 11)/* If no magic chars, return the pattern.  */
# define GLOB_ONLYDIR	 (1 << 13)/* Match only directories.  */
# define __GLOB_FLAGS	(GLOB_ERR|GLOB_MARK|GLOB_NOSORT|GLOB_DOOFFS| \
			 GLOB_NOESCAPE|GLOB_NOCHECK|GLOB_APPEND|     \
			 GLOB_PERIOD|GLOB_BRACE|     \
			 GLOB_NOMAGIC|GLOB_ONLYDIR)

/* Error returns from `glob'.  */
#define	GLOB_NOSPACE	1	/* Ran out of memory.  */
#define	GLOB_ABORTED	2	/* Read error.  */
#define	GLOB_NOMATCH	3	/* No matches found.  */
#define GLOB_NOSYS	4	/* Not implemented.  */
/* Previous versions of this file defined GLOB_ABEND instead of
   GLOB_ABORTED.  Provide a compatibility definition here.  */
# define GLOB_ABEND GLOB_ABORTED

/* Structure describing a globbing run.  */
typedef struct
  {
    size_t gl_pathc;		/* Count of paths matched by the pattern.  */
    char **gl_pathv;		/* List of matched pathnames.  */
    size_t gl_offs;		/* Slots to reserve in `gl_pathv'.  */
    int gl_flags;		/* Set to FLAGS, maybe | GLOB_MAGCHAR.  */
    int gl_dirflags;
  } glob_t;

extern int disklib_glob(ntfs_fs_t fs,
        const char *__restrict __pattern, int __flags,
		 int (*__errfunc) (const char *, int),
		 glob_t *__restrict __pglob);

/* Free storage allocated in PGLOB by a previous `glob' call.  */
extern void disklib_globfree (glob_t *__pglob);

#ifdef	__cplusplus
}
#endif

#endif /* glob.h  */

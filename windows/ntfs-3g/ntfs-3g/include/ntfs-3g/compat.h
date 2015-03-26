/*
 * compat.h - Tweaks for Windows compatibility.
 *
 * Copyright (c) 2002 Richard Russon
 * Copyright (c) 2002-2004 Anton Altaparmakov
 * Copyright (c) 2008-2009 Szabolcs Szakacsits
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the NTFS-3G
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation,Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef _NTFS_COMPAT_H
#define _NTFS_COMPAT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#ifndef HAVE_FFS
extern int ffs(int i);
#endif /* HAVE_FFS */

#ifndef HAVE_DAEMON
extern int daemon(int nochdir, int noclose);
#endif /* HAVE_DAEMON */

#ifndef HAVE_STRSEP
extern char *strsep(char **stringp, const char *delim);
#endif /* HAVE_STRSEP */

#ifdef WINDOWS

#ifndef HAVE_STDIO_H
#define HAVE_STDIO_H		/* mimic config.h */
#endif
#ifndef HAVE_STDARG_H
#define HAVE_STDARG_H
#endif

#define atoll			_atoi64
#define fdatasync		commit
#define __inline__		inline
#ifndef __GNUC__
#define __attribute__(X)	/*nothing*/
#endif

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if 0
#define __S_IREAD		0400
#define __S_IWRITE		0200
#define __S_IEXEC		0100

#define S_IRUSR			__S_IREAD
#define S_IWUSR			__S_IWRITE
#define S_IXUSR			__S_IEXEC
#endif

#define S_IRGRP			(S_IRUSR >> 3)
#define S_IWGRP			(S_IWUSR >> 3)
#define S_IXGRP			(S_IXUSR >> 3)

#define S_IROTH			(S_IRGRP >> 3)
#define S_IWOTH			(S_IWGRP >> 3)
#define S_IXOTH			(S_IXGRP >> 3)

#define S_ISUID			04000
#define S_ISGID			02000
#define S_ISVTX			01000

#define ENOMSG			42
#define ENOSHARE		ENOENT
#define EBADRQC			56
#define ENODATA			61
#define EOVERFLOW		75
#define EMSGSIZE		90
#define ENOTSUP			95
#define EOPNOTSUPP		ENOTSUP
#define ENOBUFS			105

typedef unsigned int uid_t;
typedef unsigned int gid_t;

#define S_IFLNK		0120000
#define S_IFSOCK 	0140000

static inline unsigned int major(unsigned long long int dev)
{
	return ((dev >> 8) & 0xfff) | ((unsigned int)(dev >> 32) & ~0xfff);
}

static inline unsigned int minor(unsigned long long int dev)
{
	return (dev & 0xff) | ((unsigned int)(dev >> 12) & ~0xff);
}

static inline uid_t getuid(void)
{
	return 0;
}
static inline gid_t getgid(void)
{
	return 0;
}

#else /* !defined WINDOWS */

#ifndef O_BINARY
#define O_BINARY		0		/* unix is binary by default */
#endif

#endif /* defined WINDOWS */

int ntfs_get_errno(void);
void ntfs_set_errno(int);

#endif /* defined _NTFS_COMPAT_H */


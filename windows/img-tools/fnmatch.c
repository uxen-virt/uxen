/* Copyright (C) 1991,1992,1993,1996,1997,1998,1999,2000,2001,2002,2003,2007,2010,2011
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

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ctype.h>

#include "disklib.h"
#include "fnmatch.h"

/* We often have to test for FNM_FILE_NAME and FNM_PERIOD being both set.  */
#define NO_LEADING_PERIOD(flags) \
  ((flags & (FNM_FILE_NAME | FNM_PERIOD)) == (FNM_FILE_NAME | FNM_PERIOD))

# if defined STDC_HEADERS || !defined isascii
#  define ISASCII(c) 1
# else
#  define ISASCII(c) isascii(c)
# endif

# ifdef isblank
#  define ISBLANK(c) (ISASCII (c) && isblank (c))
# else
#  define ISBLANK(c) ((c) == ' ' || (c) == '\t')
# endif
# ifdef isgraph
#  define ISGRAPH(c) (ISASCII (c) && isgraph (c))
# else
#  define ISGRAPH(c) (ISASCII (c) && isprint (c) && !isspace (c))
#endif

# define ISPRINT(c) (ISASCII (c) && isprint (c))
# define ISDIGIT(c) (ISASCII (c) && isdigit (c))
# define ISALNUM(c) (ISASCII (c) && isalnum (c))
# define ISALPHA(c) (ISASCII (c) && isalpha (c))
# define ISCNTRL(c) (ISASCII (c) && iscntrl (c))
# define ISLOWER(c) (ISASCII (c) && islower (c))
# define ISPUNCT(c) (ISASCII (c) && ispunct (c))
# define ISSPACE(c) (ISASCII (c) && isspace (c))
# define ISUPPER(c) (ISASCII (c) && isupper (c))
# define ISXDIGIT(c) (ISASCII (c) && isxdigit (c))

# define STREQ(s1, s2) ((strcmp (s1, s2) == 0))

/* Avoid depending on library functions or files
   whose names are inconsistent.  */

/* Global variable.  -1 for no, 1 for yes */
static int posixly_correct = - 1;

# ifndef internal_function
/* Inside GNU libc we mark some function in a special way.  In other
   environments simply ignore the marking.  */
#  define internal_function
# endif

#  define CHAR_CLASS_MAX_LENGTH  6 /* Namely, `xdigit'.  */

static char *my_mempcpy(void *dst, const void *src, size_t len)
{
    memcpy(dst, src, len);
    return (char *)dst + len;
}

/* Note that this evaluates C many times.  */
#define FOLD(c) ((flags & FNM_CASEFOLD) && ISUPPER (c) ? tolower (c) : (c))
#define CHAR	char
#define UCHAR	unsigned char
#define INT	int
#define FCT	my_internal_fnmatch
#define EXT	ext_match
#define END	end_pattern
#define STRUCT	fnmatch_struct
#define L(CS)	CS
#define BTOWC(C)	btowc (C)
#define STRLEN(S) strlen (S)
#define STRCAT(D, S) strcat (D, S)
#define MEMPCPY(D, S, N) my_mempcpy (D, S, N)
#define MEMCHR(S, C, N) memchr (S, C, N)
#define STRCOLL(S1, S2) strcoll (S1, S2)
#include "fnmatch_loop.c"

int
fnmatch (pattern, string, flags)
     const char *pattern;
     const char *string;
     int flags;
{
  return my_internal_fnmatch (pattern, string, string + strlen (string),
			   flags & FNM_PERIOD, flags, NULL, 0);
}

/* Copyright (C) 1991-2002, 2003, 2004, 2005, 2006, 2007, 2008, 2010, 2011
   Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is RTMemFree software; you can redistribute it and/or
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

#include "disklib.h"
#include "partition.h"
#include "fs-ntfs.h"
#include "glob.h"
#include "fnmatch.h"
#include "disklib-internal.h"

# define DIRENT_MIGHT_BE_SYMLINK(d)    1
# define DIRENT_MIGHT_BE_DIR(d)        1

#if 0
static char *mempcpy(void *dst, const void *src, size_t len)
{
    memcpy(dst, src, len);
    return (char *)dst + len;
}
#endif

static const char *next_brace_sub (const char *begin, int flags);

static int glob_in_dir (ntfs_fs_t fd, const char *pattern,
            const char *directory,
            int flags, int (*errfunc) (const char *, int),
            glob_t *pglob, size_t alloca_used);
extern int __glob_pattern_type (const char *pattern, int quote);

static int prefix_array (const char *prefix, char **array, size_t n);
static int collated_compare (const void *, const void *);


/* Find the end of the sub-pattern in a brace expression.  */
static const char *
next_brace_sub (const char *cp, int flags)
{
  unsigned int depth = 0;
  while (*cp != '\0')
    if ((flags & GLOB_NOESCAPE) == 0 && *cp == '\\')
      {
    if (*++cp == '\0')
      break;
    ++cp;
      }
    else
      {
    if ((*cp == '}' && depth-- == 0) || (*cp == ',' && depth == 0))
      break;

    if (*cp++ == '{')
      depth++;
      }

  return *cp != '\0' ? cp : NULL;
}

/* Do glob searching for PATTERN, placing results in PGLOB.
   The bits defined above may be set in FLAGS.
   If a directory cannot be opened or read and ERRFUNC is not nil,
   it is called with the pathname that caused the error, and the
   `errno' value from the failing call; if it returns non-zero
   `glob' returns GLOB_ABORTED; if it returns zero, the error is ignored.
   If memory cannot be allocated for PGLOB, GLOB_NOSPACE is returned.
   Otherwise, `glob' returns zero.  */
int
disklib_glob (fs, pattern, flags, errfunc, pglob)
     ntfs_fs_t fs;
     const char *pattern;
     int flags;
     int (*errfunc) (const char *, int);
     glob_t *pglob;
{
  const char *filename;
  char *dirname = NULL;
  size_t dirlen;
  int status;
  size_t oldcount;
  int meta;
  int dirname_modified;
  int RTMemAlloc_dirname = 0;
  glob_t dirs;
  int retval = 0;
  size_t alloca_used = 0;

  if (pattern == NULL || pglob == NULL || (flags & ~__GLOB_FLAGS) != 0)
    {
      disklib__set_errno(DISKLIB_ERR_INVAL);
      return -1;
    }

  if (!(flags & GLOB_DOOFFS))
    /* Have to do this so `disklib_globfree' knows where to start freeing.  It
       also makes all the code that uses gl_offs simpler. */
    pglob->gl_offs = 0;

  if (flags & GLOB_BRACE)
    {
      const char *begin;

      if (flags & GLOB_NOESCAPE)
    begin = strchr (pattern, '{');
      else
    {
      begin = pattern;
      while (1)
        {
          if (*begin == '\0')
        {
          begin = NULL;
          break;
        }

          if (*begin == '\\' && begin[1] != '\0')
        ++begin;
          else if (*begin == '{')
        break;

          ++begin;
        }
    }

      if (begin != NULL)
    {
      /* Allocate working buffer large enough for our work.  Note that
        we have at least an opening and closing brace.  */
      size_t firstc;
      char *alt_start;
      const char *p;
      const char *next;
      const char *rest;
      size_t rest_len;
      char *onealt;
      size_t pattern_len = strlen (pattern) - 1;
        {
          onealt = (char *) RTMemAlloc (pattern_len);
          if (onealt == NULL)
        {
          if (!(flags & GLOB_APPEND))
            {
              pglob->gl_pathc = 0;
              pglob->gl_pathv = NULL;
            }
          return GLOB_NOSPACE;
        }
        }

      /* We know the prefix for all sub-patterns.  */
      alt_start = mempcpy (onealt, pattern, begin - pattern);

      /* Find the first sub-pattern and at the same time find the
         rest after the closing brace.  */
      next = next_brace_sub (begin + 1, flags);
      if (next == NULL)
        {
          /* It is an illegal expression.  */
        illegal_brace:
        RTMemFree (onealt);
          return disklib_glob(fs, pattern, flags & ~GLOB_BRACE, errfunc, pglob);
        }

      /* Now find the end of the whole brace expression.  */
      rest = next;
      while (*rest != '}')
        {
          rest = next_brace_sub (rest + 1, flags);
          if (rest == NULL)
        /* It is an illegal expression.  */
        goto illegal_brace;
        }
      /* Please note that we now can be sure the brace expression
         is well-formed.  */
      rest_len = strlen (++rest) + 1;

      /* We have a brace expression.  BEGIN points to the opening {,
         NEXT points past the terminator of the first element, and END
         points past the final }.  We will accumulate result names from
         recursive runs for each brace alternative in the buffer using
         GLOB_APPEND.  */

      if (!(flags & GLOB_APPEND))
        {
          /* This call is to set a new vector, so clear out the
         vector so we can append to it.  */
          pglob->gl_pathc = 0;
          pglob->gl_pathv = NULL;
        }
      firstc = pglob->gl_pathc;

      p = begin + 1;
      while (1)
        {
          int result;

          /* Construct the new glob expression.  */
          mempcpy (mempcpy (alt_start, p, next - p), rest, rest_len);

          result = disklib_glob(fs, onealt,
                 ((flags & ~(GLOB_NOCHECK | GLOB_NOMAGIC))
                  | GLOB_APPEND), errfunc, pglob);

          /* If we got an error, return it.  */
          if (result && result != GLOB_NOMATCH)
        {
            RTMemFree (onealt);
          if (!(flags & GLOB_APPEND))
            {
              disklib_globfree (pglob);
              pglob->gl_pathc = 0;
            }
          return result;
        }

          if (*next == '}')
        /* We saw the last entry.  */
        break;

          p = next + 1;
          next = next_brace_sub (p, flags);
          Assert (next != NULL);
        }

        RTMemFree (onealt);

      if (pglob->gl_pathc != firstc)
        /* We found some entries.  */
        return 0;
      else if (!(flags & (GLOB_NOCHECK|GLOB_NOMAGIC)))
        return GLOB_NOMATCH;
    }
    }

  if (!(flags & GLOB_APPEND))
    {
      pglob->gl_pathc = 0;
      if (!(flags & GLOB_DOOFFS))
    pglob->gl_pathv = NULL;
      else
    {
      size_t i;

      if (pglob->gl_offs >= ~((size_t) 0) / sizeof (char *))
        return GLOB_NOSPACE;

      pglob->gl_pathv = (char **) RTMemAlloc ((pglob->gl_offs + 1)
                          * sizeof (char *));
      if (pglob->gl_pathv == NULL)
        return GLOB_NOSPACE;

      for (i = 0; i <= pglob->gl_offs; ++i)
        pglob->gl_pathv[i] = NULL;
    }
    }

  oldcount = pglob->gl_pathc + pglob->gl_offs;

  /* Find the filename.  */
  filename = strrchr (pattern, '/');
#if defined __MSDOS__ || defined WINDOWS32
  /* The case of "d:pattern".  Since `:' is not allowed in
     file names, we can safely assume that wherever it
     happens in pattern, it signals the filename part.  This
     is so we could some day support patterns like "[a-z]:foo".  */
  if (filename == NULL)
    filename = strchr (pattern, ':');
#endif /* __MSDOS__ || WINDOWS32 */
  dirname_modified = 0;
  if (filename == NULL)
    {
      /* This can mean two things: a simple name or "~name".  The latter
     case is nothing but a notation for a directory.  */
    if (__builtin_expect (pattern[0] == '\0', 0))
      {
        dirs.gl_pathv = NULL;
        goto no_matches;
      }

    filename = pattern;
    dirname = (char *) ".";
    dirlen = 0;
    }
  else if (filename == pattern
       || (filename == pattern + 1 && pattern[0] == '\\'
           && (flags & GLOB_NOESCAPE) == 0))
    {
      /* "/pattern" or "\\/pattern".  */
      dirname = (char *) "/";
      dirlen = 1;
      ++filename;
    }
  else
    {
      char *newp;
      dirlen = filename - pattern;
#if 0
      if (*filename == ':'
      || (filename > pattern + 1 && filename[-1] == ':'))
    {
      char *drive_spec;

      ++dirlen;
      drive_spec = (char *) __alloca (dirlen + 1);
      *((char *) mempcpy (drive_spec, pattern, dirlen)) = '\0';
      /* For now, disallow wildcards in the drive spec, to
         prevent infinite recursion in glob.  */
      if (__glob_pattern_p (drive_spec, !(flags & GLOB_NOESCAPE)))
        return GLOB_NOMATCH;
      /* If this is "d:pattern", we need to copy `:' to DIRNAME
         as well.  If it's "d:/pattern", don't remove the slash
         from "d:/", since "d:" and "d:/" are not the same.*/
    }
#endif
    {
      newp = RTMemAlloc (dirlen + 1);
      if (newp == NULL)
        return GLOB_NOSPACE;
      RTMemAlloc_dirname = 1;
    }
      *((char *) mempcpy (newp, pattern, dirlen)) = '\0';
      dirname = newp;
      ++filename;

      if (filename[0] == '\0'
#if defined __MSDOS__ || defined WINDOWS32
      && dirname[dirlen - 1] != ':'
      && (dirlen < 3 || dirname[dirlen - 2] != ':'
          || dirname[dirlen - 1] != '/')
#endif
      && dirlen > 1)
    /* "pattern/".  Expand "pattern", appending slashes.  */
    {
      int orig_flags = flags;
      if (!(flags & GLOB_NOESCAPE) && dirname[dirlen - 1] == '\\')
        {
          /* "pattern\\/".  Remove the final backslash if it hasn't
         been quoted.  */
          char *p = (char *) &dirname[dirlen - 1];

          while (p > dirname && p[-1] == '\\') --p;
          if ((&dirname[dirlen] - p) & 1)
        {
          *(char *) &dirname[--dirlen] = '\0';
          flags &= ~(GLOB_NOCHECK | GLOB_NOMAGIC);
        }
        }
      int val = disklib_glob(fs, dirname, flags | GLOB_MARK, errfunc, pglob);
      if (val == 0)
        pglob->gl_flags = ((pglob->gl_flags & ~GLOB_MARK)
                   | (flags & GLOB_MARK));
      else if (val == GLOB_NOMATCH && flags != orig_flags)
        {
          /* Make sure disklib_globfree (&dirs); is a nop.  */
          dirs.gl_pathv = NULL;
          flags = orig_flags;
          oldcount = pglob->gl_pathc + pglob->gl_offs;
          goto no_matches;
        }
      retval = val;
      goto out;
    }
    }

  /* Now test whether we looked for "~" or "~NAME".  In this case we
     can give the answer now.  */
  if (filename == NULL)
    {
      struct disklib_stat st64;

      /* Return the directory if we don't check for error or if it exists.  */
      if ((flags & GLOB_NOCHECK) ||
           (disklib_ntfs_stat(fs, dirname, &st64) == 0
            && st64.f_mode & DISKLIB_ISDIR))
    {
      int newcount = pglob->gl_pathc + pglob->gl_offs;
      char **new_gl_pathv;

      if (newcount > UINTPTR_MAX - (1 + 1)
          || newcount + 1 + 1 > ~((size_t) 0) / sizeof (char *))
        {
        nospace:
          RTMemFree (pglob->gl_pathv);
          pglob->gl_pathv = NULL;
          pglob->gl_pathc = 0;
          return GLOB_NOSPACE;
        }

      new_gl_pathv
        = (char **) RTMemRealloc (pglob->gl_pathv,
                 (newcount + 1 + 1) * sizeof (char *));
      if (new_gl_pathv == NULL)
        goto nospace;
      pglob->gl_pathv = new_gl_pathv;

      if (flags & GLOB_MARK)
        {
          char *p;
          pglob->gl_pathv[newcount] = RTMemAlloc (dirlen + 2);
          if (pglob->gl_pathv[newcount] == NULL)
        goto nospace;
          p = mempcpy (pglob->gl_pathv[newcount], dirname, dirlen);
          p[0] = '/';
          p[1] = '\0';
        }
      else
        {
          pglob->gl_pathv[newcount] = strdup (dirname);
          if (pglob->gl_pathv[newcount] == NULL)
        goto nospace;
        }
      pglob->gl_pathv[++newcount] = NULL;
      ++pglob->gl_pathc;
      pglob->gl_flags = flags;

      return 0;
    }

      /* Not found.  */
      return GLOB_NOMATCH;
    }

  meta = __glob_pattern_type (dirname, !(flags & GLOB_NOESCAPE));
  /* meta is 1 if correct glob pattern containing metacharacters.
     If meta has bit (1 << 2) set, it means there was an unterminated
     [ which we handle the same, using fnmatch.  Broken unterminated
     pattern bracket expressions ought to be rare enough that it is
     not worth special casing them, fnmatch will do the right thing.  */
  if (meta & 5)
    {
      /* The directory name contains metacharacters, so we
     have to glob for the directory, and then glob for
     the pattern in each directory found.  */
      size_t i;

      if (!(flags & GLOB_NOESCAPE) && dirlen > 0 && dirname[dirlen - 1] == '\\')
    {
      /* "foo\\/bar".  Remove the final backslash from dirname
         if it has not been quoted.  */
      char *p = (char *) &dirname[dirlen - 1];

      while (p > dirname && p[-1] == '\\') --p;
      if ((&dirname[dirlen] - p) & 1)
        *(char *) &dirname[--dirlen] = '\0';
    }

      status = disklib_glob(fs, dirname,
             ((flags & (GLOB_ERR | GLOB_NOESCAPE))
              | GLOB_NOSORT | GLOB_ONLYDIR),
             errfunc, &dirs);
      if (status != 0)
    {
      if ((flags & GLOB_NOCHECK) == 0 || status != GLOB_NOMATCH)
        return status;
      goto no_matches;
    }

      /* We have successfully globbed the preceding directory name.
     For each name we found, call glob_in_dir on it and FILENAME,
     appending the results to PGLOB.  */
      for (i = 0; i < dirs.gl_pathc; ++i)
    {
      int old_pathc;

      old_pathc = pglob->gl_pathc;
      status = glob_in_dir (fs, filename, dirs.gl_pathv[i],
                ((flags | GLOB_APPEND)
                 & ~(GLOB_NOCHECK | GLOB_NOMAGIC)),
                errfunc, pglob, alloca_used);
      if (status == GLOB_NOMATCH)
        /* No matches in this directory.  Try the next.  */
        continue;

      if (status != 0)
        {
          disklib_globfree (&dirs);
          disklib_globfree (pglob);
          pglob->gl_pathc = 0;
          return status;
        }

      /* Stick the directory on the front of each name.  */
      if (prefix_array (dirs.gl_pathv[i],
                &pglob->gl_pathv[old_pathc + pglob->gl_offs],
                pglob->gl_pathc - old_pathc))
        {
          disklib_globfree (&dirs);
          disklib_globfree (pglob);
          pglob->gl_pathc = 0;
          return GLOB_NOSPACE;
        }
    }

      flags |= GLOB_MAGCHAR;

      /* We have ignored the GLOB_NOCHECK flag in the `glob_in_dir' calls.
     But if we have not found any matching entry and the GLOB_NOCHECK
     flag was set we must return the input pattern itself.  */
      if (pglob->gl_pathc + pglob->gl_offs == oldcount)
    {
    no_matches:
      /* No matches.  */
      if (flags & GLOB_NOCHECK)
        {
          int newcount = pglob->gl_pathc + pglob->gl_offs;
          char **new_gl_pathv;

          if (newcount > UINTPTR_MAX - 2
          || newcount + 2 > ~((size_t) 0) / sizeof (char *))
        {
        nospace2:
          disklib_globfree (&dirs);
          return GLOB_NOSPACE;
        }

          new_gl_pathv = (char **) RTMemRealloc (pglob->gl_pathv,
                        (newcount + 2)
                        * sizeof (char *));
          if (new_gl_pathv == NULL)
        goto nospace2;
          pglob->gl_pathv = new_gl_pathv;

          pglob->gl_pathv[newcount] = RTStrDup (pattern);
          if (pglob->gl_pathv[newcount] == NULL)
        {
          disklib_globfree (&dirs);
          disklib_globfree (pglob);
          pglob->gl_pathc = 0;
          return GLOB_NOSPACE;
        }

          ++pglob->gl_pathc;
          ++newcount;

          pglob->gl_pathv[newcount] = NULL;
          pglob->gl_flags = flags;
        }
      else
        {
          disklib_globfree (&dirs);
          return GLOB_NOMATCH;
        }
    }

      disklib_globfree (&dirs);
    }
  else
    {
      int old_pathc = pglob->gl_pathc;
      int orig_flags = flags;

      if (meta & 2)
    {
      char *p = strchr (dirname, '\\'), *q;
      /* We need to unescape the dirname string.  It is certainly
         allocated by alloca, as otherwise filename would be NULL
         or dirname wouldn't contain backslashes.  */
      q = p;
      do
        {
          if (*p == '\\')
        {
          *q = *++p;
          --dirlen;
        }
          else
        *q = *p;
          ++q;
        }
      while (*p++ != '\0');
      dirname_modified = 1;
    }
      if (dirname_modified)
    flags &= ~(GLOB_NOCHECK | GLOB_NOMAGIC);
      status = glob_in_dir (fs, filename, dirname, flags, errfunc, pglob,
                alloca_used);
      if (status != 0)
    {
      if (status == GLOB_NOMATCH && flags != orig_flags
          && pglob->gl_pathc + pglob->gl_offs == oldcount)
        {
          /* Make sure disklib_globfree (&dirs); is a nop.  */
          dirs.gl_pathv = NULL;
          flags = orig_flags;
          goto no_matches;
        }
      return status;
    }

      if (dirlen > 0)
    {
      /* Stick the directory on the front of each name.  */
      if (prefix_array (dirname,
                &pglob->gl_pathv[old_pathc + pglob->gl_offs],
                pglob->gl_pathc - old_pathc))
        {
          disklib_globfree (pglob);
          pglob->gl_pathc = 0;
          return GLOB_NOSPACE;
        }
    }
    }

  if (flags & GLOB_MARK)
    {
      /* Append slashes to directory names.  */
      size_t i;
      struct disklib_stat st64;

      for (i = oldcount; i < pglob->gl_pathc + pglob->gl_offs; ++i)
    if ( (disklib_ntfs_stat(fs, pglob->gl_pathv[i], &st64) == 0
        && st64.f_mode | DISKLIB_ISDIR))
      {
        size_t len = strlen (pglob->gl_pathv[i]) + 2;
        char *new = RTMemRealloc (pglob->gl_pathv[i], len);
        if (new == NULL)
          {
        disklib_globfree (pglob);
        pglob->gl_pathc = 0;
        return GLOB_NOSPACE;
          }
        strcpy (&new[len - 2], "/");
        pglob->gl_pathv[i] = new;
      }
    }

  if (!(flags & GLOB_NOSORT))
    {
      /* Sort the vector.  */
      qsort (&pglob->gl_pathv[oldcount],
         pglob->gl_pathc + pglob->gl_offs - oldcount,
         sizeof (char *), collated_compare);
    }

 out:
  if (__builtin_expect (RTMemAlloc_dirname, 0))
    RTMemFree (dirname);

  return retval;
}


/* Free storage allocated in PGLOB by a previous `glob' call.  */
void
disklib_globfree (pglob)
     register glob_t *pglob;
{
  if (pglob->gl_pathv != NULL)
    {
      size_t i;
      for (i = 0; i < pglob->gl_pathc; ++i)
    RTMemFree (pglob->gl_pathv[pglob->gl_offs + i]);
      RTMemFree (pglob->gl_pathv);
      pglob->gl_pathv = NULL;
    }
}

/* Do a collated comparison of A and B.  */
static int
collated_compare (const void *a, const void *b)
{
  const char *const s1 = *(const char *const * const) a;
  const char *const s2 = *(const char *const * const) b;

  if (s1 == s2)
    return 0;
  if (s1 == NULL)
    return 1;
  if (s2 == NULL)
    return -1;
  return strcoll (s1, s2);
}


/* Prepend DIRNAME to each of N members of ARRAY, replacing ARRAY's
   elements in place.  Return nonzero if out of memory, zero if successful.
   A slash is inserted between DIRNAME and each elt of ARRAY,
   unless DIRNAME is just "/".  Each old element of ARRAY is freed.  */
static int
prefix_array (const char *dirname, char **array, size_t n)
{
  register size_t i;
  size_t dirlen = strlen (dirname);
#if defined __MSDOS__ || defined WINDOWS32
  int sep_char = '/';
# define DIRSEP_CHAR sep_char
#else
# define DIRSEP_CHAR '/'
#endif

  if (dirlen == 1 && dirname[0] == '/')
    /* DIRNAME is just "/", so normal prepending would get us "//foo".
       We want "/foo" instead, so don't prepend any chars from DIRNAME.  */
    dirlen = 0;
#if defined __MSDOS__ || defined WINDOWS32
  else if (dirlen > 1)
    {
      if (dirname[dirlen - 1] == '/' && dirname[dirlen - 2] == ':')
    /* DIRNAME is "d:/".  Don't prepend the slash from DIRNAME.  */
    --dirlen;
      else if (dirname[dirlen - 1] == ':')
    {
      /* DIRNAME is "d:".  Use `:' instead of `/'.  */
      --dirlen;
      sep_char = ':';
    }
    }
#endif

  for (i = 0; i < n; ++i)
    {
      size_t eltlen = strlen (array[i]) + 1;
      char *new = (char *) RTMemAlloc (dirlen + 1 + eltlen);
      if (new == NULL)
    {
      while (i > 0)
        RTMemFree (array[--i]);
      return 1;
    }

      {
    char *endp = mempcpy (new, dirname, dirlen);
    *endp++ = DIRSEP_CHAR;
    mempcpy (endp, array[i], eltlen);
      }
      RTMemFree (array[i]);
      array[i] = new;
    }

  return 0;
}


/* We must not compile this function twice.  */
int
__glob_pattern_type (pattern, quote)
     const char *pattern;
     int quote;
{
  register const char *p;
  int ret = 0;

  for (p = pattern; *p != '\0'; ++p)
    switch (*p)
      {
      case '?':
      case '*':
    return 1;

      case '\\':
    if (quote)
      {
        if (p[1] != '\0')
          ++p;
        ret |= 2;
      }
    break;

      case '[':
    ret |= 4;
    break;

      case ']':
    if (ret & 4)
      return 1;
    break;
      }

  return ret;
}

static int
link_exists2_p (ntfs_fs_t fs, const char *dir, size_t dirlen, const char *fname,
           glob_t *pglob
        , int flags
        )
{
  size_t fnamelen = strlen (fname);
  char *fullname = (char *) RTMemAlloc(dirlen + 1 + fnamelen + 1);
  struct disklib_stat st64;
  int ret;

  /* pretend it exists and let caller care about error */
  if ( NULL == fullname )
    return 1;

  mempcpy (mempcpy (mempcpy (fullname, dir, dirlen), "/", 1),
       fname, fnamelen + 1);

  ret = (disklib_ntfs_stat(fs, fullname, &st64) == 0);
  RTMemFree(fullname);
  return ret;
}
#  define link_exists_p(fs, dfd, dirname, dirnamelen, fname, pglob, flags) \
  link_exists2_p (fs, dirname, dirnamelen, fname, pglob, flags)


/* Like `glob', but PATTERN is a final pathname component,
   and matches are searched for in DIRECTORY.
   The GLOB_NOSORT bit in FLAGS is ignored.  No sorting is ever done.
   The GLOB_APPEND flag is assumed to be set (always appends).  */
static int
glob_in_dir (ntfs_fs_t fs, const char *pattern,
         const char *directory, int flags,
         int (*errfunc) (const char *, int),
         glob_t *pglob, size_t alloca_used)
{
  size_t dirlen = strlen (directory);
  ntfs_dir_t stream = NULL;
  struct globnames
    {
      struct globnames *next;
      size_t count;
      char *name[64];
    };
#define INITIAL_COUNT sizeof (init_names.name) / sizeof (init_names.name[0])
  struct globnames init_names;
  struct globnames *names = &init_names;
  struct globnames *names_alloca = &init_names;
  size_t nfound = 0;
  size_t cur = 0;
  int meta;
  int save;

  alloca_used += sizeof (init_names);

  init_names.next = NULL;
  init_names.count = INITIAL_COUNT;

  meta = __glob_pattern_type (pattern, !(flags & GLOB_NOESCAPE));
  if (meta == 0 && (flags & (GLOB_NOCHECK|GLOB_NOMAGIC)))
    {
      /* We need not do any tests.  The PATTERN contains no meta
     characters and we must not return an error therefore the
     result will always contain exactly one name.  */
      flags |= GLOB_NOCHECK;
    }
  else if (meta == 0)
    {
      /* Since we use the normal file functions we can also use stat()
     to verify the file is there.  */
      union
      {
    struct disklib_stat st64;
      } ust;
      size_t patlen = strlen (pattern);
      char *fullname;
      int alloca_fullname = 0;
    {
      fullname = RTMemAlloc (dirlen + 1 + patlen + 1);
      if (fullname == NULL)
        return GLOB_NOSPACE;
    }

      mempcpy (mempcpy (mempcpy (fullname, directory, dirlen),
            "/", 1),
           pattern, patlen + 1);
      if (disklib_ntfs_stat(fs, fullname, &ust.st64) == 0)
    /* We found this file to be existing.  Now tell the rest
       of the function to copy this name into the result.  */
    flags |= GLOB_NOCHECK;

      if (__builtin_expect (!alloca_fullname, 0))
    RTMemFree (fullname);
    }
  else
    {
      stream = disklib_ntfs_opendir(fs, directory, pglob->gl_dirflags);
      if (stream == NULL)
    {
      if (disklib_errno() != DISKLIB_ERR_NOTDIR 
          && ((errfunc != NULL && (*errfunc) (directory, disklib_errno()))
          || (flags & GLOB_ERR)))
        return GLOB_ABORTED;
    }
      else
    {
      int fnm_flags = FNM_CASEFOLD | ((!(flags & GLOB_PERIOD) ? FNM_PERIOD : 0)
               | ((flags & GLOB_NOESCAPE) ? FNM_NOESCAPE : 0));
      unsigned int i;
      const char *name;
      flags |= GLOB_MAGCHAR;

      for(i = 0; (name = disklib_ntfs_readdir(stream, i)); i++)
        {
          size_t len;

          /* If we shall match only directories use the information
         provided by the dirent call if possible.  */
          if ((flags & GLOB_ONLYDIR) && !DIRENT_MIGHT_BE_DIR (d))
        continue;

          if (fnmatch (pattern, name, fnm_flags) == 0)
        {
          /* If the file we found is a symlink we have to
             make sure the target file exists.  */
          if (!DIRENT_MIGHT_BE_SYMLINK (d)
              || link_exists_p (fs, dfd, directory, dirlen, name, pglob,
                    flags))
            {
              if (cur == names->count)
            {
              struct globnames *newnames;
              size_t count = names->count * 2;
              size_t size = (sizeof (struct globnames)
                     + ((count - INITIAL_COUNT)
                        * sizeof (char *)));
              if ((newnames = RTMemAlloc (size))
                   == NULL)
                goto memory_error;
              newnames->count = count;
              newnames->next = names;
              names = newnames;
              cur = 0;
            }
              len = strlen(name);
              names->name[cur] = (char *) RTMemAlloc (len + 1);
              if (names->name[cur] == NULL)
            goto memory_error;
              *((char *) mempcpy (names->name[cur++], name, len))
            = '\0';
              ++nfound;
            }
        }
        }
    }
    }

  if (nfound == 0 && (flags & GLOB_NOCHECK))
    {
      size_t len = strlen (pattern);
      nfound = 1;
      names->name[cur] = (char *) RTMemAlloc (len + 1);
      if (names->name[cur] == NULL)
    goto memory_error;
      *((char *) mempcpy (names->name[cur++], pattern, len)) = '\0';
    }

  int result = GLOB_NOMATCH;
  if (nfound != 0)
    {
      result = 0;

      if (pglob->gl_pathc > UINTPTR_MAX - pglob->gl_offs
      || pglob->gl_pathc + pglob->gl_offs > UINTPTR_MAX - nfound
      || pglob->gl_pathc + pglob->gl_offs + nfound > UINTPTR_MAX - 1
      || (pglob->gl_pathc + pglob->gl_offs + nfound + 1
          > UINTPTR_MAX / sizeof (char *)))
    goto memory_error;

      char **new_gl_pathv;
      new_gl_pathv
    = (char **) RTMemRealloc (pglob->gl_pathv,
                 (pglob->gl_pathc + pglob->gl_offs + nfound + 1)
                 * sizeof (char *));
      if (new_gl_pathv == NULL)
    {
    memory_error:
      while (1)
        {
          struct globnames *old = names;
          size_t i;
          for (i = 0; i < cur; ++i)
        RTMemFree (names->name[i]);
          names = names->next;
          /* NB: we will not leak memory here if we exit without
         freeing the current block assigned to OLD.  At least
         the very first block is always allocated on the stack
         and this is the block assigned to OLD here.  */
          if (names == NULL)
        {
          Assert (old == &init_names);
          break;
        }
          cur = names->count;
          if (old == names_alloca)
        names_alloca = names;
          else
        RTMemFree (old);
        }
      result = GLOB_NOSPACE;
    }
      else
    {
      while (1)
        {
          struct globnames *old = names;
          size_t i;
          for (i = 0; i < cur; ++i)
        new_gl_pathv[pglob->gl_offs + pglob->gl_pathc++]
          = names->name[i];
          names = names->next;
          /* NB: we will not leak memory here if we exit without
         freeing the current block assigned to OLD.  At least
         the very first block is always allocated on the stack
         and this is the block assigned to OLD here.  */
          if (names == NULL)
        {
          Assert (old == &init_names);
          break;
        }
          cur = names->count;
          if (old == names_alloca)
        names_alloca = names;
          else
        RTMemFree (old);
        }

      pglob->gl_pathv = new_gl_pathv;

      pglob->gl_pathv[pglob->gl_offs + pglob->gl_pathc] = NULL;

      pglob->gl_flags = flags;
    }
    }

  if (stream != NULL)
    {
      save = disklib_errno();
      disklib_ntfs_closedir(stream);
      disklib__set_errno(save);
    }

  return result;
}

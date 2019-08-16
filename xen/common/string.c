/*
 *  linux/lib/string.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 */

#include <xen/types.h>
#include <xen/string.h>
#include <xen/ctype.h>

#ifndef __HAVE_ARCH_STRLCPY
/**
 * strlcpy - Copy a %NUL terminated string into a sized buffer
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 * @size: size of destination buffer
 *
 * Compatible with *BSD: the result is always a valid
 * NUL-terminated string that fits in the buffer (unless,
 * of course, the buffer size is zero). It does not pad
 * out the result like strncpy() does.
 */
size_t strlcpy(char *dest, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size-1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}
EXPORT_SYMBOL(strlcpy);
#endif

#ifndef __HAVE_ARCH_STRLCAT
/**
 * strlcat - Append a %NUL terminated string into a sized buffer
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 * @size: size of destination buffer
 *
 * Compatible with *BSD: the result is always a valid
 * NUL-terminated string that fits in the buffer (unless,
 * of course, the buffer size is zero).
 */
size_t strlcat(char *dest, const char *src, size_t size)
{
	size_t slen = strlen(src);
	size_t dlen = strnlen(dest, size);
	char *p = dest + dlen;

	while ((p - dest) < size)
		if ((*p++ = *src++) == '\0')
			break;

	if (dlen < size)
		*(p-1) = '\0';

	return slen + dlen;
}
EXPORT_SYMBOL(strlcat);
#endif

#ifndef __HAVE_ARCH_STRCMP
/**
 * strcmp - Compare two strings
 * @cs: One string
 * @ct: Another string
 */
int strcmp(const char * cs,const char * ct)
{
	register signed char __res;

	while (1) {
		if ((__res = *cs - *ct++) != 0 || !*cs++)
			break;
	}

	return __res;
}
#endif

#ifndef __HAVE_ARCH_STRNCMP
/**
 * strncmp - Compare two length-limited strings
 * @cs: One string
 * @ct: Another string
 * @count: The maximum number of bytes to compare
 */
int strncmp(const char * cs,const char * ct,size_t count)
{
	register signed char __res = 0;

	while (count) {
		if ((__res = *cs - *ct++) != 0 || !*cs++)
			break;
		count--;
	}

	return __res;
}
#endif

#ifndef __HAVE_ARCH_STRCHR
/**
 * strchr - Find the first occurrence of a character in a string
 * @s: The string to be searched
 * @c: The character to search for
 */
char * strchr(const char * s, int c)
{
	for(; *s != (char) c; ++s)
		if (*s == '\0')
			return NULL;
	return (char *) s;
}
#endif

#ifndef __HAVE_ARCH_STRRCHR
/**
 * strrchr - Find the last occurrence of a character in a string
 * @s: The string to be searched
 * @c: The character to search for
 */
char * strrchr(const char * s, int c)
{
       const char *p = s + strlen(s);
       do {
           if (*p == (char)c)
               return (char *)p;
       } while (--p >= s);
       return NULL;
}
#endif

#ifndef __HAVE_ARCH_STRLEN
/**
 * strlen - Find the length of a string
 * @s: The string to be sized
 */
size_t strlen(const char * s)
{
	const char *sc;

	for (sc = s; *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}
#endif

#ifndef __HAVE_ARCH_STRNLEN
/**
 * strnlen - Find the length of a length-limited string
 * @s: The string to be sized
 * @count: The maximum number of bytes to search
 */
size_t strnlen(const char * s, size_t count)
{
	const char *sc;

	for (sc = s; count-- && *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}
#endif

#ifndef __HAVE_ARCH_MEMCMP
/**
 * memcmp - Compare two areas of memory
 * @cs: One area of memory
 * @ct: Another area of memory
 * @count: The size of the area.
 */
int memcmp(const void * cs,const void * ct,size_t count)
{
	const unsigned char *su1, *su2;
	int res = 0;

	for( su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
		if ((res = *su1 - *su2) != 0)
			break;
	return res;
}
#endif

#ifndef __HAVE_ARCH_STRSTR
/**
 * strstr - Find the first substring in a %NUL terminated string
 * @s1: The string to be searched
 * @s2: The string to search for
 */
char * strstr(const char * s1,const char * s2)
{
	int l1, l2;

	l2 = strlen(s2);
	if (!l2)
		return (char *) s1;
	l1 = strlen(s1);
	while (l1 >= l2) {
		l1--;
		if (!memcmp(s1,s2,l2))
			return (char *) s1;
		s1++;
	}
	return NULL;
}
#endif

#ifndef __HAVE_ARCH_STRLLCPY
size_t
strllcpy(char *dest, size_t d_len, const char *src, size_t s_len)
{
	size_t ret = strnlen(src, s_len);

	if (d_len) {
		size_t len = (ret >= d_len) ? d_len-1 : ret;
		memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}
#endif

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 */

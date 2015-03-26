/******************************************************************************
 * string.c
 * 
 * These provide something for compiler-emitted string operations to link
 * against.
 */

#include <xen/config.h>
#include <xen/lib.h>

#ifndef __UXEN__
#undef memcpy
#endif  /* __UXEN__ */
void *memcpy(void *dest, const void *src, size_t n)
{
    long d0, d1, d2;

    asm volatile (
        "   rep ; movs"__OS" ; "
        "   mov %4,%3        ; "
        "   rep ; movsb        "
        : "=&c" (d0), "=&D" (d1), "=&S" (d2)
        : "0" (n/BYTES_PER_LONG), "r" (n%BYTES_PER_LONG), "1" (dest), "2" (src)
        : "memory" );

    return dest;
}

#ifndef __UXEN__
#undef memset
#endif  /* __UXEN__ */
void *memset(void *s, int c, size_t n)
{
    long d0, d1;

    asm volatile (
        "rep stosb"
        : "=&c" (d0), "=&D" (d1)
        : "a" (c), "1" (s), "0" (n)
        : "memory");

    return s;
}

#ifndef __UXEN__
#undef memmove
#endif  /* __UXEN__ */
void *memmove(void *dest, const void *src, size_t n)
{
    long d0, d1, d2;

    if ( dest < src )
        return memcpy(dest, src, n);

    asm volatile (
        "   std         ; "
        "   rep movsb   ; "
        "   cld           "
        : "=&c" (d0), "=&S" (d1), "=&D" (d2)
        : "0" (n), "1" (n-1+(const char *)src), "2" (n-1+(char *)dest)
        : "memory");

    return dest;
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

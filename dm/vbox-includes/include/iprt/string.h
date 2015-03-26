#ifndef _iprt_string_h
#define _iprt_string_h
#include <string.h>
#define RT_ZERO(Obj)        RT_BZERO(&(Obj), sizeof(Obj))
#define RT_BZERO(pv, cb)    do { memset((pv), 0, cb); } while (0)
#endif


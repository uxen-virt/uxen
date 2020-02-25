#ifndef __XEN_ERRNO_PRIVATE_H__
#define __XEN_ERRNO_PRIVATE_H__

#include <public/errno.h>

#define is_errno(e) ((e) >= EPERM && (e) <= ERETRY)
#define is_neg_errno(e) is_errno(-(e))

#endif


#ifndef _I386_ERRNO_H
#define _I386_ERRNO_H

#define	EPERM		 1	/* Operation not permitted */
#define	ENOENT		 2	/* No such file or directory */
#define	ESRCH		 3	/* No such process */
#define	EINTR		 4	/* Interrupted system call */
#define	EIO		 5	/* I/O error */
#define	ENXIO		 6	/* No such device or address */
#define	E2BIG		 7	/* Arg list too long */
#define	EAGAIN		11	/* Try again */ /* XXX osx 35 */
#define	ENOMEM		12	/* Out of memory */
#define	EACCES		13	/* Permission denied */
#define	EFAULT		14	/* Bad address */
#define	EBUSY		16	/* Device or resource busy */
#define	EEXIST		17	/* File exists */
#define	ENODEV		19	/* No such device */
#define	EINVAL		22	/* Invalid argument */
#define	ENOSPC		28	/* No space left on device */
#define	ERANGE		34	/* Math result not representable */
#define	ENOSYS		40	/* Function not implemented */ /* XXX osx 78 */
#define EMSGSIZE        90      /* Message too long */ /* XXX osx 40 */
#define ECONNREFUSED    111     /* Connection refused */ /* XXX osx 61 */

#define ECONTINUATION   129     /* pseudo error code: retry after
                                 * scheduling */
#define EPREEMPT        130     /* pseudo error code: retry because of
                                 * preemption */
#define EMAPPAGERANGE   131     /* pseudo error code: retry after
                                 * handling pending map range
                                 * request */
#define ERETRY          132     /* pseudo error code: generic retry from
                                   hypercall_create_retry_continuation */

#define is_errno(e) ((e) >= EPERM && (e) <= ERETRY)
#define is_neg_errno(e) is_errno(-(e))

#endif

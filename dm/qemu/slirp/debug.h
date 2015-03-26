/*
 * Copyright (c) 1995 Danny Gasparovski.
 *
 * Please read the file COPYRIGHT for the
 * terms and conditions of the copyright.
 */

//#define DEBUG 1

#ifdef DEBUG

#define DBG_CALL 0x1
#define DBG_MISC 0x2
#define DBG_ERROR 0x4
#define DBG_XTRA 0x8
#define DBG_MBUF 0x10
#define DBG_ARP 0x20
#define DBG_VERBOSE 0x40

#define dfd stderr

extern int slirp_debug;

#if 0
#define _DEBUG_PRINT(dfd, fmt, ...) do { fprintf(dfd, fmt, ## __VA_ARGS__); fflush(dfd); } while (0)
#else
#define _DEBUG_PRINT(dfd, fmt, ...) term_printf(fmt, ## __VA_ARGS__)
#endif

#ifdef _WIN32
#define _DEBUG_RESTORE_ERRNO(old_errno) WSASetLastError(old_errno)
#else
#define _DEBUG_RESTORE_ERRNO(old_errno) errno = old_errno
#endif

#define DEBUG_PRINT(dfd, fmt, ...) do {		\
    int old_errno = errno;			\
    _DEBUG_PRINT(dfd, fmt, ## __VA_ARGS__);	\
    _DEBUG_RESTORE_ERRNO(old_errno);		\
  } while (0)

#define DEBUG_CALL(dfd, fmt, ...) if (slirp_debug & DBG_CALL) DEBUG_PRINT(dfd, fmt "\n", ## __VA_ARGS__)
#define DEBUG_CALL_MORE(dfd, fmt, ...) if (slirp_debug & DBG_CALL) DEBUG_PRINT(dfd, fmt, ## __VA_ARGS__)
#define DEBUG_MISC(dfd, fmt, ...) if (slirp_debug & DBG_MISC) DEBUG_PRINT(dfd, fmt "\n", ## __VA_ARGS__)
#define DEBUG_ERROR(dfd, fmt, ...) if (slirp_debug & DBG_ERROR) DEBUG_PRINT(dfd, fmt "\n", ## __VA_ARGS__)
#define DEBUG_XTRA(dfd, fmt, ...) if (slirp_debug & DBG_XTRA) DEBUG_PRINT(dfd, fmt "\n", ## __VA_ARGS__)
#define DEBUG_MBUF(dfd, fmt, ...) if (slirp_debug & DBG_MBUF) DEBUG_PRINT(dfd, fmt "\n", ## __VA_ARGS__)
#define DEBUG_ARP(dfd, fmt, ...) if (slirp_debug & DBG_ARP) DEBUG_PRINT(dfd, fmt "\n", ## __VA_ARGS__)
#define DEBUG_VERBOSE(dfd, fmt, ...) if (slirp_debug & DBG_VERBOSE) DEBUG_PRINT(dfd, fmt "\n", ## __VA_ARGS__)

#else

#define DEBUG_CALL(dfd, fmt, ...)
#define DEBUG_CALL_MORE(dfd, fmt, ...)
#define DEBUG_MISC(dfd, fmt, ...)
#define DEBUG_ERROR(dfd, fmt, ...)
#define DEBUG_XTRA(dfd, fmt, ...)
#define DEBUG_MBUF(dfd, fmt, ...)
#define DEBUG_ARP(dfd, fmt, ...)
#define DEBUG_VERBOSE(dfd, fmt, ...)

#endif

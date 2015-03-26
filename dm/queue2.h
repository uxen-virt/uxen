/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)queue.h	8.5 (Berkeley) 8/20/94
 */
/*
 * uXen changes:
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef	_SYS_QUEUE2_H_
#define	_SYS_QUEUE2_H_

/*
 * List definitions.
 */
#define	RLIST_HEAD(name, type)						\
struct name {								\
union {									\
	struct type *le_next;	/* first element */			\
	struct type *lh_first;						\
};									\
union {									\
	struct type *le_prev;	/* last element */			\
	struct type *lh_last;						\
};									\
}

#define	RLIST_HEAD_INITIALIZER(head)					\
	{ &(head), &(head) }

#define RLIST_HEAD_INIT(s, field, type)  do {                           \
            (s)->field.lh_first = (struct type *) s;                    \
            (s)->field.lh_last  = (struct type *) s;                    \
        } while (1 == 0)

#define	RLIST_ENTRY(name)						\
struct name

/*
 * List functions.
 */
#if defined(_KERNEL) && defined(QUEUEDEBUG)
#define	QUEUEDEBUG_RLIST_INSERT_HEAD(head, elm, field)			\
	if ((head)->lh_first &&						\
	    (head)->lh_first->field.le_prev != &(head)->lh_first)	\
		panic("RLIST_INSERT_HEAD %p %s:%d", (head), __FILE__, __LINE__);
#define	QUEUEDEBUG_RLIST_OP(elm, field)					\
	if ((elm)->field.le_next &&					\
	    (elm)->field.le_next->field.le_prev !=			\
	    &(elm)->field.le_next)					\
		panic("RLIST_* forw %p %s:%d", (elm), __FILE__, __LINE__);\
	if (*(elm)->field.le_prev != (elm))				\
		panic("RLIST_* back %p %s:%d", (elm), __FILE__, __LINE__);
#define	QUEUEDEBUG_RLIST_POSTREMOVE(elm, field)				\
	(elm)->field.le_next = (void *)1L;				\
	(elm)->field.le_prev = (void *)1L;
#else
#define	QUEUEDEBUG_RLIST_INSERT_HEAD(head, elm, field)
#define	QUEUEDEBUG_RLIST_OP(elm, field)
#define	QUEUEDEBUG_RLIST_POSTREMOVE(elm, field)
#endif

#define	RLIST_INIT(head, field) do {					\
	(head)->field.lh_first = (void *)head;				\
	(head)->field.lh_last = (void *)head;				\
} while (/*CONSTCOND*/0)

#define	RLIST_INSERT_AFTER(listelm, elm, field) do {			\
	(elm)->field.le_next = (listelm)->field.le_next;		\
	(elm)->field.le_prev = (listelm);				\
	(listelm)->field.le_next->field.le_prev = (elm);		\
	(listelm)->field.le_next = (elm);				\
} while (/*CONSTCOND*/0)

#define	RLIST_INSERT_BEFORE(listelm, elm, field) do {			\
	(elm)->field.le_next = (void *) (listelm);			\
	(elm)->field.le_prev = (listelm)->field.le_prev;		\
	(listelm)->field.le_prev->field.le_next = (elm);		\
	(listelm)->field.le_prev = (elm);				\
} while (/*CONSTCOND*/0)

#define	RLIST_INSERT_HEAD(head, elm, field)				\
	RLIST_INSERT_AFTER(head, elm, field)

#define	RLIST_INSERT_TAIL(head, elm, field)				\
	RLIST_INSERT_BEFORE(head, elm, field)

#define	RLIST_REMOVE(elm, field) do {					\
	(elm)->field.le_next->field.le_prev = (elm)->field.le_prev; 	\
	(elm)->field.le_prev->field.le_next = (elm)->field.le_next;	\
	RLIST_INIT(elm, field);                                         \
} while (/*CONSTCOND*/0)

#define	RLIST_FOREACH(var, head, field)					\
	for ((var) = RLIST_FIRST((head), field);			\
	     (var) != (void *)(head) || ((var) = NULL, 0);		\
	     (var) = RLIST_NEXT((var), field))

#define	RLIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = RLIST_FIRST((head), field);			\
	     ((var) != (head) && ((tvar) = RLIST_NEXT((var), field), 1)) || \
		     ((var) = NULL, 0);					\
	     (var) = (tvar))

#define	RLIST_FOREACH_REVERSE(var, head, field)				\
	for ((var) = RLIST_LAST((head), field);				\
	     (var) != (head) || ((var) = NULL, 0);			\
	     (var) = RLIST_PREV((var), field))

#define	RLIST_FOREACH_REVERSE_SAFE(var, head, field, tvar)		\
	for ((var) = RLIST_LAST((head), field);				\
	     ((var) != (head) && ((tvar) = RLIST_PREV((var), field), 1)) || \
		     ((var) = NULL, 0);					\
	     (var) = (tvar))

/*
 * List access methods.
 */
#define	RLIST_EMPTY(head, field)	((head)->field.lh_first == (void *)(head))
#define	RLIST_FIRST(head, field)	((head)->field.lh_first)
#define	RLIST_LAST(head, field)		((head)->field.lh_last)
#define	RLIST_NEXT(elm, field)		((elm)->field.le_next)
#define	RLIST_PREV(elm, field)		((elm)->field.le_prev)
#define RLIST_START(head)               ((void *)(head))
#define RLIST_END(head)                 ((void *)(head))
#define	RLIST_STARTP(elm, head)		((elm) && (elm) == (void *)(head))
#define	RLIST_ENDP(elm, head)		((elm) && (elm) == (void *)(head))

#endif	/* !_SYS_QUEUE2_H_ */

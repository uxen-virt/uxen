/*
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#ifndef _OPTS_H_
#define _OPTS_H_

#include "queue.h"
#include "yajl.h"

// typedef struct QemuOpt QemuOpt;
typedef struct yajl_val_s QemuOpts;

enum QemuOptType {
    QEMU_OPT_STRING = 0,  /* no parsing (use string as-is)                        */
    QEMU_OPT_BOOL,        /* on/off                                               */
    QEMU_OPT_NUMBER,      /* simple number                                        */
    QEMU_OPT_SIZE,        /* size, accepts (K)ilo, (M)ega, (G)iga, (T)era postfix */
};

typedef struct QemuOptDesc {
    const char *name;
    enum QemuOptType type;
    const char *help;
} QemuOptDesc;

typedef struct QemuOptsList {
    const char *name;
    TAILQ_HEAD(,QemuOpts) head;
    QemuOptDesc desc[];
} QemuOptsList;

#define qemu_opt_get(o, key) yajl_object_get_string(o, (key))
#define qemu_opt_get_bool(o, key, defval)               \
    yajl_object_get_bool_default(o, (key), (defval))
#define qemu_opt_get_number(o, key, defval)			\
    yajl_object_get_integer_default(o, (key), (defval))
#define qemu_opt_set(o, key, val)               \
    yajl_object_set_string(o, (key), (val))
#define qemu_opts_id(o) qemu_opt_get(o, "id")
#define qemu_opts_validate(o, d) 0
#define qemu_opts_create(l, id, fail_if_exists) \
    yajl_object_create()
#define qemu_opts_del(o)                        \
    yajl_object_destroy(o)

typedef int (*_opt_loopfunc)(const char *name, const char *value, void *opaque);
#define _dict_opt_foreach(o, func, opaque, aof, want_object) ({		\
	    int i, rc = 0;						\
	    for (i = 0; i < (o)->u.object.len; i++) {			\
		const char *key = (o)->u.object.keys[i];		\
		rc = (func)(key, (want_object) ?			\
			    (void *)(o)->u.object.values[i] :		\
			    (void *)qemu_opt_get((o), key), (opaque));	\
		if ((aof) && rc)					\
		    break;						\
	    }								\
	    rc;								\
	})
#define dict_opt_foreach(o, func, opaque, aof)  \
    _dict_opt_foreach((o), (func), (opaque), (aof), 0)

#define qemu_opt_foreach(o, func, opaque, aof)	\
    _dict_opt_foreach((o), (func), (opaque), (aof), 0)
#define qemu_opt_foreach_object(o, func, opaque, aof)	\
    _dict_opt_foreach((o), (func), (opaque), (aof), 1)

#endif	/* _OPTS_H_ */

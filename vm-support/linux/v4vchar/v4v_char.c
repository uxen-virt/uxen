/*
 * Copyright 2020, Bromium, Inc.
 * Author: Simon Haggett <simon.haggett@gmail.com>
 * SPDX-License-Identifier: ISC
 */

#include <linux/module.h>
#include <linux/slab.h>

#include "v4v_char.h"
#include "v4v_char_device.h"
#include "v4v_char_v4v.h"

static uint32_t v4v_port = 0;
module_param(v4v_port, uint, 0);
MODULE_PARM_DESC(v4v_port, "The V4V port to bind to");

static char *device_name = KBUILD_MODNAME;
module_param(device_name, charp, 0);
MODULE_PARM_DESC(device_name, "The character device name to use");

/*
 * \brief The context instance used by this module.
 *
 * Kernel memory for this instance is allocated during module initialisation, and maintained for the lifetime of this
 * module. This instance is global so that it is accessible to the module exit function (which takes no parameters).
 */
static struct v4v_char_context *v4vc_context;

static void v4vc_context_free(struct v4v_char_context *context)
{
    v4v_char_device_free(context);
    v4v_char_v4v_free(context);
    kfree(context);
}

static int __init v4v_char_init(void)
{
    int ret = 0;

    v4vc_context = kzalloc(sizeof(struct v4v_char_context), GFP_KERNEL);
    if (unlikely(!v4vc_context))
    {
        printk(V4VC_ERR "failed to allocate memory for context\n");
        goto fail;
    }

    ret = v4v_char_v4v_init(v4vc_context, v4v_port);
    if (unlikely(ret))
    {
        printk(V4VC_ERR "error %i initialising V4V\n", ret);
        goto fail;
    }

    ret = v4v_char_device_init(v4vc_context, device_name);
    if (unlikely(ret))
    {
        printk(V4VC_ERR "error %i initialising device\n", ret);
        goto fail;
    }

    return ret;

fail:
    v4vc_context_free(v4vc_context);
    return ret;
}

static void __exit v4v_char_exit(void)
{
    v4vc_context_free(v4vc_context);
}

module_init(v4v_char_init);
module_exit(v4v_char_exit);

MODULE_AUTHOR("simon.haggett@bromium.com");
MODULE_DESCRIPTION("V4V Character Device");
MODULE_LICENSE("GPL");

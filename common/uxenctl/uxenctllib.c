/*
 *  uxenctllib.c
 *  uxen
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#if defined(_WIN32)
#define ERR_WINDOWS
#define ERR_NO_PROGNAME
#define ERR_STDERR _uxenctllib_stderr
#endif
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

#include "uxenctllib.h"

int uxen_ioctl(UXEN_HANDLE_T h, uint64_t ctl, ...);
#if defined(_WIN32)
#include <winioctl.h>
#endif
#include <uxen_ioctl.h>

#include <uuid/uuid.h>

#include <xen/xen.h>
#include <xen/version.h>
#ifdef _WIN32
#include <xen/domctl.h>
#endif
#include <xen/sysctl.h>

#ifdef _WIN32
FILE *_uxenctllib_stderr = NULL;

void
uxen_set_logfile(FILE *f)
{

    _uxenctllib_stderr = f;
}
#endif

int
uxen_init(UXEN_HANDLE_T h, const struct uxen_init_desc *uid)
{
    int ret;
    struct uxen_init_desc _uid = { };

    if (!uid)
        uid = &_uid;
    ret = uxen_ioctl(h, UXENINIT, uid);
    if (ret)
	warn("ioctl(UXENINIT)");

    return ret;
}

int
uxen_shutdown(UXEN_HANDLE_T h)
{
    int ret;

    ret = uxen_ioctl(h, UXENSHUTDOWN);
    if (ret)
	warn("ioctl(UXENSHUTDOWN)");

    return ret;
}

int
uxen_wait_vm_exit(UXEN_HANDLE_T h)
{
    int ret;

    ret = uxen_ioctl(h, UXENWAITVMEXIT);
    if (ret)
        warn("ioctl(UXENWAITVMEXIT)");

    return ret;
}

int
uxen_load(UXEN_HANDLE_T h, const char *filename)
{
#if defined(__APPLE__)
    int ret;
    int file_fd = -1;
    struct stat statbuf;
    struct uxen_load_desc uld = { };
    uint8_t *uvaddr = NULL;

    if (_uxenctllib_stderr)
        fprintf(_uxenctllib_stderr, "loading hypervisor binary \"%s\"\n",
                filename);

    memset(&uld, 0, sizeof(uld));

    ret = open(filename, O_RDONLY | O_BINARY);
    if (ret < 0) {
	warn("open %s", filename);
	goto out;
    }
    file_fd = ret;

    ret = fstat(file_fd, &statbuf);
    if (ret) {
	warn("fstat %s", filename);
	goto out;
    }

    uld.uld_size = statbuf.st_size;
    uvaddr = (uint8_t *)malloc(uld.uld_size);
    if (uvaddr == NULL) {
	warn("malloc %d", uld.uld_size);
	ret = -1;
	goto out;
    }
    set_xen_guest_handle(uld.uld_uvaddr, uvaddr);

    ret = read(file_fd, uvaddr, uld.uld_size);
    if (ret != uld.uld_size) {
	warn("read %d from %s, got %d", uld.uld_size, filename, ret);
	goto out;
    }

    ret = uxen_ioctl(h, UXENLOAD, &uld);
    if (ret)
	warn("ioctl(UXENLOAD)");

  out:
    if (uvaddr)
	free(uvaddr);
    if (file_fd >= 0)
	close(file_fd);
    return ret;
#elif defined(_WIN32)
    _set_errno(EINVAL);
    return -1;
#endif
}

int
uxen_unload(UXEN_HANDLE_T h)
{
#if defined(__APPLE__)
    int ret;

    ret = uxen_ioctl(h, UXENUNLOAD);
    if (ret)
	warn("ioctl(UXENUNLOAD)");

    return ret;
#elif defined(_WIN32)
    _set_errno(EINVAL);
    return -1;
#endif
}

int
uxen_output_version_info(UXEN_HANDLE_T h, FILE *f)
{
    int ret;
    struct uxen_version_desc uvd = { };
    struct uxen_hypercall_desc uhd = { };
    xen_extraversion_t xen_extraversion;
    xen_changeset_info_t xen_chgset;
    void *buf = NULL;

    ret = uxen_ioctl(h, UXENVERSION, &uvd);
    if (ret) {
	warn("ioctl(UXENVERSION)");
	goto out;
    }

    if (f)
	fprintf(f, "uxen driver version %d.%d%c%s\n",
		uvd.uvd_driver_version_major, uvd.uvd_driver_version_minor,
		uvd.uvd_driver_version_tag[0] ? '-' : '\n',
		uvd.uvd_driver_version_tag);

    buf = uxen_malloc(h, 1);
    if (!buf) {
        warn("uxen_malloc failed");
        ret = -1;
        goto out;
    }

    uhd.uhd_op = __HYPERVISOR_xen_version;
    uhd.uhd_arg[0] = XENVER_extraversion;
    uhd.uhd_arg[1] = (uint64_t)(uintptr_t)buf;
    ret = uxen_hypercall(h, &uhd);
    if (ret < 0) {
	warn("hypercall(HYPERVISOR_xen_version,XENVER_extraversion)");
	ret = -1;
	goto out;
    }
    memcpy(&xen_extraversion, buf, sizeof(xen_extraversion));

    uhd.uhd_op = __HYPERVISOR_xen_version;
    uhd.uhd_arg[0] = XENVER_version;
    ret = uxen_hypercall(h, &uhd);
    if (ret < 0) {
	warn("hypercall(HYPERVISOR_xen_version,XENVER_version)");
	ret = -1;
	goto out;
    }

    if (f)
	fprintf(f, "uxen core version %d.%d%.*s\n", ret >> 16, (uint16_t)ret,
		(int)XEN_EXTRAVERSION_LEN, xen_extraversion);

    uhd.uhd_op = __HYPERVISOR_xen_version;
    uhd.uhd_arg[0] = XENVER_changeset;
    uhd.uhd_arg[1] = (uint64_t)(uintptr_t)buf;
    ret = uxen_hypercall(h, &uhd);
    if (ret < 0) {
	warn("hypercall(HYPERVISOR_xen_version,XENVER_changeset)");
	ret = -1;
	goto out;
    }
    memcpy(&xen_chgset, buf, sizeof(xen_chgset));

    if (f)
	fprintf(f, "uxen core changeset %.*s\n",
		(int)XEN_CHANGESET_INFO_LEN, xen_chgset);

    ret = 0;
  out:
    if (buf)
        uxen_free(h, buf, 1);

    return ret;
}

int
uxen_trigger_keyhandler(UXEN_HANDLE_T h, const char *keys)
{
    int ret;
    char keys_arg[UXEN_MAX_KEYHANDLER_KEYS];

    if (strlen(keys) > UXEN_MAX_KEYHANDLER_KEYS)
        warn("%s: too many keys", __FUNCTION__);

    strncpy(keys_arg, keys, UXEN_MAX_KEYHANDLER_KEYS);
    ret = uxen_ioctl(h, UXENKEYHANDLER, keys_arg);
    if (ret)
	warn("ioctl(UXENKEYHANDLER)");

    return ret;
}

int
uxen_power(UXEN_HANDLE_T h, uint32_t suspend)
{
    int ret;

    ret = uxen_ioctl(h, UXENPOWER, &suspend);
    if (ret)
        warn("ioctl(UXENPOWER,%x)", suspend);

    return ret;
}

int
uxen_hypercall(UXEN_HANDLE_T h, struct uxen_hypercall_desc *uhd)
{
    uint64_t op = uhd->uhd_op;
    int ret;

    ret = uxen_ioctl(h, UXENHYPERCALL, uhd);
    if (ret)
        warn("ioctl(UXENHYPERCALL,%"PRIx64")", op);
    else
        ret = uhd->uhd_op;

    return ret;
}

int
uxen_create_vm(UXEN_HANDLE_T h, xen_domain_handle_t vm_uuid,
               uint32_t create_flags, uint32_t create_ssidref,
               uint32_t max_vcpus, uint32_t *domid)
{
    int ret;
    struct uxen_createvm_desc ucd = { };

#ifdef _WIN32
    if (!(create_flags & XEN_DOMCTL_CDF_template)) {
        ret = uxen_processexit_helper(h);
        if (ret < 0) {
            warn("%s: uxen_processexit_helper", __FUNCTION__);
            goto out;
        }
    }
#endif

    memcpy(ucd.ucd_vmuuid, vm_uuid, sizeof(xen_domain_handle_t));
    ucd.ucd_create_flags = create_flags;
    ucd.ucd_create_ssidref = create_ssidref;
    ucd.ucd_max_vcpus = max_vcpus;

    ret = uxen_ioctl(h, UXENCREATEVM, &ucd);
    if (ret) {
	warn("ioctl(UXENCREATEVM)");
	goto out;
    }

    if (domid)
        *domid = ucd.ucd_domid;
  out:
    return ret;
}

void *
uxen_malloc(UXEN_HANDLE_T h, uint32_t npages)
{
    struct uxen_malloc_desc umd = { };
    void *addr = NULL;
    int ret;

    memset(&umd, 0, sizeof(struct uxen_malloc_desc));
    umd.umd_npages = npages;

    ret = uxen_ioctl(h, UXENMALLOC, &umd);
    if (ret) {
        warn("ioctl(UXENMALLOC)");
        goto out;
    }

    addr = (void *)(uintptr_t)umd.umd_addr;

  out:
    return addr;
}

int
uxen_free(UXEN_HANDLE_T h, void *addr, uint32_t npages)
{
    struct uxen_free_desc ufd = { };
    int ret;

    memset(&ufd, 0, sizeof(struct uxen_free_desc));
    ufd.ufd_addr = (uint64_t)(uintptr_t)addr;
    ufd.ufd_npages = npages;

    ret = uxen_ioctl(h, UXENFREE, &ufd);
    if (ret)
        warn("ioctl(UXENFREE)");

    return ret;
}

int
uxen_mmapbatch(UXEN_HANDLE_T h, struct uxen_mmapbatch_desc *umd)
{
    int ret;

    ret = uxen_ioctl(h, UXENMMAPBATCH, umd);
    if (ret)
	warn("ioctl(UXENMMAPBATCH)");

    return ret;
}

int
uxen_munmap(UXEN_HANDLE_T h, struct uxen_munmap_desc *umd)
{
    int ret;

    ret = uxen_ioctl(h, UXENMUNMAP, umd);
    if (ret)
	warn("ioctl(UXENMUNMAP)");

    return ret;
}

int
uxen_target_vm(UXEN_HANDLE_T h, xen_domain_handle_t vm_uuid)
{
    int ret;
    struct uxen_targetvm_desc utd = { };

    memset(&utd, 0, sizeof(utd));

    memcpy(utd.utd_vmuuid, vm_uuid, sizeof(xen_domain_handle_t));

    ret = uxen_ioctl(h, UXENTARGETVM, &utd);
    if (ret) {
	warn("ioctl(UXENTARGETVM)");
	goto out;
    }

    ret = utd.utd_domid;
  out:
    return ret;
}

int
uxen_destroy_vm(UXEN_HANDLE_T h, xen_domain_handle_t vm_uuid)
{
    int ret;
    struct uxen_destroyvm_desc udd = { };

    memset(&udd, 0, sizeof(udd));

    memcpy(udd.udd_vmuuid, vm_uuid, sizeof(xen_domain_handle_t));

    ret = uxen_ioctl(h, UXENDESTROYVM, &udd);
    if (ret && errno != EAGAIN)
	warn("ioctl(UXENDESTROYVM)");

    return ret;
}

int
uxen_execute(UXEN_HANDLE_T h, struct uxen_execute_desc *ued)
{
    int ret;

    ret = uxen_ioctl(h, UXENEXECUTE, ued);
    if (ret)
	warn("ioctl(UXENEXECUTE)");

    return ret;
}

int
uxen_setup_event(UXEN_HANDLE_T h, struct uxen_event_desc *ued)
{
    int ret;

    ret = uxen_ioctl(h, UXENSETEVENT, ued);
    if (ret)
	warn("ioctl(UXENSETEVENT)");

    return ret;
}

int
uxen_setup_host_event_channel(UXEN_HANDLE_T h,
                              struct uxen_event_channel_desc *uecd)
{
    int ret;

    ret = uxen_ioctl(h, UXENSETEVENTCHANNEL, uecd);
    if (ret)
	warn("ioctl(UXENSETEVENTCHANNEL)");

    return ret;
}

int
uxen_memcacheinit(UXEN_HANDLE_T h, int end_low_pfn,
                  int start_high_pfn, int end_high_pfn,
                  uint8_t **va,
                  volatile uint32_t **pfn_to_entry)
{
    struct uxen_memcacheinit_desc umd = { };
    int ret;

    umd.end_low_gpfn = end_low_pfn;
    umd.start_high_gpfn = start_high_pfn;
    umd.end_high_gpfn = end_high_pfn;
    ret = uxen_ioctl(h, UXENMEMCACHEINIT, &umd);
    if (ret) {
	warn("ioctl(UXENMEMCACHEINIT)");
        goto out;
    }

    *va = umd.va;
    *pfn_to_entry = umd.pfn_to_entry;

  out:
    return ret;
}

int
uxen_memcachemap(UXEN_HANDLE_T h, uint32_t domid, uint32_t pfn, uint32_t nr_pfn)
{
    struct uxen_memcachemap_desc umd = { };
    int ret;

    umd.pfn = pfn;
    umd.nr_pfn = nr_pfn;
    ret = uxen_ioctl(h, UXENMEMCACHEMAP, &umd);
    if (ret)
	warn("ioctl(UXENMEMCACHEMAP)");

    return ret;
}

int
uxen_enum_vms(UXEN_HANDLE_T h, int (*cb)(struct uxen_queryvm_desc *, void *),
              void *cb_opaque)
{
    struct uxen_queryvm_desc uqd = { };
    int ret;

    uqd.uqd_domid = 0;

    for (;;) {
	ret = uxen_ioctl(h, UXENQUERYVM, &uqd);
	if (ret) {
	    warn("ioctl(UXENQUERYVM)");
	    goto out;
	}

	if (uqd.uqd_domid == (domid_t)-1)
	    break;

        ret = cb(&uqd, cb_opaque);
        if (ret < 0)
            break;

	uqd.uqd_domid++;
    }

 out:
    return ret;
}

int
uxen_logging(UXEN_HANDLE_T h, uint32_t size, UXEN_EVENT_HANDLE_T event,
             struct uxen_logging_buffer **logbuf)
{
    struct uxen_logging_desc uld = { };
    int ret;

    uld.uld_size = size;
    uld.uld_event = event;

    ret = uxen_ioctl(h, UXENLOGGING, &uld);
    if (ret) {
        warn("ioctl(UXENLOGGING)");
        goto out;
    }

    *logbuf = uld.uld_buffer;

  out:
    return ret;
}

#define pos_of(x) ((x) & 0xffffffffULL)
#define ovfl_of(x) ((x) & ~0xffffffffULL)
#define wrap_of(x) (ovfl_of(x) + 0x100000000ULL)

char *
uxen_logging_read(struct uxen_logging_buffer *logbuf, uint64_t *reader,
                  uint32_t *incomplete)
{
    char *buf = NULL;
    uint64_t cons, prod;
    uint32_t a1, a2;

    if (incomplete)
        *incomplete = 0;

  again:
    prod = logbuf->ulb_producer;
    if (*reader == prod)
        return NULL;

    cons = logbuf->ulb_consumer;
    if (cons > *reader && !(wrap_of(cons) == ovfl_of(*reader) &&
                            pos_of(*reader) <= pos_of(cons))) {
        if (incomplete)
            *incomplete = 1;
        *reader = cons;
    }

    a1 = pos_of(prod) > pos_of(*reader) ? pos_of(prod) - pos_of(*reader) :
        strnlen(&logbuf->ulb_buffer[pos_of(*reader)],
                logbuf->ulb_size - pos_of(*reader));
    a2 = pos_of(prod) < pos_of(*reader) ? pos_of(prod) : 0;

    buf = calloc(1, a1 + a2 + 1);
    if (!buf) {
        warnx("%s: calloc(,%d) failed", __FUNCTION__, a1 + a2 + 1);
        return NULL;
    }

    memcpy(buf, &logbuf->ulb_buffer[pos_of(*reader)], a1);
    buf[a1] = 0;
    if (a2) {
        memcpy(&buf[a1], &logbuf->ulb_buffer[0], a2);
        buf[a1 + a2] = 0;
    }

    cons = logbuf->ulb_consumer;
    if (cons > *reader && !(wrap_of(cons) == ovfl_of(*reader) &&
                            pos_of(*reader) <= pos_of(cons))) {
        unsigned int trim = 0;
        if (ovfl_of(cons) != ovfl_of(*reader)) {
            trim += a1;
            *reader = wrap_of(*reader);
            if (ovfl_of(cons) != ovfl_of(*reader)) {
                *reader = cons;
                free(buf);
                if (incomplete)
                    *incomplete = 1;
                goto again;
            }
        }
        trim += pos_of(cons - *reader);
        if (trim >= a1 + a2) {
            /* sanity check: this shouldn't/can't happen */
            *reader = cons;
            free(buf);
            if (incomplete)
                *incomplete = 1;
            goto again;
        }
        memmove(buf, &buf[trim], a1 + a2 + 1 - trim);
        if (incomplete)
            *incomplete = 1;
    }

    *reader = prod;

    return buf;
}

int
uxen_map_host_pages(UXEN_HANDLE_T h, void *va, size_t len, uint64_t gmfn)
{
    struct uxen_map_host_pages_desc umhpd = { };
    int ret;

    umhpd.umhpd_va = va;
    umhpd.umhpd_len = len;
    umhpd.umhpd_gmfn = gmfn;

    ret = uxen_ioctl(h, UXENMAPHOSTPAGES, &umhpd);
    if (ret)
        warn("ioctl(UXENMAPHOSTPAGES)");

    return ret;
}

int
uxen_unmap_host_pages(UXEN_HANDLE_T h, void *va, size_t len)
{
    struct uxen_map_host_pages_desc umhpd = { };
    int ret;

    umhpd.umhpd_va = va;
    umhpd.umhpd_len = len;

    ret = uxen_ioctl(h, UXENUNMAPHOSTPAGES, &umhpd);
    if (ret)
        warn("ioctl(UXENUNMAPHOSTPAGES)");

    return ret;
}

int
uxen_physinfo(UXEN_HANDLE_T h, uxen_physinfo_t *up)
{
    int ret;
    struct uxen_hypercall_desc uhd = { };
    struct xen_sysctl *xs;
    void *buf = NULL;

    buf = uxen_malloc(h, 1);
    if (!buf) {
        warn("uxen_malloc failed");
        ret = -1;
        goto out;
    }

    xs = (struct xen_sysctl *)buf;
    xs->interface_version = XEN_SYSCTL_INTERFACE_VERSION;
    xs->cmd = XEN_SYSCTL_physinfo;
    memcpy(&xs->u.physinfo, up, sizeof(*up));

    uhd.uhd_op = __HYPERVISOR_sysctl;
    uhd.uhd_arg[0] = (uint64_t)(uintptr_t)buf;
    ret = uxen_hypercall(h, &uhd);
    if (ret < 0) {
	warn("hypercall(HYPERVISOR_sysctl,XEN_SYSCTL_physinfo)");
	ret = -1;
	goto out;
    }
    memcpy(up, &xs->u.physinfo, sizeof(*up));

  out:
    if (buf)
        uxen_free(h, buf, 1);
    return ret;
}

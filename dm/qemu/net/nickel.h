#ifndef QEMU_NET_NICKEL_H
#define QEMU_NET_NICKEL_H

#include <dm/qemu_glue.h>
#ifdef CONFIG_NICKEL

int net_init_nickel(QemuOpts *opts,
                   Monitor *mon,
                   const char *name,
                   VLANState *vlan);

#endif

#endif /* QEMU_NET_NICKEL_H */

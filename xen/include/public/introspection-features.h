/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#ifndef __INTROSPECTION_FEATURES_H
#define __INTROSPECTION_FEATURES_H

/* The following six features are set via domctl, based on vm config */
#define XEN_DOMCTL_INTROSPECTION_FEATURE_CR0WPCLEAR (1<<0)
#define XEN_DOMCTL_INTROSPECTION_FEATURE_CR4VMXESET (1<<1)
#define XEN_DOMCTL_INTROSPECTION_FEATURE_SMEP       (1<<2)
#define XEN_DOMCTL_INTROSPECTION_FEATURE_IMMUTABLE_MEMORY (1<<5)
#define XEN_DOMCTL_INTROSPECTION_FEATURE_HIDDEN_PROCESS (1<<6)
#define XEN_DOMCTL_INTROSPECTION_FEATURE_DR_BACKDOOR    (1<<7)

/* The following bits are auxiliary helper state bits or ioreq codes */
#define XEN_DOMCTL_INTROSPECTION_FEATURE_SMEP_OFF   (1<<3)
#define XEN_DOMCTL_INTROSPECTION_FEATURE_CR4SMEPCLEAR (1<<4)

#endif


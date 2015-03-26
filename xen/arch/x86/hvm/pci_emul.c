#include <asm/hvm/support.h>
#include <xen/hvm/pci_emul.h>
#include <xen/pci.h>
#include <xen/pci_regs.h>
#include <xen/sched.h>
#include <xen/xmalloc.h>

#undef DEBUG_PCI_ACCESS

static inline int device_dispatch(struct pci_device_bar_emul *b, int dir,
                                  uint32_t addr, uint32_t size, void *val)
{
    if ((addr < b->base) || ((addr + size) > (b->base + b->size)))
        return X86EMUL_UNHANDLEABLE;

    return b->handler(b->context, b->bar, dir, addr, size, val);
}


static int
device_mmio_dispatch(struct pci_device_bar_emul *b, ioreq_t *p)
{
    unsigned long data;
    int rc = X86EMUL_OKAY, i, sign = p->df ? -1 : 1;

    if (!p->data_is_ptr) {
        if (p->dir == IOREQ_READ) {
            rc = device_dispatch(b, IOREQ_READ, p->addr, p->size, &data);
            p->data = data;
        } else /* p->dir == IOREQ_WRITE */
            rc = device_dispatch(b, IOREQ_WRITE, p->addr, p->size, &data);

        return rc;
    }

    if (p->dir == IOREQ_READ) {
        for (i = 0; i < p->count; i++) {
            int ret;

            rc = device_dispatch(b, IOREQ_READ, p->addr + (sign * i * p->size),
                                 p->size, &data);
            if (rc != X86EMUL_OKAY)
                break;

            ret = hvm_copy_to_guest_phys(p->data + (sign * i * p->size),
                                         &data, p->size);
            if ((ret == HVMCOPY_gfn_paged_out) || (ret == HVMCOPY_gfn_shared)) {
                rc = X86EMUL_RETRY;
                break;
            }
        }
    } else {
        for (i = 0; i < p->count; i++) {
            int ret;

            ret = hvm_copy_from_guest_phys(&data,
                                           p->data + (sign * i * p->size),
                                           p->size);
            if ((ret == HVMCOPY_gfn_paged_out) || (ret == HVMCOPY_gfn_shared)) {
                rc = X86EMUL_RETRY;
                break;
            }

            rc = device_dispatch(b, IOREQ_WRITE, p->addr + (sign * i * p->size),
                                 p->size, &data);
            if (rc != X86EMUL_OKAY)
                break;
        }
    }

    if (i != 0) {
        p->count = i;
        rc = X86EMUL_OKAY;
    }

    return rc;
}

static int
device_portio_dispatch(struct pci_device_bar_emul *b, ioreq_t *p)
{
    int rc = X86EMUL_OKAY, i, sign = p->df ? -1 : 1;
    uint32_t data;

    if (!p->data_is_ptr) {
        if (p->dir == IOREQ_READ) {
            rc = device_dispatch(b, IOREQ_READ, p->addr, p->size, &data);
            p->data = data;
        } else {
            data = p->data;
            rc = device_dispatch(b, IOREQ_WRITE, p->addr, p->size, &data);
        }
        return rc;
    }

    if (p->dir == IOREQ_READ) {
        for (i = 0; i < p->count; i++) {
            rc = device_dispatch(b, IOREQ_READ, p->addr, p->size, &data);
            if (rc != X86EMUL_OKAY)
                break;

            (void)hvm_copy_to_guest_phys(p->data + sign * i * p->size,
                                         &data, p->size);
        }
    } else /* p->dir == IOREQ_WRITE */ {
        for (i = 0; i < p->count; i++) {
            data = 0;
            (void)hvm_copy_from_guest_phys(&data, p->data + sign * i * p->size,
                                           p->size);

            rc = device_dispatch(b, IOREQ_WRITE, p->addr, p->size, &data);
            if (rc != X86EMUL_OKAY)
                break;
        }
    }

    if (i != 0) {
        p->count = i;
        rc = X86EMUL_OKAY;
    }

    return rc;
}

/*XXX: this assumes that a single ioreq targets exactly zero or one bars */

int
hvm_internal_pci_intercept(struct ioreq *p, int type)
{
    struct pci_root_emul *root = &current->domain->arch.hvm_domain.pci_root;
    struct pci_device_bar_emul *bar;
    int i;
    int rc = X86EMUL_UNHANDLEABLE;

    /* short circuit without spinlock*/
    if (!root->nbars)
        return rc;

    spin_lock(&root->pci_lock);

    for (i = root->nbars, bar = root->bars; i; i--, bar++) {
        if (type != bar->type)
            continue;

        if (p->addr < bar->base)
            continue;

        if (p->addr >= bar->base + bar->size)
            continue;

        /* It doesn't matter if the io runs off the end, as we check
         * that later*/
        if (type == PCI_TYPE_IO)
            rc = device_portio_dispatch(bar, p);
        else
            rc = device_mmio_dispatch(bar, p);

        break;
    }

    spin_unlock(&root->pci_lock);
    return rc;
}

static int
device_activate_bar(struct domain *d, struct pci_device_bar_emul *b)
{
    struct pci_root_emul *root = &d->arch.hvm_domain.pci_root;
    int i;

    if (b->active != PCI_DEVICE_BAR_NOT_ACTIVE) {
        for (i = 0; i < PCI_TOTAL_NUM_BAR; ++i) {
            if (root->bars[i].active == PCI_DEVICE_BAR_NOT_ACTIVE) {
                b->active = i;
                break;
            }
        }
    }

    if (b->active == PCI_DEVICE_BAR_NOT_ACTIVE)
        return -1;

    if (b->active >= root->nbars)
        root->nbars = b->active + 1;

    memcpy(&root->bars[b->active], b, sizeof(*b));
    return 0;
}

static void
device_deactivate_bar(struct domain *d, struct pci_device_bar_emul *b)
{
    struct pci_root_emul *root = &d->arch.hvm_domain.pci_root;
    int i;

    if (b->active == PCI_DEVICE_BAR_NOT_ACTIVE)
        return;

    root->bars[b->active].active = PCI_DEVICE_BAR_NOT_ACTIVE;
    b->active = PCI_DEVICE_BAR_NOT_ACTIVE;

    for (i = 0; i < PCI_TOTAL_NUM_BAR; ++i) {
        if (root->bars[i].active != PCI_DEVICE_BAR_NOT_ACTIVE)
            root->nbars = i + 1;
    }
}

static void
device_check_bar(struct pci_device_emul *p, int i)
{
    struct domain *d = current->domain;
    struct pci_device_bar_emul *b = &p->bars[i];
    u32 *cfg = (u32 *)&p->config_space[PCI_BASE_ADDRESS_0 + (i << 2)];
    u32 addr;
    int enabled = 0;

    if (!b->present) {
        *cfg = 0;
        return;
    }

    switch (b->type) {
    case PCI_TYPE_IO:
        enabled = p->config_space[PCI_COMMAND] & PCI_COMMAND_IO;
        addr = *cfg & PCI_BASE_ADDRESS_IO_MASK;

        if (addr == PCI_BASE_ADDRESS_IO_MASK) 
            enabled = 0;    /* Disable decode during a size probe */

        addr &= ~(b->size - 1);
        *cfg &= ~PCI_BASE_ADDRESS_IO_MASK;
        *cfg |= addr;
        break;

    case PCI_TYPE_MMIO:
        enabled = p->config_space[PCI_COMMAND] & PCI_COMMAND_MEMORY;
        addr = *cfg & PCI_BASE_ADDRESS_MEM_MASK;

        if (addr == PCI_BASE_ADDRESS_MEM_MASK) 
            enabled = 0;    /* Disable decode during a size probe */

        addr &= ~(b->size - 1);
        *cfg &= ~PCI_BASE_ADDRESS_MEM_MASK;
        *cfg |= addr;
        break;

    default:
        return;
    }

    if (!addr)
        enabled = 0;

    if (enabled) {
        b->base = addr;
        device_activate_bar(d, b);
    } else
        device_deactivate_bar(d, b);
}

static int
device_config_handler_locked(struct pci_device_emul *p, int dir,
                             uint32_t offset, uint32_t size, void *val)
{
    int i;
    u8 *vp = (u8 *)val;
    u8 *we = (u8 *)p->config_space_rw;
    u8 *cp = (u8 *)p->config_space;

    if (dir == IOREQ_READ) {
        if ((offset + size) > sizeof(p->config_space)) {
            memset(val, 0, size);
            return X86EMUL_OKAY;
        }

        memcpy(val, cp + offset, size);
        return X86EMUL_OKAY;
    }

    if ((offset + size) > sizeof(p->config_space))
        return X86EMUL_OKAY;

    cp += offset;
    we += offset;

    while (size--) {
        *cp = (*cp & ~*we) | (*vp & *we);
        cp++, we++, vp++;
    }

    for (i = 0; i < PCI_NUM_BAR; ++i)
        device_check_bar(p, i);

    return X86EMUL_OKAY;
}

static struct pci_device_emul *
get_pcidev(struct domain *d, u16 bdf)
{
    struct pci_device_emul *p;

    for (p = d->arch.hvm_domain.pci_root.pci; p; p = p->next)
        if (p->bdf == bdf)
            return p;

    return NULL;
}

int
pci_device_config_handler(int dir, uint32_t addr, uint32_t size,
                          uint32_t *val)
{
    struct domain *d = current->domain;
    struct pci_device_emul *p;
    u16 bdf = PCI_CF8_TO_BDF(addr);
    int rc;

    addr &= 0xff;
    spin_lock(&d->arch.hvm_domain.pci_root.pci_lock);
    p = get_pcidev(d, bdf);

    if (!p) {
        spin_unlock(&d->arch.hvm_domain.pci_root.pci_lock);
        return X86EMUL_UNHANDLEABLE;
    }

    rc = device_config_handler_locked(p, dir, addr, size, val);
    spin_unlock(&d->arch.hvm_domain.pci_root.pci_lock);
#ifdef DEBUG_PCI_ACCESS
    {
        uint32_t v = *val;
        char l = 'u';

        switch (size) {
        case 1:
            v &= 0xff;
            l = 'b';
            break;

        case 2:
            v &= 0xffff;
            l = 'w';
            break;

        case 4:
            l = 'l';
        }

        dprintk(XENLOG_DEBUG "PCI_CONFIG: %c %02x:%02x.%x %02x.%c%c=%8x\n",
                dir == IOREQ_READ ? 'R' : 'W',
                bdf >> 8, (bdf >> 3) & 0x1f, bdf & 0x7,
                addr, l,
                dir == IOREQ_READ ? '=' : '<',
                v);
    }
#endif
    return rc;
}

static int
handle_type1_config(int dir, uint32_t port, uint32_t size, uint32_t *val)
{
    uint32_t pci_cf8;
    struct pci_device_emul *pci;
    ioreq_t *p = get_ioreq(current);
    struct vcpu *v = current;
    u16 bdf;

    switch (port) {
    case 0xcf8:
        if (size != 4)
            return X86EMUL_UNHANDLEABLE;

        spin_lock(&v->domain->arch.hvm_domain.pci_root.pci_lock);

        if (dir == IOREQ_READ)
            *val = v->arch.hvm_vcpu.pci_cf8;
        else
            v->arch.hvm_vcpu.pci_cf8 = *val;

        spin_unlock(&v->domain->arch.hvm_domain.pci_root.pci_lock);
        return X86EMUL_OKAY;

    case 0xcfc:
        break;

    case 0xcfd:
        if (size != 1)
            return X86EMUL_UNHANDLEABLE;
        break;

    case 0xcfe:
        if (size == 4)
            return X86EMUL_UNHANDLEABLE;
        break;

    case 0xcff:
        if (size != 1)
            return X86EMUL_UNHANDLEABLE;
        break;

    default:
        return X86EMUL_UNHANDLEABLE;
    }

    spin_lock(&v->domain->arch.hvm_domain.pci_root.pci_lock);
    pci_cf8 = v->arch.hvm_vcpu.pci_cf8;
    pci = NULL;

    if (pci_cf8 & 0x80000000UL) {
        /* Retrieve PCI */
        pci = v->domain->arch.hvm_domain.pci_root.pci;
        bdf = PCI_CF8_TO_BDF(pci_cf8);

        while (pci && (pci->bdf != bdf))
            pci = pci->next;
    }

    /* We just fill the ioreq, hvm_send_assist_req will send the request */
    if (unlikely(pci == NULL)) {
        if (dir == IOREQ_READ)
            *val = ~0;

        spin_unlock(&v->domain->arch.hvm_domain.pci_root.pci_lock);
        return X86EMUL_OKAY;
    }

    p->type = IOREQ_TYPE_PCI_CONFIG;
    p->addr = (pci_cf8 & ~3) + (port & 3);
    p->size = size;

    if (pci->server)
        set_ioreq(v, &pci->server->ioreq, p);

    spin_unlock(&v->domain->arch.hvm_domain.pci_root.pci_lock);
    return X86EMUL_UNHANDLEABLE;
}

static void
device_init(struct pci_device_emul *p)
{
    int i;
    memset(p->config_space, 0, PCI_CONFIG_SPACE_SIZE);
    memset(p->config_space_rw, 0, PCI_CONFIG_SPACE_SIZE);
    p->config_space_rw[PCI_COMMAND] =
        PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER;
    p->config_space_rw[PCI_LATENCY_TIMER] = 0xff;

    for (i = 0; i < PCI_NUM_BAR; ++i)
        memset(&p->config_space_rw[PCI_BASE_ADDRESS_0 + (i << 2)], 0xff, 4);

    p->config_space_rw[PCI_INTERRUPT_LINE] = 0xff;
    p->config_space_rw[PCI_INTERRUPT_PIN] = 0xff;

    for (i = 0; i < PCI_NUM_BAR; ++i) {
        memset(&p->bars[i], 0, sizeof(struct pci_device_bar_emul));
        p->bars[i].active = PCI_DEVICE_BAR_NOT_ACTIVE;
        p->bars[i].bar = i;
    }
}

int
hvm_pcidev_set_config(struct domain *d, u16 bdf, u32 offset, u32 len,
                      void *data)
{
    struct pci_device_emul *p;
    spin_lock(&d->arch.hvm_domain.ioreq_server_lock);
    p = get_pcidev(d, bdf);

    if (!p) {
        spin_unlock(&d->arch.hvm_domain.ioreq_server_lock);
        return -ENOENT;
    }

    memcpy(&p->config_space[offset], data, len);
    spin_unlock(&d->arch.hvm_domain.ioreq_server_lock);
    return 0;
}

int
hvm_pcidev_set_ids(struct domain *d, u16 bdf, u16 vid, u16 did, u32 class,
                   u8 revision, u16 svid, u16 sdid)
{
    hvm_pcidev_set_config(d, bdf, 0, 2, &vid);
    hvm_pcidev_set_config(d, bdf, 2, 2, &did);
    class <<= 8;
    class |= revision;
    hvm_pcidev_set_config(d, bdf, 8, 4, &class);
    hvm_pcidev_set_config(d, bdf, 0x2c, 2, &svid);
    hvm_pcidev_set_config(d, bdf, 0x2e, 2, &sdid);
    return 0;
}

int
hvm_pcidev_set_bar(struct domain *d, u16 bdf, int bar, int type, u32 flags,
                   u32 size, pcibar_action_t *handler, void *context)
{
    struct pci_device_emul *p;
    struct pci_device_bar_emul *b;
    uint32_t flags_rw;

    spin_lock(&d->arch.hvm_domain.ioreq_server_lock);
    p = get_pcidev(d, bdf);
    if (!p) {
        spin_unlock(&d->arch.hvm_domain.ioreq_server_lock);
        return -ENOENT;
    }

    b = &p->bars[bar];
    device_deactivate_bar(d, b);
    b->active = PCI_DEVICE_BAR_NOT_ACTIVE;
    b->present = 1;
    b->type = type;
    b->base = 0;
    b->size = size;
    b->handler = handler;
    b->context = context;

    switch (b->type) {
    case PCI_TYPE_IO:
        flags |= PCI_BASE_ADDRESS_SPACE_IO;
        flags_rw = (uint32_t)PCI_BASE_ADDRESS_IO_MASK;
        break;

    case PCI_TYPE_MMIO:
        flags &= ~PCI_BASE_ADDRESS_SPACE_IO;
        flags_rw = (uint32_t)PCI_BASE_ADDRESS_MEM_MASK;
        break;

    default:
        flags_rw = 0;
    }

    memcpy(&p->config_space[PCI_BASE_ADDRESS_0 + (bar << 2)], &flags,
           sizeof(u32));
    memcpy(&p->config_space_rw[PCI_BASE_ADDRESS_0 + (bar << 2)], &flags_rw,
           sizeof(u32));
    spin_unlock(&d->arch.hvm_domain.ioreq_server_lock);
    return 0;
}

int
hvm_register_pcidev_with_lock(struct domain *d, servid_t server_id, u16 bdf)
{
    struct hvm_ioreq_server *s;
    struct pci_device_emul *x;

    if (!is_hvm_domain(d))
        return -EINVAL;

    /* Search server */

    if (server_id == SERVID_INTERNAL)
        s = NULL;
    else {
        spin_lock(&d->arch.hvm_domain.ioreq_server_lock);
        s = d->arch.hvm_domain.ioreq_server_list;

        while ((s != NULL) && (s->id != server_id))
            s = s->next;

        spin_unlock(&d->arch.hvm_domain.ioreq_server_lock);
        //XXX: s isn't locked here - expect misery

        if (s == NULL) {
            dprintk(XENLOG_DEBUG, "Cannot find server %d\n", server_id);
            spin_unlock(&d->arch.hvm_domain.pci_root.pci_lock);
            return -ENOENT;
        }
    }

    x = xmalloc(struct pci_device_emul);
    if (!x) {
        dprintk(XENLOG_DEBUG, "Cannot allocate pci\n");
        return ENOMEM;
    }

    spin_lock(&d->arch.hvm_domain.pci_root.pci_lock);

    if (!s)
        device_init(x);

    x->bdf = bdf;
    x->server = s;            //XXX: race
    x->next = d->arch.hvm_domain.pci_root.pci;
    d->arch.hvm_domain.pci_root.pci = x;
    spin_unlock(&d->arch.hvm_domain.pci_root.pci_lock);
    return 0;
}

int
hvm_register_pcidev(domid_t domid, servid_t server_id, u16 bdf)
{
    int rc;
    struct domain *d;

    rc = rcu_lock_remote_target_domain_by_id(domid, &d);
    if (rc != 0)
        return rc;

    rc = hvm_register_pcidev_with_lock(d, server_id, bdf);

    rcu_unlock_domain(d);
    return rc;
}

int
hvm_init_pci_emul(struct domain *d)
{
    struct pci_root_emul *root = &d->arch.hvm_domain.pci_root;
    int i;
    struct pci_device_bar_emul *bars;

    bars = xmalloc_array(struct pci_device_bar_emul, PCI_TOTAL_NUM_BAR);
    if (!bars)
        return -ENOMEM;

    spin_lock_init(&root->pci_lock);
    root->pci = NULL;
    root->bars = bars;

    for (i = 0; i < PCI_TOTAL_NUM_BAR; ++i)
        root->bars[i].active = PCI_DEVICE_BAR_NOT_ACTIVE;

    root->nbars = 0;
    /* Register the config space handler */
    register_portio_handler(d, 0xcf8, 8, handle_type1_config);

    return 0;
}

void
hvm_destroy_pci_emul(struct domain *d)
{
    struct pci_root_emul *root = &d->arch.hvm_domain.pci_root;
    struct pci_device_emul *p;
    spin_lock(&root->pci_lock);
    xfree(root->bars);

    while ((p = root->pci) != NULL) {
        root->pci = p->next;
        xfree(p);
    }

    spin_unlock(&root->pci_lock);
}

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

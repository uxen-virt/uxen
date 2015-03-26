#ifndef __XEN_HVM_PCI_EMUL_H__
#define __XEN_HVM_PCI_EMUL_H__

#include <xen/types.h>
#include <xen/spinlock.h>

typedef int (pcibar_action_t)(void *context, int bar, int dir,
                              uint32_t addr, uint32_t size, void * val);

int hvm_init_pci_emul(struct domain *d);
void hvm_destroy_pci_emul(struct domain *d);

int hvm_pcidev_set_config(struct domain *d, u16 bdf,  u32 offset, u32 len,
                          void *data);
int hvm_pcidev_set_bar(struct domain *d, u16 bdf, int bar, int type, u32 flags,
                       u32 size, pcibar_action_t *handler,void *context);
int pci_device_config_handler (int dir, uint32_t addr, uint32_t size,
                               uint32_t * val);

int hvm_pcidev_set_ids(struct domain *d, u16 bdf, u16 vid, u16 did, u32 class,
                       u8 revision, u16 svid, u16 sdid);

int hvm_register_pcidev_with_lock(struct domain *d, servid_t id, u16 bdf);
int hvm_register_pcidev(domid_t domid, servid_t id, u16 bdf);

int hvm_internal_pci_intercept(struct ioreq *p,int type);

/* Size of the standard PCI config space */
#define PCI_CONFIG_SPACE_SIZE 0x100
#define PCI_NUM_BAR        5
#define PCI_TOTAL_NUM_BAR        20
#define PCI_CF8_TO_BDF(cf8) (((cf8) & 0x00ffff00) >> 8)
#define PCI_BDF_TO_CF8(bdf) ((((bdf) & 0xffff) << 8UL) | 0x80000000UL)
#define PCI_DEVICE_BAR_NOT_ACTIVE -1

#define PCI_TYPE_MMIO  0
#define PCI_TYPE_IO    1

struct pci_device_bar_emul {
    int present;
    int active;                   /*-1 or index into the array*/
    int type;
    int bar;
    u32 base;                     /*XXX: only 32bit bars for now */
    u32 size;
    pcibar_action_t *handler;
    void *context;
};

struct pci_device_emul {
    u16 bdf;
    struct hvm_ioreq_server *server;
    struct pci_device_emul *next;

    /* for internal emulation of pci devices in xen */
    u8 config_space[PCI_CONFIG_SPACE_SIZE];
    u8 config_space_rw[PCI_CONFIG_SPACE_SIZE];
    struct pci_device_bar_emul bars[PCI_NUM_BAR]; /*XXX: no roms yet */
};

struct pci_root_emul {
    spinlock_t pci_lock;
    struct pci_device_emul *pci;
    struct pci_device_bar_emul *bars;
    int nbars;
};

#endif /* !__XEN_HVM_PCI_EMUL_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

#include <xen/config.h>
#include <xen/init.h>
#include <xen/types.h>
#include <xen/lib.h>
#include <xen/sched.h>
#include <xen/domain_page.h>
#include <xen/iommu.h>
#include <xen/acpi.h>
#include <xen/pfn.h>
#include <asm/fixmap.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/e820.h>
#include <asm/tboot.h>
#include <crypto/vmac.h>

/* Global pointer to shared data; NULL means no measured launch. */
tboot_shared_t *g_tboot_shared;

int tboot_in_measured_env(void)
{
    return (g_tboot_shared != NULL);
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

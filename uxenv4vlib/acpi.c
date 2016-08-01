/*
 * Copyright 2016, Bromium, Inc.
 * Author: Paulian Marinca <paulian@marinca.net>
 * SPDX-License-Identifier: ISC
 */

#include <linux/acpi.h>
#include <linux/completion.h>


static struct completion probe_event;
static int driver_registered = 0;
static int irq_line = -1;

static acpi_status walk_resources(struct acpi_resource *res, void *context)
{
    switch (res->type) {
    case ACPI_RESOURCE_TYPE_IRQ:
        irq_line = res->data.irq.interrupts[0];

        printk(KERN_INFO "uxenv4vlib: irq line %d\n", irq_line);
    }

    return AE_OK;
}

static int acpi_driver_add(struct acpi_device *device)
{
    int ret = 0;
    acpi_status result;

    result = acpi_walk_resources(device->handle, METHOD_NAME__CRS, walk_resources, NULL);
    if (ACPI_FAILURE(result))
        ret = -ENODEV;

    complete(&probe_event);
    return ret;
}

static int acpi_driver_remove(struct acpi_device *device)
{
    return 0;
}

static const struct acpi_device_id device_ids[] = {
        { "UXV0100", 0},
        { "", 0},
    };
MODULE_DEVICE_TABLE(acpi, device_ids);
static struct acpi_driver uxenv4v_driver = {
    .name =   "uxenv4v",
    .class =  "uxen",
    .ids =    device_ids,
    .ops =    {
        .add =      acpi_driver_add,
        .remove =   acpi_driver_remove,
    },
    .owner =        THIS_MODULE,
};

int acpi_init_irq_line(void)
{
    init_completion(&probe_event);
    if (acpi_bus_register_driver(&uxenv4v_driver) < 0) {
        ACPI_DEBUG_PRINT((ACPI_DB_ERROR, "Error registering driver\n"));
        return -ENODEV;
    }
    driver_registered = 1;

    if (wait_for_completion_timeout(&probe_event, 5 * HZ) == 0) {
        acpi_bus_unregister_driver(&uxenv4v_driver);
        return -ETIMEDOUT;
    }

    return irq_line;
}

void acpi_exit(void)
{
    if (driver_registered)
        acpi_bus_unregister_driver(&uxenv4v_driver);
}

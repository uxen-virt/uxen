/* 
 * Generic VM initialization for x86-64 NUMA setups.
 * Copyright 2002,2003 Andi Kleen, SuSE Labs.
 * Adapted for Xen: Ryan Harper <ryanh@us.ibm.com>
 */ 

#include <xen/mm.h>
#include <xen/string.h>
#include <xen/init.h>
#include <xen/ctype.h>
#include <xen/nodemask.h>
#include <xen/numa.h>
#include <xen/keyhandler.h>
#include <xen/time.h>
#include <xen/smp.h>
#include <xen/pfn.h>
#include <asm/acpi.h>
#include <xen/sched.h>

struct node_data node_data[MAX_NUMNODES];

/* Mapping from pdx to node id */
int memnode_shift;
static typeof(*memnodemap) _memnodemap[64];
u8 *memnodemap;

unsigned char cpu_to_node[NR_CPUS] __read_mostly = {
	[0 ... NR_CPUS-1] = NUMA_NO_NODE
};
cpumask_t node_to_cpumask[MAX_NUMNODES] __read_mostly;

nodemask_t __read_mostly node_online_map = { { [0] = 1UL } };

int numa_off __devinitdata = 0;

/* initialize NODE_DATA given nodeid and start/end */
void __init setup_node_bootmem(int nodeid, u64 start, u64 end)
{ 
	unsigned long start_pfn, end_pfn;

	start_pfn = start >> PAGE_SHIFT;
	end_pfn = end >> PAGE_SHIFT;

	NODE_DATA(nodeid)->node_id = nodeid;
	NODE_DATA(nodeid)->node_start_pfn = start_pfn;
	NODE_DATA(nodeid)->node_spanned_pages = end_pfn - start_pfn;

	node_set_online(nodeid);
} 

void __init numa_initmem_init(unsigned long start_pfn, unsigned long end_pfn)
{ 
	int i;

#ifdef CONFIG_NUMA_EMU
	if (numa_fake && !numa_emulation(start_pfn, end_pfn))
		return;
#endif

#ifdef CONFIG_ACPI_NUMA
	if (!numa_off && !acpi_scan_nodes((u64)start_pfn << PAGE_SHIFT,
					  (u64)end_pfn << PAGE_SHIFT))
		return;
#endif

	printk(KERN_INFO "%s\n",
	       numa_off ? "NUMA turned off" : "No NUMA configuration found");

	printk(KERN_INFO "Faking a node at %016"PRIx64"-%016"PRIx64"\n",
	       (u64)start_pfn << PAGE_SHIFT,
	       (u64)end_pfn << PAGE_SHIFT);
	/* setup dummy node covering all memory */ 
	memnode_shift = BITS_PER_LONG - 1;
	memnodemap = _memnodemap;
	nodes_clear(node_online_map);
	node_set_online(0);
	for (i = 0; i < nr_cpu_ids; i++)
		numa_set_node(i, 0);
	cpumask_copy(&node_to_cpumask[0], cpumask_of(0));
	setup_node_bootmem(0, (u64)start_pfn << PAGE_SHIFT, (u64)end_pfn << PAGE_SHIFT);
}

__cpuinit void numa_add_cpu(int cpu)
{
	cpumask_set_cpu(cpu, &node_to_cpumask[cpu_to_node(cpu)]);
} 

void __cpuinit numa_set_node(int cpu, int node)
{
	cpu_to_node[cpu] = node;
}

/*
 * Setup early cpu_to_node.
 *
 * Populate cpu_to_node[] only if x86_cpu_to_apicid[],
 * and apicid_to_node[] tables have valid entries for a CPU.
 * This means we skip cpu_to_node[] initialisation for NUMA
 * emulation and faking node case (when running a kernel compiled
 * for NUMA on a non NUMA box), which is OK as cpu_to_node[]
 * is already initialized in a round robin manner at numa_init_array,
 * prior to this call, and this initialization is good enough
 * for the fake NUMA cases.
 */
void __init init_cpu_to_node(void)
{
	int i, node;
 	for (i = 0; i < nr_cpu_ids; i++) {
		node = 0;
		numa_set_node(i, node);
	}
}

EXPORT_SYMBOL(cpu_to_node);
EXPORT_SYMBOL(node_to_cpumask);
EXPORT_SYMBOL(memnode_shift);
EXPORT_SYMBOL(memnodemap);
EXPORT_SYMBOL(node_data);


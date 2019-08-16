
#include <xen/lib.h>
#include <xen/smp.h>
#include <xen/time.h>
#include <xen/perfc.h>
#include <xen/keyhandler.h> 
#include <xen/spinlock.h>
#include <xen/mm.h>
#include <xen/guest_access.h>
#include <public/sysctl.h>
#include <asm/perfc.h>

#define PERFCOUNTER( var, name )              { name, TYPE_SINGLE, 0 },
#define PERFCOUNTER_ARRAY( var, name, size )  { name, TYPE_ARRAY,  size },
#define PERFSTATUS( var, name )               { name, TYPE_S_SINGLE, 0 },
#define PERFSTATUS_ARRAY( var, name, size )   { name, TYPE_S_ARRAY,  size },
static const struct {
    const char *name;
    enum { TYPE_SINGLE, TYPE_ARRAY,
           TYPE_S_SINGLE, TYPE_S_ARRAY
    } type;
    unsigned int nr_elements;
} perfc_info[] = {
#include <xen/perfc_defn.h>
};

#define NR_PERFCTRS (sizeof(perfc_info) / sizeof(perfc_info[0]))

DEFINE_PER_CPU(perfc_t[NUM_PERFCOUNTERS], perfcounters);

static int show_all_cpus = 0;

void perfc_printall(unsigned char key)
{
    unsigned int i, j;
    s_time_t now = NOW();

    printk("Xen performance counters SHOW  (now = 0x%08X:%08X)\n",
           (u32)(now>>32), (u32)now);

    for ( i = j = 0; i < NR_PERFCTRS; i++ )
    {
        unsigned int k, cpu;
        unsigned long long sum = 0;

        switch ( perfc_info[i].type )
        {
        case TYPE_SINGLE:
        case TYPE_S_SINGLE:
            for_each_online_cpu ( cpu )
                sum += per_cpu(perfcounters, cpu)[j];
            if ( perfc_info[i].type == TYPE_S_SINGLE ) 
                sum = (perfc_t) sum;
            if ( sum )
            {
                printk("%-32s  TOTAL[%12Lu]", perfc_info[i].name, sum);
                k = 0;
                if (show_all_cpus) for_each_online_cpu ( cpu )
                {
                    if ( k > 0 && (k % 4) == 0 )
                        printk("\n%46s", "");
                    printk("  CPU%02u[%10"PRIperfc"u]", cpu, per_cpu(perfcounters, cpu)[j]);
                    ++k;
                }
                printk("\n");
            }
            ++j;
            break;
        case TYPE_ARRAY:
        case TYPE_S_ARRAY:
            for_each_online_cpu ( cpu )
            {
                perfc_t *counters = per_cpu(perfcounters, cpu) + j;

                for ( k = 0; k < perfc_info[i].nr_elements; k++ )
                    sum += counters[k];
            }
            if ( perfc_info[i].type == TYPE_S_ARRAY ) 
                sum = (perfc_t) sum;
            if (sum)
            {
                printk("%-32s  TOTAL[%12Lu]", perfc_info[i].name, sum);
#ifdef PERF_ARRAYS
                for ( k = 0; k < perfc_info[i].nr_elements; k++ )
                {
                    sum = 0;
                    for_each_online_cpu ( cpu )
                        sum += per_cpu(perfcounters, cpu)[j + k];
                    if ( perfc_info[i].type == TYPE_S_ARRAY ) 
                        sum = (perfc_t) sum;
                    if ( (k % 4) == 0 )
                        printk("\n%16s", "");
                    printk("  ARR%03x[%10Lu]", k, sum);
                }
#else
                k = 0;
                if (show_all_cpus) for_each_online_cpu ( cpu )
                {
                    perfc_t *counters = per_cpu(perfcounters, cpu) + j;
                    unsigned int n;

                    sum = 0;
                    for ( n = 0; n < perfc_info[i].nr_elements; n++ )
                        sum += counters[n];
                    if ( perfc_info[i].type == TYPE_S_ARRAY ) 
                        sum = (perfc_t) sum;
                    if ( k > 0 && (k % 4) == 0 )
                        printk("\n%46s", "");
                    printk("  CPU%02u[%10Lu]", cpu, sum);
                    ++k;
                }
#endif
                printk("\n");
            }
            j += perfc_info[i].nr_elements;
            break;
        }
    }
}

void perfc_reset(unsigned char key)
{
    unsigned int i, j;
    s_time_t now = NOW();

    if ( key != '\0' )
        printk("Xen performance counters RESET (now = 0x%08X:%08X)\n",
               (u32)(now>>32), (u32)now);

    /* leave STATUS counters alone -- don't reset */

    for ( i = j = 0; i < NR_PERFCTRS; i++ )
    {
        unsigned int cpu;

        switch ( perfc_info[i].type )
        {
        case TYPE_SINGLE:
            for_each_online_cpu ( cpu )
                per_cpu(perfcounters, cpu)[j] = 0;
        case TYPE_S_SINGLE:
            ++j;
            break;
        case TYPE_ARRAY:
            for_each_online_cpu ( cpu )
                memset(per_cpu(perfcounters, cpu) + j, 0,
                       perfc_info[i].nr_elements * sizeof(perfc_t));
        case TYPE_S_ARRAY:
            j += perfc_info[i].nr_elements;
            break;
        }
    }

    arch_perfc_reset();
}

void
perfc_all_cpus(unsigned char key)
{

    show_all_cpus = (key == '0') ? 0 : 1;
    printk("%s: printing %s performance counters", __FUNCTION__,
           show_all_cpus ? "per-cpu" : "totals only");
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

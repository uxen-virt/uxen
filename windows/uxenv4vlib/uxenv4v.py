from pykd import *
from math import *
import sys

argc = len(sys.argv)
argv = sys.argv

def dump_globals():
    uxen_v4v_pde = typedVar("uxenv4vlib!uxen_v4v_pde")
    dprintln("<link cmd=\"?? uxenv4vlib!uxen_v4v_pde\">pending_irp_queue</link> (%d):" % 
             (uxen_v4v_pde.pending_irp_count), True)

    pending_irp_queue = typedVarList(uxen_v4v_pde.pending_irp_queue, "nt!_IRP", "Tail.Overlay.ListEntry")
    for irp in pending_irp_queue:
        thread = irp.Tail.Overlay.Thread
        process = typedVar("nt!_EPROCESS", thread.Tcb.Process)
        
        dprintln("  irp: <link cmd=\"!irp 0x%x\">0x%x</link>"
                 " (thread <link cmd=\"!thread 0x%x 1f\">0x%x</link> ["
                 "<link cmd=\"!process 0x%x 1f\">%s</link>])" % 
                 (irp, irp, thread, thread, process, loadCStr(process.ImageFileName)), True)
    ring_list = typedVarList(uxen_v4v_pde.ring_list, "uxenv4vlib!xenv4v_ring_t", "le")
    
    dprintln("xenv4v ring_list:")
    for ring in ring_list:
        v4v_ring = typedVar("uxenv4vlib!v4v_ring", ring.ring)
        dprint("  <link cmd=\"?? (uxenv4vlib!xenv4v_ring_t *)0x%x\">0x%x</link>: "
               "v4v_ring: <link cmd=\"?? (uxenv4vlib!v4v_ring *)0x%x\">0x%x</link> "
               "(id: 0x%x/0x%x, len: 0x%x, rx: 0x%x, tx: 0x%x)" %
               (ring, ring, v4v_ring, v4v_ring, v4v_ring.id.addr.port, v4v_ring.id.addr.domain,
                v4v_ring.len, v4v_ring.rx_ptr, v4v_ring.tx_ptr), True)
        if v4v_ring.rx_ptr == v4v_ring.tx_ptr:
            dprint(" - empty")
        dprintln("")

def main():
    dump_globals()

if __name__ == "__main__":
    main()

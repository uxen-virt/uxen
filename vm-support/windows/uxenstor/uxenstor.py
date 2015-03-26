from pykd import *
from math import *
import sys

argc = len(sys.argv)
argv = sys.argv

def dec_with_commas(x):
    if x < 0:
        return '-' + dec_with_commas(-x)
    result = ''
    while x >= 1000:
        x, r = divmod(x, 1000)
        result = "`%03d%s" % (r, result)
    return "%d%s" % (x, result)

def perfcnt_arr_item_name(id, aid):
    perfcnt_arr_items = typedVar("uxenstor!perfcnt_arr_items")
    for i in range(0, len(perfcnt_arr_items)):
        if perfcnt_arr_items[i].id == id and perfcnt_arr_items[i].aid == aid:
            return loadCStr(perfcnt_arr_items[i].name) + ":"
    return ""

def dump_counters():
    perfcnt = typedVar("uxenstor!perfcnt")
    perfcnt_desc = typedVar("uxenstor!perfcnt_desc")
    dprintln("=== uxenstor counters (%d)" % (len(perfcnt_desc)))
    d = 0
    for i in range(0, len(perfcnt_desc)):
        if perfcnt_desc[i].arr_len > 0:
            total = 0
            for j in range(0, perfcnt_desc[i].arr_len):
                total += int(perfcnt[j + d])
            dprintln("  %d. %s = %s" % (i, loadCStr(perfcnt_desc[i].name),
                                      dec_with_commas(total)))
            for j in range(0, perfcnt_desc[i].arr_len):
                if perfcnt[j + d] != 0:
                    dprintln("    %s0x%x = %s" % 
                             (perfcnt_arr_item_name(perfcnt_desc[i].id, j),
                              j, dec_with_commas(int(perfcnt[j + d]))))
            d += perfcnt_desc[i].arr_len
        else:
            dprintln("  %d. %s = %s" % (i, loadCStr(perfcnt_desc[i].name),
                                       dec_with_commas(int(perfcnt[d]))))
            d += 1
    dprintln("=======================================")

def dump_trace_print(it):
    if ((it.status == 0x103 and it.data.scsi.cdb[0] == 0x2a) or 
        (it.status == 0 and it.data.scsi.cdb[0] == 0x28)):
        sec = ((it.data.scsi.cdb[2] << 24) | (it.data.scsi.cdb[3] << 16) |
               (it.data.scsi.cdb[4] << 8) | (it.data.scsi.cdb[5] << 0))
        sec_cnt = (it.data.scsi.cdb[7] << 8) | (it.data.scsi.cdb[8] << 0)
        dprintln("[0x%x:%d] seq: 0x%x, irp: 0x%x, cmd: 0x%x, status: 0x%08x,"
                 " data_len: 0x%08x, LBA: 0x%08x, sec_cnt: %03d, chk_sum: 0x%08x (0x%08x)" % 
                 (it.seq, it.line, it.seq_id, it.irp, it.data.scsi.cdb[0], it.status,
                  it.data.scsi.data_len, sec, sec_cnt, it.data.scsi.chksum[0], it.data.scsi.chksum[1]))
    elif it.status == 0x103 and it.data.scsi.cdb[0] == 0x28:
        sec = ((it.data.scsi.cdb[2] << 24) | (it.data.scsi.cdb[3] << 16) |
               (it.data.scsi.cdb[4] << 8) | (it.data.scsi.cdb[5] << 0))
        sec_cnt = (it.data.scsi.cdb[7] << 8) | (it.data.scsi.cdb[8] << 0)
        dprintln("[0x%x:%d] seq: 0x%x, irp: 0x%x, cmd: 0x%x, status: 0x%08x,"
                 " data_len: 0x%08x, LBA: 0x%08x, sec_cnt: %03d" % 
                 (it.seq, it.line, it.seq_id, it.irp, it.data.scsi.cdb[0], it.status,
                  it.data.scsi.data_len, sec, sec_cnt))
    else:
        dprintln("[0x%x:%d] seq: 0x%x, irp: 0x%x, cmd: 0x%x, status: 0x%08x, data_len: 0x%08x" % 
            (it.seq, it.line, it.seq_id, it.irp, it.data.scsi.cdb[0], it.status, it.data.scsi.data_len))

def dump_trace():
    trace_len = typedVar("uxenstor!trace_len")
    trace_prov = typedVar("uxenstor!trace_prov")
    trace_wrapped = typedVar("uxenstor!trace_wrapped")
    trace = typedVarArray(typedVar("uxenstor!trace"), "uxenstor!TRACE_ITEM", trace_len)

    if argc > 1:
        max_to_print = min(int(argv[1]), trace_len)
        if max_to_print == 0:
            max_to_print = trace_len
    else:
        max_to_print = 10

    dprintln("=== uxenstor request trace ============")

    if trace_wrapped and max_to_print > trace_prov:
        start = max(trace_prov, trace_len - (max_to_print - trace_prov))
        for i in range(start, trace_len):
            dump_trace_print(trace[i])
    if trace_prov > max_to_print:
        start = trace_prov - max_to_print
    else:
        start = 0
    for i in range(start, trace_prov):
        dump_trace_print(trace[i])

    dprintln("=======================================")

def main():
    dump_counters()
    dump_trace()

if __name__ == "__main__":
    main()

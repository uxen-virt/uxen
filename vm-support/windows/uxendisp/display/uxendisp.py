from pykd import *
from math import *
import sys

argc = len(sys.argv)
argv = sys.argv

def get_arg(arg_index, def_val = 0):
    if arg_index < argc:
        return sys.argv[arg_index]
    else:
        return def_val

def dec_with_commas(x):
    if x < 0:
        return '-' + dec_with_commas(-x)
    result = ''
    while x >= 1000:
        x, r = divmod(x, 1000)
        result = "`%03d%s" % (r, result)
    return "%d%s" % (x, result)

def perfcnt_arr_item_name(id, aid):
    perfcnt_arr_items = typedVar("uxendispdd!perfcnt_arr_items")
    for i in range(0, len(perfcnt_arr_items)):
        if perfcnt_arr_items[i].id == id and perfcnt_arr_items[i].aid == aid:
            return loadCStr(perfcnt_arr_items[i].name) + ":"
    return ""

def dump_counters(ignore_val):
    total_displayed = 0
    perfcnt = typedVar("uxendispdd!perfcnt")
    perfcnt_desc = typedVar("uxendispdd!perfcnt_desc")
    dprintln("=== uxendispdd counters")
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
            if int(perfcnt[d]) != ignore_val:
                dprintln("  %d. %s = %s" % (i, loadCStr(perfcnt_desc[i].name),
                                            dec_with_commas(int(perfcnt[d]))))
                total_displayed += 1
            d += 1
    dprintln("=== displayed %d out of %d ============" % (total_displayed,
                                                          len(perfcnt_desc)))

def main():
    dump_counters(int(get_arg(1, 0)))

if __name__ == "__main__":
    main()

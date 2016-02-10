#
# Copyright 2012-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

define isuxenmodule
    if ($arg0[0]  == 'o' && \
        $arg0[1]  == 'r' && \
        $arg0[2]  == 'g' && \
        $arg0[3]  == '.' && \
        $arg0[4]  == 'u' && \
        $arg0[5]  == 'x' && \
        $arg0[6]  == 'e' && \
        $arg0[7]  == 'n' && \
        $arg0[8]  == '.' && \
        $arg0[9]  == 'u' && \
        $arg0[10] == 'x' && \
        $arg0[11] == 'e' && \
        $arg0[12] == 'n')
        set $ret = 0
    else
        set $ret = 1
    end
end

define finduxenmodule
    set $kmodp = (struct kmod_info *)kmod
    set $found = 0
    while ($kmodp && !$found) 
        isuxenmodule $kmodp->name
        if ($ret == 0)
            set $found = 1
        else
            set $kmodp = $kmodp->next
        end
    end
    if ($found)
        set $ret = $kmodp
    else
        set $ret = 0
    end
end

define loaduxensymbols
    if $argc == 1
        set $uxen_addr = $arg0
    else
        finduxenmodule
        set $uxen_kmod = $ret
        set $uxen_addr = $uxen_kmod->address
    end
    
    set logging file .uxen_address
    set logging overwrite on
    set logging on
    printf "org.uxen.uxen@%p\n", $uxen_addr
    set logging off
    
    set kext-symbol-file-path
    shell kextutil -s . -n -e -a `cat .uxen_address` -r KernelDebugKit/ \
                   -d System.kext \
                   -arch x86_64 uxen.kext && rm -f .uxen_address
    
    add-kext uxen.kext

    add-symbol-file uxen.elf _uxen_core_text \
                    -s .rodata &_uxen_core_rodata \
                    -s .data.read_mostly &_uxen_core_data_read_mostly \
                    -s .data &_uxen_core_data \
                    -s .init.data &_uxen_core_init_data \
                    -s .init.setup &_uxen_core_init_setup \
                    -s .initcall.init &_uxen_core_initcall \
                    -s .bss &_uxen_core_bss
end

define us
    if $argc == 1
        loaduxensymbols $arg0
    else
        loaduxensymbols
    end
end

define clearuxensymbols
    echo Type:\n
    shell echo remove-symbol-file `pwd`/org.uxen.uxen.sym
    shell echo remove-symbol-file `pwd`/uxen.elf
end

define uc
    clearuxensymbols
end

define reboot
    set *(*(unsigned **) 0xffffff8000002928) = 1
    detach
end

define uxenlog
  set $n = $arg0
  set $ulb = uxen_sys_logging_buffer_desc->buffer

  set $ul_prod = $ulb->ulb_producer
  set $ul_read = 0
  if $ul_prod & ~0xffffffffULL
    set $ul_read = $ul_prod - 0x100000000ULL
  end

  set $ul_a1 = ($ul_prod & 0xffffffffULL) - ($ul_read & 0xffffffffULL)
  set $ul_a2 = 0
  if $ul_a1 <= 0
    set $ul_a1 = $ulb->ulb_size - ($ul_read & 0xffffffffULL)
    set $ul_a2 = ($ul_prod & 0xffffffffULL)
  end

  set $avail = $ul_a1 + $ul_a2
  if $n == 0
    set $n = $avail
  end
  if  $n > $avail
    set $n = $avail
  end
  if $n - $ul_a2 < $ul_a1
    set $ul_read += $ul_a1 - ($n - $ul_a2)
    set $ul_a1 = ($n - $ul_a2)
    set $n -= $ul_a1
  end
  if $n < $ul_a2
    set $ul_read += $ul_a2 - $n
    set $ul_a2 = $n
    set $n -= $ul_a2
  end

  printf "%s", &$ulb->ulb_buffer[($ul_read & 0xffffffffULL)]
  #while $ul_a1 > 80
  #  printf "%.80s", &$ulb->ulb_buffer[($ul_read & 0xffffffffULL)]
  #  set $ul_a1 -= 80
  #  set $ul_read += 80
  #end
  #while $ul_a1 > 10
  #  printf "%.10s", &$ulb->ulb_buffer[($ul_read & 0xffffffffULL)]
  #  set $ul_a1 -= 10
  #  set $ul_read += 10
  #end
  #while $ul_a1 >= 1
  #  printf "%.1s", &$ulb->ulb_buffer[($ul_read & 0xffffffffULL)]
  #  set $ul_a1 -= 1
  #  set $ul_read += 1
  #end

  if $ul_a2 != 0
    printf "%s", &$ulb->ulb_buffer[0]
  end

  printf "\n"
end
document uxenlog
| Syntax: uxenlog max (max=0 for all)
| Display uxen system log
end

echo Loading uXen GDB Macros package.  Type "help uxen" for more info.\n

define uxen
printf ""
echo These are the uXen gdb macros.  Type "help uxen" for more info.\n
end

document uxen
| These are the uXen gdb macros.
|
| The following macros are available:
|     clearuxensymbols Output the commands to clear uxen.kexet and
|                      uxen.elf symbols  (alias: uc)
|     loaduxensymbols  Load symbols for uxen.kext and uxen.elf (alias: us)
|     uxenlog          Diplay uxen system log
|     reboot           Reboot the target
|
end

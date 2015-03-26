#
# Copyright 2012-2015, Bromium, Inc.
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
                   uxen.kext && rm -f .uxen_address
    
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
|     reboot           Reboot the target
|
end

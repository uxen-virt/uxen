

SRCDIR ?= .
TOPDIR = $(abspath $(SRCDIR)/..)
include $(TOPDIR)/Config.mk

ifeq (,$(MAKENOW))

export XEN_ROOT ?= $(abspath $(SRCDIR))
include $(XEN_ROOT)/Config.mk

VPATH = $(SRCDIR)

$(TARGET_elf_only)TARGET = uxen.macho
$(TARGET_pe_only)TARGET = uxen-cv.obj
$(TARGET_pe_only)$(X86_64_only)TARGET += uxen-xpdata.obj

XEN_CFLAGS += $(CFLAGS)

$(X86_32_only)XEN_CFLAGS += -m32 -march=i686
$(X86_32_only)XEN_CFLAGS += -mno-stack-arg-probe

$(X86_64_only)XEN_CFLAGS += -m64
#$(X86_64_only)XEN_CFLAGS += -mabi=sysv
$(X86_64_elf_only)XEN_CFLAGS += -mcmodel=large

# PE: frame pointer unusable for stack traces since PE unwind tables
# cannot represent a frame pointer at the top of the frame of a
# function with a large frame causing the frame pointer to end up
# pointing at a "random" location within those frames
$(X86_64_pe_only)XEN_CFLAGS += -fomit-frame-pointer
# PE: options to build with frame pointer and without unwind tables
#$(DEBUG_ONLY)$(X86_64_pe_only)XEN_CFLAGS += -fno-omit-frame-pointer
#$(DEBUG_ONLY)$(X86_64_pe_only)XEN_CFLAGS += -DCONFIG_FRAME_POINTER
#$(DEBUG_ONLY)$(X86_64_pe_only)XEN_CFLAGS += -fno-asynchronous-unwind-tables

$(X86_64_elf_only)XEN_CFLAGS += -fno-omit-frame-pointer
$(X86_64_elf_only)XEN_CFLAGS += -DCONFIG_FRAME_POINTER
$(X86_32_only)XEN_CFLAGS += -fno-omit-frame-pointer
$(X86_32_only)XEN_CFLAGS += -DCONFIG_FRAME_POINTER

$(X86_64_only)XEN_CFLAGS += -fno-stack-protector
$(X86_64_only)XEN_CFLAGS += -mno-red-zone
$(X86_64_only)XEN_CFLAGS += -fno-reorder-blocks
$(X86_64_pe_only)XEN_CFLAGS += -mno-stack-arg-probe

XEN_CFLAGS += -fno-strict-aliasing -std=gnu99
XEN_CFLAGS += -Wall -Wstrict-prototypes -Wno-unused-value
XEN_CFLAGS += -Wdeclaration-after-statement
XEN_CFLAGS += -nostdinc
XEN_CFLAGS += -fno-builtin -fno-common
XEN_CFLAGS += -fno-jump-tables
XEN_CFLAGS += -iwithprefix include
XEN_CFLAGS += -Werror -Wno-pointer-arith -pipe
XEN_CPPFLAGS += -I$(abspath include)
XEN_CPPFLAGS += -I$(abspath $(SRCDIR)/include)
XEN_CPPFLAGS += -I$(abspath include/asm/mach-generic)
XEN_CPPFLAGS += -I$(abspath include/asm/mach-default)
XEN_CPPFLAGS += -I$(TOPDIR)/common
XEN_CFLAGS += -msoft-float
$(TARGET_pe_only)XEN_CFLAGS += -mno-ms-bitfields
XEN_CFLAGS += -fms-extensions
$(OSX)XEN_CFLAGS += -Wno-microsoft
XEN_CPPFLAGS += -D__XEN__ -D__UXEN__
XEN_CPPFLAGS += -D__UXEN_NOT_YET__
XEN_CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@
XEN_CFLAGS += -DPERF_COUNTERS
#XEN_CFLAGS += -DPERF_ARRAYS
#XEN_CFLAGS += -DPERF_VMRW
$(DEBUG_ONLY)XEN_CFLAGS += -DCRASH_DEBUG

$(REL_ONLY)XEN_CPPFLAGS += -DNDEBUG
# always build with debug info and don't strip --
# debug info ends up in pdb file, which is not distributed
$(REL_ONLY)CFLAGS_debug += -g
$(REL_ONLY)LDFLAGS := $(filter-out -s,$(LDFLAGS))

# (julian) The version of binutils that we compile gdb against for OSX
# seems rather strict on the format of debugging symbols in the binary,
# hence forcing strict DWARF2 here.
$(X86_64_elf_only)XEN_CFLAGS += -gdwarf-2 -gstrict-dwarf

ifeq ($(TARGET_HOST),windows)
XEN_CPPFLAGS += -DUXEN_HOST_WINDOWS
$(TARGET_pe_only)XEN_CPPFLAGS += -D__OBJ_PE__
else ifeq ($(TARGET_HOST),osx)
XEN_CPPFLAGS += -DUXEN_HOST_OSX
else
$(error invalid TARGET_HOST)
endif

XEN_LDFLAGS += $(LDFLAGS)
$(X86_32_only)$(TARGET_elf_only)XEN_LDFLAGS += -melf_i386

$(X86_32_only)XEN_LD_EMUL = i386pe
$(X86_64_only)XEN_LD_EMUL = i386pep
$(TARGET_pe_only)XEN_LDFLAGS += -m $(XEN_LD_EMUL)

$(X86_32_only)$(TARGET_pe_only)XEN_CFLAGS += -fno-leading-underscore
$(X86_32_only)$(TARGET_pe_only)XEN_LDFLAGS += --no-leading-underscore

$(TARGET_sysvabi_only)XEN_CFLAGS += -D__SYSV_ABI__
$(TARGET_msabi_only)XEN_CFLAGS += -D__MS_ABI__

# use -O1 on windows, since -O2 compiled uxen.obj has corrupt .pdata
# do the same on OSX, since it seems to exhibit the same issue
CFLAGS_debug := $(subst -O2,-O1,$(CFLAGS_debug))
# files below don't build with -O2 -g on windows
#arch/x86/x86_emulate.o : CFLAGS_debug := $(subst -O2,-O1,$(CFLAGS_debug))
#arch/x86/hvm/vmx/intr.o : CFLAGS_debug := $(subst -O2,-O1,$(CFLAGS_debug))

TARGET1 := $(first $(TARGET))

all: $(TARGET)

SDK_include_files = uxen/uxen_desc.h
SDK_include_files += xen/xen.h xen/xen-compat.h
SDK_include_files += xen/features.h xen/version.h
SDK_include_files += xen/memory.h xen/sysctl.h
SDK_include_files += xen/arch-x86/xen.h xen/arch-x86/xen-$(XEN_TARGET_ARCH).h
SDK_include_files += xen/v4v.h

SDK_include_files := $(patsubst %,$(SDKDIR_include)/%,$(SDK_include_files))

dist: $(TARGET) $(SDK_include_files)
ifeq ($(UXEN_TARGET_FORMAT),pe)
	@mkdir -p $(DISTDIR)/debug
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)/debug
	$(_W)echo Installing -- $(patsubst %-cv.obj,%.obj,$(<F))
	$(_V)$(call install_data,$(patsubst %-cv.obj,%.obj,$(<)),$(DISTDIR)/debug)
endif
ifeq ($(UXEN_TARGET_FORMAT),elf)
	@mkdir -p $(DISTDIR)
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(patsubst %.macho,%.elf,$(<F))
	$(_V)$(call install_data,$(patsubst %.macho,%.elf,$(<)),$(DISTDIR))
endif

_install_banner_%:
	$(_W)echo Installing from $(abspath $(SRCDIR)/include/$(*F)) to $(SDKDIR_include)/$(*F)

$(filter $(SDKDIR_include)/xen/%,$(SDK_include_files)) : $(SDKDIR_include)/xen/% : include/public/% _install_banner_xen
	$(_W)echo Installing -- $*
	@mkdir -p $(SDKDIR_include)/xen/$(*D)
	$(_V)$(call install_data,$<,$(SDKDIR_include)/xen/$*)

$(filter $(SDKDIR_include)/uxen/%,$(SDK_include_files)) : $(SDKDIR_include)/uxen/% : include/uxen/% _install_banner_uxen $(SDKDIR_include)/uxen/.exists
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_data,$<,$(SDKDIR_include)/uxen)

$(BUILDDIR:%=x)clean::
	rm -f uxen.elf
	rm -f uxen-cv.obj uxen.obj uxen-xpdata.obj
	rm -f uxen.check uxen.0.o uxen.1.o
	rm -f uxen-syms.0.S uxen-syms.1.S
	rm -f uxen-prelink.o common/symbols-dummy.o
	rm -f arch/$(TARGET_ARCH)/xen.lds
	rm -f arch/$(TARGET_ARCH)/asm-offsets.s
	rm -f include/asm/asm-offsets.h
	rm -f include/xen/compile.h
	rm -f $(XEN_OBJS)
	rm -rf .deps
	rm -rf include/asm
	rm -f .banner
	$(MAKE) -C $(SRCDIR)/tools clean

XEN_SRCS =
#XEN_SRCS += head.S
XEN_SRCS += uxen/main.c

XEN_SRCS += uxen/kdxinfo.c
$(TARGET_windows_only)XEN_SRCS += uxen/mapcache.c
XEN_SRCS += uxen/memcache-dm.c
XEN_SRCS += uxen/shadow_subst.c
XEN_SRCS += uxen/time.c
$(TARGET_pe_only)$(X86_64_only)XEN_SRCS += uxen/unwind/unwind-pe.c

XEN_SRCS += common/bitmap.c
XEN_SRCS += common/cpu.c
XEN_SRCS += common/cpupool.c
XEN_SRCS += common/domain.c
XEN_SRCS += common/domctl.c
XEN_SRCS += common/event_channel.c
$(DEBUG_ONLY)XEN_SRCS += common/gdbstub.c
XEN_SRCS += common/hvm/save.c
XEN_SRCS += common/kernel.c
XEN_SRCS += common/keyhandler.c
XEN_SRCS += common/memory.c
XEN_SRCS += common/lib.c
XEN_SRCS += common/notifier.c
XEN_SRCS += common/page_alloc.c
XEN_SRCS += common/page_store.c
#XEN_SRCS += common/pci_test.c
XEN_SRCS += common/perfc.c
XEN_SRCS += common/radix-tree.c
XEN_SRCS += common/rangeset.c
XEN_SRCS += common/rcupdate.c
XEN_SRCS += common/schedule.c
XEN_SRCS += common/sched_host.c
XEN_SRCS += common/softirq.c
XEN_SRCS += common/sort.c
XEN_SRCS += common/spinlock.c
XEN_SRCS += common/string.c
XEN_SRCS += common/symbols.c
XEN_SRCS += common/sysctl.c
XEN_SRCS += common/tasklet.c
XEN_SRCS += common/trace.c
XEN_SRCS += common/time.c
XEN_SRCS += common/timer.c
XEN_SRCS += common/v4v.c
XEN_SRCS += common/version.c
XEN_SRCS += common/vsprintf.c
XEN_SRCS += common/xenoprof.c
XEN_SRCS += common/xmalloc_tlsf.c
XEN_SRCS += drivers/char/console.c
XEN_SRCS += drivers/char/ns16550.c
XEN_SRCS += drivers/char/serial.c
XEN_SRCS += drivers/passthrough/io.c
XEN_SRCS += drivers/passthrough/pci.c
XEN_SRCS += arch/x86/bitops.c
XEN_SRCS += arch/x86/clear_page.S
XEN_SRCS += arch/x86/delay.c
XEN_SRCS += arch/x86/domain.c
XEN_SRCS += arch/x86/domctl.c
XEN_SRCS += arch/x86/extable.c
XEN_SRCS += arch/x86/flushtlb.c
$(DEBUG_ONLY)XEN_SRCS += arch/x86/gdbstub.c
XEN_SRCS += arch/x86/hvm/save.c
XEN_SRCS += arch/x86/i387.c
XEN_SRCS += arch/x86/i8259.c
XEN_SRCS += arch/x86/mm.c
XEN_SRCS += arch/x86/nmi.c
XEN_SRCS += arch/x86/numa.c
XEN_SRCS += arch/x86/pci.c
XEN_SRCS += arch/x86/percpu.c
XEN_SRCS += arch/x86/poke.c
XEN_SRCS += arch/x86/setup.c
XEN_SRCS += arch/x86/shutdown.c
XEN_SRCS += arch/x86/smp.c
XEN_SRCS += arch/x86/smpboot.c
XEN_SRCS += arch/x86/string.c
XEN_SRCS += arch/x86/sysctl.c
XEN_SRCS += arch/x86/tboot.c
XEN_SRCS += arch/x86/time.c
XEN_SRCS += arch/x86/traps.c
XEN_SRCS += arch/x86/usercopy.c
XEN_SRCS += arch/x86/x86_emulate.c
XEN_SRCS += arch/x86/xstate.c
XEN_SRCS += arch/x86/cpu/amd.c
XEN_SRCS += arch/x86/cpu/common.c
XEN_SRCS += arch/x86/cpu/intel.c
XEN_SRCS += arch/x86/cpu/intel_cacheinfo.c
XEN_SRCS += arch/x86/cpu/mtrr/main.c
XEN_SRCS += arch/x86/hvm/asid.c
XEN_SRCS += arch/x86/hvm/ax.c
arch/x86/hvm/ax.o: XEN_CFLAGS += -Wno-unused-function
XEN_SRCS += arch/x86/hvm/ax_pv_vmcs.S
XEN_SRCS += arch/x86/hvm/xen_pv.c
XEN_SRCS += arch/x86/hvm/xcfm.c
XEN_SRCS += arch/x86/hvm/debug_port.c
XEN_SRCS += arch/x86/hvm/emulate.c
XEN_SRCS += arch/x86/hvm/i8254.c
XEN_SRCS += arch/x86/hvm/intercept.c
XEN_SRCS += arch/x86/hvm/io.c
XEN_SRCS += arch/x86/hvm/irq.c
XEN_SRCS += arch/x86/hvm/hpet.c
XEN_SRCS += arch/x86/hvm/hvm.c
XEN_SRCS += arch/x86/hvm/mtrr.c
XEN_SRCS += arch/x86/hvm/nestedhvm.c
XEN_SRCS += arch/x86/hvm/pci_emul.c
XEN_SRCS += arch/x86/hvm/pmtimer.c
XEN_SRCS += arch/x86/hvm/rtc.c
XEN_SRCS += arch/x86/hvm/svm/asid.c
XEN_SRCS += arch/x86/hvm/svm/emulate.c
XEN_SRCS += arch/x86/hvm/svm/entry.S
XEN_SRCS += arch/x86/hvm/svm/intr.c
XEN_SRCS += arch/x86/hvm/svm/nestedsvm.c
XEN_SRCS += arch/x86/hvm/svm/svm.c
XEN_SRCS += arch/x86/hvm/svm/svmdebug.c
XEN_SRCS += arch/x86/hvm/svm/vmcb.c
#XEN_SRCS += arch/x86/hvm/svm/vpmu.c
XEN_SRCS += arch/x86/hvm/vioapic.c
XEN_SRCS += arch/x86/hvm/viridian.c
XEN_SRCS += arch/x86/hvm/vlapic.c
XEN_SRCS += arch/x86/hvm/vpic.c
#XEN_SRCS += arch/x86/hvm/vpmu.c
XEN_SRCS += arch/x86/hvm/vpt.c
XEN_SRCS += arch/x86/hvm/vmx/entry.S
XEN_SRCS += arch/x86/hvm/vmx/intr.c
XEN_SRCS += arch/x86/hvm/vmx/realmode.c
##XEN_SRCS += arch/x86/hvm/vmx/vpmu_core2.c
XEN_SRCS += arch/x86/hvm/vmx/vmx.c
XEN_SRCS += arch/x86/hvm/vmx/vmcs.c
## XEN_SRCS += arch/x86/mm/guest_walk.c  ==> guest_walk_X.o below
## XEN_SRCS += arch/x86/mm/hap/guest_walk.c  ==> hap/guest_walk_X.o below
XEN_SRCS += arch/x86/mm/paging.c
XEN_SRCS += arch/x86/mm/p2m.c
XEN_SRCS += arch/x86/mm/p2m-ept.c
XEN_SRCS += arch/x86/mm/p2m-pod.c
XEN_SRCS += arch/x86/mm/p2m-pt.c
XEN_SRCS += arch/x86/mm/hap/hap.c
#XEN_SRCS += arch/x86/mm/shadow/common.c
## XEN_SRCS += arch/x86/mm/shadow/multi.c  ==> guest_X.o below
$(DEBUG_ONLY)XEN_SRCS += arch/x86/$(XEN_TARGET_ARCH)/gdbstub.c
XEN_SRCS += arch/x86/$(XEN_TARGET_ARCH)/mm.c
XEN_SRCS += arch/x86/$(XEN_TARGET_ARCH)/pci.c
XEN_SRCS += arch/x86/$(XEN_TARGET_ARCH)/traps.c

COMMON_SRCS += lz4/lz4.c
arch/x86/mm/p2m-pod.o: XEN_CPPFLAGS += -I$(TOPDIR)/common/lz4

XEN_OBJS = $(patsubst %.S,%.o,$(patsubst %.c,%.o,$(XEN_SRCS)))
#XEN_OBJS += arch/x86/mm/shadow/guest_2.o
#XEN_OBJS += arch/x86/mm/shadow/guest_3.o
#$(X86_64_only)XEN_OBJS += arch/x86/mm/shadow/guest_4.o
XEN_OBJS += arch/x86/mm/guest_walk_2.o
XEN_OBJS += arch/x86/mm/guest_walk_3.o
$(X86_64_only)XEN_OBJS += arch/x86/mm/guest_walk_4.o
XEN_OBJS += arch/x86/mm/hap/guest_walk_2.o
XEN_OBJS += arch/x86/mm/hap/guest_walk_3.o
$(X86_64_only)XEN_OBJS += arch/x86/mm/hap/guest_walk_4.o

XEN_OBJS += $(patsubst %.S,%.o,$(patsubst %.c,%.o,$(COMMON_SRCS)))

$(XEN_OBJS) common/symbols-dummy.o: include/asm/config.h .deps/.exists
arch/$(TARGET_ARCH)/asm-offsets.s: include/asm/config.h .deps/.exists
$(XEN_OBJS): include/asm/asm-offsets.h
$(XEN_OBJS): .obj_dirs

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(TARGET_CC) $(XEN_CFLAGS) $(XEN_CPPFLAGS) -c $< -o $@

arch/x86/bitops.o : %.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(TARGET_CC) $(XEN_CFLAGS) $(XEN_CPPFLAGS) -Wa,--divide -c $< -o $@

%.o : %.S
	$(_W)echo Assembling - $@
	$(_V)$(TARGET_CC) $(XEN_CFLAGS) $(XEN_CPPFLAGS) -D__ASSEMBLY__ -Wa,--divide -c $< -o $@

arch/x86/mm/shadow/guest_%.o: arch/x86/mm/shadow/multi.c
	$(_W)echo Compiling - $@
	$(_V)$(TARGET_CC) $(XEN_CFLAGS) $(XEN_CPPFLAGS) -DGUEST_PAGING_LEVELS=$* -c $< -o $@

arch/x86/mm/guest_walk_%.o: arch/x86/mm/guest_walk.c
	$(_W)echo Compiling - $@
	$(_V)$(TARGET_CC) $(XEN_CFLAGS) $(XEN_CPPFLAGS) -DGUEST_PAGING_LEVELS=$* -c $< -o $@

arch/x86/mm/hap/guest_walk_%.o: arch/x86/mm/hap/guest_walk.c
	$(_W)echo Compiling - $@
	$(_V)$(TARGET_CC) $(XEN_CFLAGS) $(XEN_CPPFLAGS) -DGUEST_PAGING_LEVELS=$* -c $< -o $@

lz4/%.o: $(TOPDIR)/common/lz4/%.c
	$(_W)echo Compiling - $@
	$(_V)$(TARGET_CC) $(XEN_CFLAGS) $(XEN_CPPFLAGS) -c $< -o $@

.obj_dirs:
	@mkdir -p $(dir $(XEN_OBJS))
	@touch $@

UXEN_KEXT_SYM_FIXUP = memcpy memcmp memmove memset
UXEN_KEXT_SYM_FIXUP += panic tsc_get_info
UXEN_KEXT_SYM_FIXUP += serial_putc serial_getc
UXEN_KEXT_SYM_FIXUP += snprintf sscanf vsnprintf vsscanf
UXEN_KEXT_SYM_FIXUP += strchr strcmp strncmp strlcat strlcpy strlen strnlen
UXEN_KEXT_SYM_FIXUP := $(patsubst %,-nl:%,$(UXEN_KEXT_SYM_FIXUP))

uxen.macho: uxen.elf
	$(_W)echo Converting - $@
	$(_V)objconv -fmacho -nu $(UXEN_KEXT_SYM_FIXUP) $< $@

$(TARGET_pe_only)UXEN_LDS = uxen/uxen-pe.lds
$(TARGET_elf_only)UXEN_LDS = arch/$(TARGET_ARCH)/xen.lds
$(UXEN_LDS): include/asm/config.h

uxen.elf: uxen-prelink.o uxen-syms.1.o $(UXEN_LDS)
	$(_W)echo Linking - $@
	$(_V)$(TARGET_LD) $(XEN_LDFLAGS) -T $(UXEN_LDS) -r -o $@ \
	  -N $(filter-out $(UXEN_LDS),$^)

uxen-cv.obj: uxen.obj
	$(_W)echo Generating - $@
	$(_V)$(DWARFCV) $< $@.tmp
	$(_V)$(TARGET_OBJCOPY) \
	  -R .debug_aranges \
	  -R .debug_info \
	  -R .debug_abbrev \
	  -R .debug_line \
	  -R .debug_frame \
	  -R .debug_str \
	  -R .debug_ranges \
	  -R '.odebug$$S' \
	  $@.tmp $@ || \
	  (rm -f $@.tmp; false)
	@rm -f $@.tmp

uxen_post_link = true
uxen.obj: uxen-prelink.o uxen-syms.1.o $(UXEN_LDS)
	$(_W)echo Linking - $@
	$(_V)$(TARGET_LD) $(XEN_LDFLAGS) -T $(UXEN_LDS) -r -o $@ \
	  $(filter-out $(UXEN_LDS),$^) && $(call uxen_post_link,$@)

uxen-xpdata.obj: uxen.obj uxen/unwind/xpdata-extract$(HOST_EXE_SUFFIX)
	$(_W)echo Generating - $@
	$(_V)./uxen/unwind/xpdata-extract$(HOST_EXE_SUFFIX) $< $@

.INTERMEDIATE: uxen.1.o
uxen.1.o: uxen-prelink.o uxen-syms.0.o $(UXEN_LDS)
	$(_W)echo Linking - $@
	$(_V)$(TARGET_LD) $(XEN_LDFLAGS) -T $(UXEN_LDS) -r -o $@ \
	  $(filter-out $(UXEN_LDS),$^)

.INTERMEDIATE: uxen.0.o
uxen.0.o: uxen.check
uxen.0.o: uxen-prelink.o common/symbols-dummy.o $(UXEN_LDS)
	$(_W)echo Linking - $@
	$(_V)$(TARGET_LD) $(XEN_LDFLAGS) -T $(UXEN_LDS) -r -o $@ \
	  uxen-prelink.o common/symbols-dummy.o

SYMBOLS_ARGS := --all-symbols

.INTERMEDIATE: uxen-syms.0.o uxen-syms.1.o
uxen-syms.%.S: uxen.%.o tools/symbols$(HOST_EXE_SUFFIX)
	$(_W)echo Generating - $@
	$(_V)$(TARGET_NM) -n $< | \
	  ./tools/symbols$(HOST_EXE_SUFFIX) $(SYMBOLS_ARGS) >$@ || \
	    (rm -f $@; false)

.INTERMEDIATE: uxen-prelink.o
$(TARGET_pe_only)uxen-prelink.o: uxen/$(XEN_LD_EMUL).xr common/version.o $(XEN_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(TARGET_LD) $(XEN_LDFLAGS) -T $< -r -o $@ $(XEN_OBJS)

$(TARGET_elf_only)uxen-prelink.o: common/version.o $(XEN_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(TARGET_LD) $(XEN_LDFLAGS) -r -o $@ $(XEN_OBJS)

.INTERMEDIATE: uxen/uxen-pe.lds
uxen/uxen-pe.lds: uxen/uxen-pe.lds.S
	@mkdir -p $(@D)
	$(_V)$(TARGET_CC) -P -E $(XEN_CFLAGS) $(XEN_CPPFLAGS) -D__ASSEMBLY__ \
	  -o $@ $<

.INTERMEDIATE: arch/$(TARGET_ARCH)/xen.lds
arch/$(TARGET_ARCH)/xen.lds: arch/$(TARGET_ARCH)/xen.lds.S
	@mkdir -p $(@D)
	$(_V)$(TARGET_CC) -P -E -Ui386 $(XEN_CFLAGS) $(XEN_CPPFLAGS) \
	  -D__ASSEMBLY__ -o $@ $<

$(X86_32_only)UXEN_RELOC_ADDR ?= 0x80000000
$(X86_64_only)UXEN_RELOC_ADDR ?= 0xFFFFFFFF80000000

.INTERMEDIATE: uxen.check
$(TARGET_elf_only)uxen.check: uxen-prelink.o common/symbols-dummy.o $(UXEN_LDS)
	$(_V)$(TARGET_LD) $(XEN_LDFLAGS) -Ttext $(UXEN_RELOC_ADDR) -T $(UXEN_LDS) -o $@ $(filter-out $(UXEN_LDS),$^) 2>&1 | grep undefined.ref | tee /dev/tty | (urs=$$(wc -l); echo "$@: undefined references: $$urs"; [ "$$urs" -eq 0 ])

$(TARGET_pe_only)uxen.check: uxen-prelink.o common/symbols-dummy.o $(UXEN_LDS)
	$(_V)$(TARGET_LD) $(XEN_LDFLAGS) -T $(UXEN_LDS) -o $@ $(filter-out $(UXEN_LDS),$^) 2>&1 | tee /dev/tty | sed -n 's/.* undefined reference to /undefined reference /p' | sort -u | tee /dev/tty | (urs=$$(wc -l); echo "Checking - uxen.obj: undefined references: $$urs"; [ "$$urs" -eq 0 ])

uxen-gdb: .phony
	@[ -e $(TARGET1) ] || $(MAKE) $(TARGET1)
	$(_W)echo Linking - $@
	$(_V)$(TARGET_LD) $(XEN_LDFLAGS) -o $@ $(TARGET1)


uxen: arch/$(TARGET_ARCH)/xen-abs.lds $(XEN_OBJS)
	$(_V)$(TARGET_LD) $(LDFLAGS) -T arch/$(TARGET_ARCH)/xen-abs.lds -r \
	  -N $(XEN_OBJS) -o $@

.PHONY: arch/$(TARGET_ARCH)/xen-abs.lds
arch/$(TARGET_ARCH)/xen-abs.lds: arch/$(TARGET_ARCH)/xen.lds.S include/asm/asm-offsets.h
	$(_V)$(TARGET_CC) -P -E -Ui386 $(XEN_CFLAGS) $(XEN_CPPFLAGS) \
	  -D__ASSEMBLY__ -DUXEN_RELOC_ADDR=$(UXEN_RELOC_ADDR) -o $@ $<


$(HOST_NOT_WINDOWS)include/asm/config.h:
	@rm -rf include/asm
	@(cd $(SRCDIR)/include/asm-$(TARGET_ARCH) && find . -type d) | \
	  while read d; \
	  do \
	    mkdir -p include/asm/$$d; \
	  done
	@(cd $(SRCDIR)/include/asm-$(TARGET_ARCH) && find * -type f) | \
	  grep -v asm-offsets.h | while read f; \
	  do \
	    ln -s $(SRCDIR)/include/asm-$(TARGET_ARCH)/$$f include/asm/$$f; \
	  done

$(HOST_WINDOWS)include/asm/config.h:
	@rm -rf include/asm
	@(cd $(SRCDIR)/include/asm-$(TARGET_ARCH) && find . -type d) | \
	  while read d; \
	  do \
	    mkdir -p include/asm/$$d; \
	  done
	@WSRCDIR=$(shell cd $(SRCDIR) && pwd -W) && \
	  (cd $(SRCDIR)/include/asm-$(TARGET_ARCH) && find * -type f) | \
	    grep -v asm-offsets.h | while read f; \
	    do \
	      echo "#include \"$$WSRCDIR/include/asm-$(TARGET_ARCH)/$$f\"" \
	        >include/asm/$$f; \
	    done

# This is the correct place to edit the build version.
# All other places this is stored (eg. compile.h) should be autogenerated.
export XEN_VERSION       = 0
export XEN_SUBVERSION    = 5
export XEN_EXTRAVERSION ?= -unlimited$(XEN_VENDORVERSION)
export XEN_FULLVERSION   = $(XEN_VERSION).$(XEN_SUBVERSION)$(XEN_EXTRAVERSION)
-include xen-version

export XEN_WHOAMI	?= $(USER)
export XEN_DOMAIN	?= $(shell ([ -x /bin/dnsdomainname ] && /bin/dnsdomainname) || ([ -x /bin/domainname ] && /bin/domainname || echo [unknown]))

$(SRCDIR)/common/version.c: include/xen/compile.h
include/xen/compile.h: $(filter-out common/version.c,$(XEN_SRCS))
include/xen/compile.h: $(patsubst %,$(TOPDIR)/common/%,$(COMMON_SRCS))

tools/symbols$(HOST_EXE_SUFFIX): tools/symbols.c
	@$(MAKE) -C $(SRCDIR)/tools symbols$(HOST_EXE_SUFFIX)

tools/figlet/figlet$(HOST_EXE_SUFFIX): tools/figlet/figlet.c
	@$(MAKE) -C $(SRCDIR)/tools/figlet

uxen/unwind/xpdata-extract$(HOST_EXE_SUFFIX): uxen/unwind/xpdata-extract.c
	@$(MAKE) -C $(SRCDIR)/uxen/unwind xpdata-extract$(HOST_EXE_SUFFIX)

.banner: tools/figlet/figlet$(HOST_EXE_SUFFIX) Makefile
	$(_V)./$< -d $(SRCDIR)/tools/figlet -e %00b5Xen unlimited 2>$@2 >$@1
	@cat $@1 $@2 >$@
	@rm -f $@1 $@2

# compile.h contains dynamic build info. Rebuilt on every 'make' invocation.
include/xen/compile.h: include/xen/compile.h.in .banner
	@mkdir -p $(@D)
	@cd $(SRCDIR) && git log --pretty=format:%H -n 1 >/dev/null 2>&1
	@sed -e 's/@@date@@/$(shell LC_ALL=C date)/g' \
	    -e 's/@@time@@/$(shell LC_ALL=C date +%T)/g' \
	    -e 's/@@whoami@@/$(XEN_WHOAMI)/g' \
	    -e 's/@@domain@@/$(XEN_DOMAIN)/g' \
	    -e 's/@@hostname@@/$(shell hostname)/g' \
	    -e 's!@@compiler@@!$(shell $(TARGET_CC) $(CFLAGS) -v 2>&1 | grep version | tail -1)!g' \
	    -e 's/@@version@@/$(XEN_VERSION)/g' \
	    -e 's/@@subversion@@/$(XEN_SUBVERSION)/g' \
	    -e 's/@@extraversion@@/$(XEN_EXTRAVERSION)/g' \
	    -e 's!@@changeset@@!$(shell cd $(SRCDIR) && echo $$(git log --pretty=format:%H -n 1 && git diff --quiet || echo -dirty))!g' \
	    < $< > $@.new
	@grep \" .banner >> $@.new
	@grep -v \" .banner
	@mv -f $@.new $@

include/asm/asm-offsets.h: arch/$(TARGET_ARCH)/asm-offsets.s
	@(set -e; \
	  echo "/*"; \
	  echo " * DO NOT MODIFY."; \
	  echo " *"; \
	  echo " * This file was auto-generated from $<"; \
	  echo " *"; \
	  echo " */"; \
	  echo ""; \
	  echo "#ifndef __ASM_OFFSETS_H__"; \
	  echo "#define __ASM_OFFSETS_H__"; \
	  echo ""; \
	  sed -ne "/^->/{s:^->\([^ ]*\) [\$$#]*\([^ ]*\) \(.*\):#define \1 \2 /* \3 */:; s:->::; p;}"; \
	  echo ""; \
	  echo "#endif") <$< >$@

arch/$(TARGET_ARCH)/asm-offsets.s: arch/$(TARGET_ARCH)/$(XEN_TARGET_ARCH)/asm-offsets.c
	@mkdir -p $(@D)
	$(_W)echo Generating - $@
	$(_V)$(TARGET_CC) $(XEN_CFLAGS) $(XEN_CPPFLAGS) -S -o $@ $<

-include .deps/*.d

.PHONY: xenversion
xenversion:
	@echo $(XEN_FULLVERSION)

.PHONY: uxenversion
uxenversion:
	@echo $(XEN_FULLVERSION)

.PHONY: src-files
src-files:
	@echo $(XEN_SRCS) $(patsubst %,$(TOPDIR)/common/%,$(COMMON_SRCS))

endif # MAKENOW

.PHONY: TAGS
TAGS:
	set -e; rm -f TAGS; \
	find uxen arch common include drivers crypto -name '*.[chsS]' | xargs etags -a -

.PHONY: tags
tags:
	set -e; rm -f tags; \
	find . -name '*.[chsS]' | xargs ctags

#DISTDIR = ../dist
#
#.PHONY: install-headers
#install-headers: $(DISTDIR)/.include-xen
#	@ :
#
#$(DISTDIR)/.include-xen:
#	@mkdir -p $(DISTDIR)/include/xen
#	cp -fr include/public/. $(DISTDIR)/include/xen/
#	$(MAKE) -C ../tools/include/xen-foreign
#	@mkdir -p $(DISTDIR)/include/xen/foreign/
#	cp -f ../tools/include/xen-foreign/*.h $(DISTDIR)/include/xen/foreign/
#	@echo '$(DISTDIR)/.include-xen: \\' >.deps/DISTDIR_.include-xen.d
#	@find include/public -type f | \
#	  sed -e 's/^/  /' -e 's/$$/ \\/' >>.deps/DISTDIR_.include-xen.d
#	@echo >>.deps/DISTDIR_.include-xen.d
#	@touch $@

#uxen_prog: uxen_prog.o libelf/libelf-loader.o
#uxen_prog: libelf/libelf-relocate.o libelf/libelf-tools.o
#
#uxen_prog.o: uxen_mod.c uxen.hex
#	$(TARGET_CC) -DUXEN_STANDALONE $(CFLAGS) -c -o $@ $<

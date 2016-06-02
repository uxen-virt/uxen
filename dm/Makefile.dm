#
# Copyright 2012-2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

all: build-uxendm
dist: install-uxendm
build-uxendm install-uxendm: check-build_info.h

build-uxendm: uxendm$(EXE_SUFFIX)
install-uxendm: $(DISTDIR)/uxendm$(EXE_SUFFIX)

$(OSX)OSX_NOT_YET = no_
$(OSX_NOT_YET)OSX_CONFIG_NOT = no_
$(OSX_CONFIG_NOT)CPPFLAGS += -DOSX_NOT_YET

$(REL_ONLY)CONFIG_CONTROL_TEST ?= no_

$(REL_ONLY)CONFIG_MONITOR ?= no_

$(OSX_CONFIG_NOT)CONFIG_VBOXDRV ?= no_

#CONFIG_NICKEL ?= no_
#CONFIG_NICKEL_THREADED ?= no_

DM_CONFIG_DUMP_BLOCK_STAT ?= no_
DM_CONFIG_DUMP_CPU_STAT ?= no_
DM_CONFIG_DUMP_MEMORY_STAT ?= no_
DM_CONFIG_DUMP_SWAP_STAT ?= no_

COMMONINCLUDEDIR = $(TOPDIR)/common/include
LIBELFDIR = $(TOPDIR)/xen/common/libelf
LIBELFDIR_include = $(TOPDIR)/common/include/xen-public
LZ4DIR = $(TOPDIR)/common/lz4
LZ4DIR_include = $(TOPDIR)/common/lz4
CUCKOODIR = $(TOPDIR)/common/cuckoo
CUCKOODIR_include = $(TOPDIR)/common/cuckoo
QEMUDIR = $(SRCROOT)/qemu
VBOXDRVDIR = $(SRCROOT)/vbox-drivers
NICKELDIR = $(SRCROOT)/nickel
XENPUBLICDIR = $(TOPDIR)/common/include/xen-public
XENDIR_include = $(TOPDIR)/xen/include
VBOX_INCLUDES = $(TOPDIR)/dm/vbox-includes
FILECRYPT_INCLUDES = $(TOPDIR)/common/filecrypt

CFLAGS += -D__UXEN_TOOLS__ -DQEMU_UXEN
$(OSX)CFLAGS += -Wno-deprecated-declarations
CFLAGS += -fms-extensions
$(OSX)CFLAGS += -Wno-microsoft

$(DEBUG_ONLY)CFLAGS += -DDEBUG=1

CFLAGS += $(YAJL_CPPFLAGS)
CFLAGS += -D_err_vprintf=control_err_vprintf -D_err_flush=control_err_flush

$(WINDOWS)CPPFLAGS += -D_FILE_OFFSET_BITS=64

DM_CFLAGS = -I$(TOPDIR)
DM_CFLAGS += -Dmain=dm_main

$(CONFIG_CONTROL_TEST)control.o: DM_CFLAGS += -DCONTROL_TEST=1
$(CONFIG_MONITOR)DM_CFLAGS += -DMONITOR=1
$(CONFIG_MONITOR)QEMU_CFLAGS += -DMONITOR=1
$(CONFIG_NICKEL_THREADED)DM_CFLAGS += -DNICKEL_THREADED=1
$(CONFIG_VBOXDRV)DM_CFLAGS += -DCONFIG_VBOXDRV=1

$(filter no_,$(DM_CONFIG_DUMP_BLOCK_STAT))DM_CFLAGS += \
         -DCONFIG_DUMP_BLOCK_STAT=1
$(filter no_,$(DM_CONFIG_DUMP_CPU_STAT))DM_CFLAGS += \
         -DCONFIG_DUMP_CPU_STAT=1
$(filter no_,$(DM_CONFIG_DUMP_MEMORY_STAT))DM_CFLAGS += \
         -DCONFIG_DUMP_MEMORY_STAT=1
$(filter no_,$(DM_CONFIG_DUMP_SWAP_STAT))DM_CFLAGS += \
         -DCONFIG_DUMP_SWAP_STAT=1

DM_SRCS =
# on OSX constructor functions are invoked in linking order, therefore
# this needs to be first to setup logging
$(OSX)DM_SRCS += osx-logging.o
DM_SRCS += aio.c
DM_SRCS += async-op.c
DM_SRCS += base64.c
DM_SRCS += bh.c
block.o: CPPFLAGS += $(LIBVHD_CPPFLAGS)
block.o: $(LIBVHD_DEPS)
DM_SRCS += block.c
block-vhd.o: CPPFLAGS += $(LIBVHD_CPPFLAGS)
block-vhd.o: $(LIBVHD_DEPS)
DM_SRCS += block-vhd.c
$(OSX)DM_SRCS += block-raw-posix.c
$(WINDOWS)DM_SRCS += block-raw-win32.c
DM_SRCS += block-swap.c
block-swap.o: CPPFLAGS += $(LZ4_CPPFLAGS)
DM_SRCS +=   block-swap/copybuffer.c
DM_SRCS +=   block-swap/dubtree.c
block-swap_dubtree.o: CPPFLAGS += $(LZ4_CPPFLAGS)
DM_SRCS +=   block-swap/md5.c
DM_SRCS +=   block-swap/simpletree.c
DM_SRCS +=   block-swap/hashtable.c
DM_SRCS += char.c
DM_SRCS += clock.c
DM_SRCS += conffile.c
$(WINDOWS)DM_SRCS += console-win32.c
console-win32.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
console-win32.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
console-win32.o: CPPFLAGS += -I$(TOPDIR)/common/uxenconsole
$(CONFIG_VBOXDRV)console-win32.o: CPPFLAGS += -DNOTIFY_CLIPBOARD_SERVICE
$(OSX)DM_SRCS += console-osx.m
console-osx.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
console-osx.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
DM_SRCS += console-remote.c
console-remote.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
console-remote.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
console-remote.o: CPPFLAGS += -I$(TOPDIR)/common/uxenconsole
$(CONFIG_VBOXDRV)console-remote.o: CPPFLAGS += -DNOTIFY_CLIPBOARD_SERVICE
DM_SRCS += console.c
console.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
console.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
DM_SRCS += control.c
control.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
$(OSX_NOT_YET)DM_SRCS += cuckoo.c
$(OSX_NOT_YET)cuckoo.o: CFLAGS_debug := $(subst -O0,-O2,$(CFLAGS_debug))
$(OSX_NOT_YET)cuckoo.o: CFLAGS += $(LZ4_CPPFLAGS)
$(OSX_NOT_YET)cuckoo.o: CPPFLAGS += $(CUCKOO_CPPFLAGS)
$(OSX_NOT_YET)DM_SRCS += cuckoo-uxen.c
$(OSX_NOT_YET)cuckoo-uxen.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
$(OSX_NOT_YET)cuckoo-uxen.o: CPPFLAGS += $(LZ4_CPPFLAGS)
DM_SRCS += debug.c
DM_SRCS += dev.c
DM_SRCS += dict.c
DM_SRCS += dict-rpc.c
DM_SRCS += dm.c
dm.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
dm.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
dm.o: CPPFLAGS += $(LIBFILECRYPT_CPPFLAGS)
DM_SRCS += dmpdev-rpc.c
DM_SRCS += dmreq.c
dmreq.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
dmreq.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
DM_SRCS += edid.c
DM_SRCS += filebuf.c
DM_SRCS += firmware.c
$(WINDOWS)DM_SRCS += guest-agent.c
guest-agent.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
guest-agent.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
DM_SRCS += nickel/http-parser/http_parser.c
DM_SRCS += input.c
DM_SRCS += introspection.c
introspection.o: CPPFLAGS += -I$(XENPUBLICDIR)
$(WINDOWS)DM_SRCS += introspection-win7.c
introspection-win7.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
$(OSX)DM_SRCS += ioh-osx.c
$(WINDOWS)DM_SRCS += ioh-win32.c
DM_SRCS += ioh.c
DM_SRCS += iomem.c
DM_SRCS += ioport.c
DM_SRCS += ioreq.c
ioreq.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
ioreq.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
DM_SRCS += iovec.c
DM_SRCS += ipc.c
DM_SRCS += lib.c
$(WINDOWS)DM_SRCS += malloc-wrappers.c
DM_SRCS += mapcache-memcache.c
mapcache-memcache.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
mapcache-memcache.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
DM_SRCS += memory.c
memory.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
DM_SRCS += memory-virt.c
memory-virt.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
$(CONFIG_MONITOR)DM_SRCS += monitor.c
DM_SRCS += mr.c
DM_SRCS += ns.c
DM_SRCS += ns-echo.c
$(CONFIG_WEBDAV)DM_SRCS += ns-webdav.c
$(CONFIG_WEBDAV)DM_SRCS += webdav.c
DM_SRCS += ns-forward.c
DM_SRCS += ns-logging.c
$(CONFIG_VBOXDRV)DM_SRCS += shared-folders.c
$(CONFIG_VBOXDRV)shared-folders.o: CFLAGS += \
      -I$(TOPDIR)/vm-support/windows/uxensf/driver
$(CONFIG_VBOXDRV)shared-folders.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
$(CONFIG_VBOXDRV)shared-folders.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
$(CONFIG_VBOXDRV)DM_SRCS += clipboard.c
$(CONFIG_VBOXDRV)DM_SRCS += clipboard-protocol.c
$(CONFIG_VBOXDRV)clipboard-protocol.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
$(CONFIG_VBOXDRV)clipboard-protocol.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)

$(OSX)DM_SRCS += osx.c
osx.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
osx.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
$(OSX)DM_SRCS += osx-app-delegate.m
$(OSX)DM_SRCS += osx-main.m
$(OSX)DM_SRCS += osx-vm-view.m
DM_SRCS += priv-heap.c
DM_SRCS += qemu_glue.c
DM_SRCS += rbtree.c
DM_SRCS += sysbus.c
DM_SRCS += timer.c
DM_SRCS += uuidgen.c
DM_SRCS += version.c
version.o: CPPFLAGS += -I$(BUILDDIR)
version.o: build_info.h
DM_SRCS += vm.c
vm.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
vm.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
DM_SRCS += vm-save.c
vm-save.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
vm-save.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
vm-save.o: CPPFLAGS += $(LZ4_CPPFLAGS)
vm-save.o: CPPFLAGS += $(CUCKOO_CPPFLAGS)
$(WINDOWS)DM_SRCS += win32.c
DM_SRCS += xen.c
xen.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
xen.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
DM_SRCS += uxen.c
uxen.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
uxen.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
DM_SRCS += vram.c
vram.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
vram.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
vram.o: CPPFLAGS += $(LZ4_CPPFLAGS)

DM_SRCS += hw/applesmc.c
DM_SRCS += hw/dmpdev.c
DM_SRCS += hw/pci-ram.c
hw_pci-ram.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
hw_pci-ram.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
DM_SRCS += hw/piix4acpi.c
hw_piix4acpi.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
hw_piix4acpi.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
$(OSX_NOT_YET)DM_SRCS += hw/uxen_audio.c
$(OSX_NOT_YET)DM_SRCS += hw/wasapi.c
$(OSX_NOT_YET)DM_SRCS += hw/resampler.c
DM_SRCS += hw/uxen_debug.c
DM_SRCS += hw/uxen_display.c
$(OSX_NOT_YET)DM_SRCS += hw/uxen_hid.c
hw_uxen_hid.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
hw_uxen_hid.o: CPPFLAGS += $(LIBUXENCTL_CPPFLAGS)
DM_SRCS += hw/uxen_platform.c
hw_uxen_platform.o: CPPFLAGS += -I$(XENPUBLICDIR)
hw_uxen_platform.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
DM_SRCS += hw/vga.c
hw_vga.o: CPPFLAGS += $(LZ4_CPPFLAGS)
DM_SRCS += hw/xenpc.c
hw_xenpc.o: CPPFLAGS += $(LIBXC_CPPFLAGS)
DM_SRCS += hw/xenrtc.c
DM_SRCS += hw/uxen_net.c
hw_uxen_net.o: CPPFLAGS += -I$(XENPUBLICDIR)
DM_SRCS += hw/uxen_null.c
hw_uxen_null.o: CPPFLAGS += -I$(XENPUBLICDIR)
DM_SRCS += hw/uxen_stor.c
DM_SRCS += hw/uxen_scsi.c
$(OSX)DM_SRCS += hw/uxen_scsi_osx.c
hw_uxen_stor.o: CPPFLAGS += -I$(XENPUBLICDIR)

$(WINDOWS)DM_SRCS += hw/uxen_v4v_win32.c
hw_uxen_v4v_win32.o: CPPFLAGS += -I$(XENPUBLICDIR)
$(OSX)DM_SRCS += hw/uxen_v4v_osx.c
hw_uxen_v4v_osx.o: CPPFLAGS += -I$(XENPUBLICDIR)

QEMU_CFLAGS += -I$(TOPDIR)

$(OSX_NOT_YET)QEMU_SRCS += audio/audio.c
$(OSX_NOT_YET)QEMU_SRCS += audio/audio_win_int.c
$(OSX_NOT_YET)QEMU_SRCS += audio/mixeng.c
$(OSX_NOT_YET)QEMU_SRCS += audio/wavaudio.c
$(OSX_NOT_YET)QEMU_SRCS += audio/winwaveaudio.c
QEMU_SRCS += dma-helpers.c
QEMU_SRCS += hw/cdrom.c
QEMU_SRCS += hw/e1000.c
QEMU_SRCS += hw/e1000_babysitter.c
$(OSX_NOT_YET)QEMU_SRCS += hw/hda-audio.c
QEMU_SRCS += hw/irq.c
QEMU_SRCS += hw/ide/ahci.c
QEMU_SRCS += hw/ide/atapi.c
QEMU_SRCS += hw/ide/core.c
QEMU_SRCS += hw/ide/ich.c
QEMU_SRCS += hw/ide/pci.c
QEMU_SRCS += hw/ide/piix.c
QEMU_SRCS += hw/ide/qdev.c
QEMU_SRCS += hw/scsi-bus.c
QEMU_SRCS += hw/scsi-disk.c
$(OSX_NOT_YET)QEMU_SRCS += hw/intel-hda.c
QEMU_SRCS += hw/isa-bus.c
QEMU_SRCS += hw/pci.c
QEMU_SRCS += hw/pci_host.c
QEMU_SRCS += hw/pckbd.c
QEMU_SRCS += hw/piix_pci.c
QEMU_SRCS += hw/ps2.c
QEMU_SRCS += hw/qdev-properties.c
QEMU_SRCS += hw/serial.c
QEMU_SRCS += module.c
QEMU_SRCS += net.c
QEMU_SRCS += net/checksum.c
QEMU_SRCS += net/queue.c
QEMU_SRCS += net/util.c
QEMU_SRCS += qemu-sockets.c
$(CONFIG_MONITOR)QEMU_SRCS += readline.c
QEMU_SRCS += savevm.c

LIBELF_CPPFLAGS += -DNO_XEN_ELF_NOTE
LIBELF_CPPFLAGS += -I$(LIBELFDIR_include) -I$(XENDIR_include)
LIBELF_SRCS += libelf-loader.c
LIBELF_SRCS += libelf-tools.c

LZ4_CPPFLAGS += -I$(LZ4DIR_include)
LZ4_SRCS += lz4.c
LZ4_SRCS += lz4hc.c

CUCKOO_CPPFLAGS += -I$(CUCKOODIR_include)
CUCKOO_SRCS += fingerprint.c

NICKEL_CPPFLAGS += -I$(TOPDIR) -I$(TOPDIR)/dm/nickel
$(CONFIG_VBOXDRV)NICKEL_CPPFLAGS += -DCONFIG_VBOXDRV=1
$(CONFIG_NICKEL_THREADED)NICKEL_CPPFLAGS += -DNICKEL_THREADED=1
NICKEL_SRCS += access-control.c
NICKEL_SRCS += buff.c
NICKEL_SRCS += dhcp.c
NICKEL_SRCS += lava.c
NICKEL_SRCS += log.c
NICKEL_SRCS += nickel.c
NICKEL_SRCS += rpc.c
NICKEL_SRCS += service.c
NICKEL_SRCS += socket.c
NICKEL_SRCS += tcpip.c
NICKEL_SRCS += dns/dns.c
NICKEL_SRCS += dns/dns-fake.c
NICKEL_SRCS += http/auth-basic.c
NICKEL_SRCS += http/auth-challenge.c
$(WINDOWS)NICKEL_SRCS += http/sspi.c
$(OSX)NICKEL_SRCS += http/ntlm-osx.c
$(OSX)NICKEL_SRCS += http/cert-osx.c
$(WINDOWS)NICKEL_SRCS += http/cert-win32.c
NICKEL_SRCS += http/auth.c
NICKEL_SRCS += http/main.c
NICKEL_SRCS += http/ntlm.c
NICKEL_SRCS += http/proxy.c
NICKEL_SRCS += http/parser.c
NICKEL_SRCS += http/tls.c
NICKEL_SRCS += tcp-service.c
NICKEL_SRCS += udp-service.c

VBOXDRV_SRCS += server.c
VBOXDRV_SRCS += hgcm-simple.c
VBOXDRV_SRCS += shared-folders/filecrypt_helper.c
shared-folders/filecrypt_helper.o: CPPFLAGS += $(LIBFILECRYPT_CPPFLAGS)
shared-folders/filecrypt_helper.o: $(LIBFILECRYPT_DEPS)
VBOXDRV_SRCS += shared-folders/sf-server.c
VBOXDRV_SRCS += shared-folders/mappings.c
VBOXDRV_SRCS += shared-folders/mappings-opts.c
VBOXDRV_SRCS += shared-folders/sf-service.c
VBOXDRV_SRCS += shared-folders/shflhandle.c
VBOXDRV_SRCS += shared-folders/quota.c
VBOXDRV_SRCS += shared-folders/vbsf.c
VBOXDRV_SRCS += shared-clipboard/VBoxClipboard-win.c
VBOXDRV_SRCS += shared-clipboard/service.c
VBOXDRV_SRCS += shared-clipboard/server.c
VBOXDRV_SRCS += shared-clipboard/rpc.c
VBOXDRV_SRCS += shared-clipboard/clipboardformats.c
VBOXDRV_SRCS += shared-clipboard/uxen_bmp_convert.c
VBOXDRV_SRCS += shared-clipboard/policy.c
VBOXDRV_SRCS += rt/other.c
VBOXDRV_SRCS += rt/RTDir-generic.c
VBOXDRV_SRCS += rt/RTErrConvertFromWin32.c
VBOXDRV_SRCS += rt/dir-win.c
VBOXDRV_SRCS += rt/dir.c
VBOXDRV_SRCS += rt/fileio-win.c
VBOXDRV_SRCS += rt/fileio.c
VBOXDRV_SRCS += rt/fs-win.c
VBOXDRV_SRCS += rt/fs.c
VBOXDRV_SRCS += rt/path-win.c


LDLIBS += $(LIBVHD_LIBS)
LDLIBS += $(LIBUXENCTL_LIBS)
LDLIBS += $(LIBXC_LIBS)
LDLIBS += $(YAJL_LIBS)

$(OSX)LDLIBS += -lm -lz

$(WINDOWS)LDLIBS += -lwinmm -lws2_32 -lfltlib
$(WINDOWS)$(CONFIG_NICKEL)LDLIBS += -liphlpapi -ldnsapi -lcrypt32 -lwinhttp -lsecur32
$(WINDOWS)LDLIBS += -lole32
$(WINDOWS)LDLIBS += -ldxguid
$(WINDOWS)LDLIBS += -lgdi32
$(WINDOWS)LDLIBS += -lgdiplus
$(WINDOWS)$(CONFIG_FILECRYPT)LDLIBS += $(LIBFILECRYPT_LIBS)
$(WINDOWS)LDLIBS += $(LIBUXENCONSOLE_LIBS)

$(OSX)LDLIBS += -framework AppKit
$(OSX)LDLIBS += -framework Carbon
$(OSX)LDLIBS += -framework Security
$(OSX)LDLIBS += -framework IOKit
$(OSX)LDLIBS += -framework DiskArbitration

$(WINDOWS)LDFLAGS += -mwindows
$(WINDOWS)LDFLAGS += -Wl,--wrap,malloc,--wrap,realloc,--wrap,calloc,--wrap,free
$(WINDOWS)LDFLAGS += -Wl,--wrap,strdup,--wrap,strndup,--wrap,wcsdup,--wrap,wcsndup
$(OSX)LDFLAGS += -sectcreate __RESTRICT __restrict /dev/null

DM_OBJS = $(patsubst %.m,%.o,$(patsubst %.c,%.o,$(DM_SRCS)))
DM_OBJS := $(subst /,_,$(DM_OBJS))

QEMU_OBJS = $(patsubst %.m,%.o,$(patsubst %.c,%.o,$(QEMU_SRCS)))
QEMU_OBJS := $(subst /,_,$(patsubst %,qemu/%,$(QEMU_OBJS)))
DM_OBJS += $(QEMU_OBJS)

LIBELF_OBJS = $(patsubst %.m,%.o,$(patsubst %.c,%.o,$(LIBELF_SRCS)))
LIBELF_OBJS := $(subst /,_,$(patsubst %,libelf/%,$(LIBELF_OBJS)))
DM_OBJS += $(LIBELF_OBJS)

LZ4_OBJS = $(patsubst %.m,%.o,$(patsubst %.c,%.o,$(LZ4_SRCS)))
LZ4_OBJS := $(subst /,_,$(patsubst %,lz4/%,$(LZ4_OBJS)))
DM_OBJS += $(LZ4_OBJS)
lz4_lz4.o: CFLAGS_debug := $(subst -O0,-O2,$(CFLAGS_debug))

CUCKOO_OBJS = $(patsubst %.m,%.o,$(patsubst %.c,%.o,$(CUCKOO_SRCS)))
CUCKOO_OBJS := $(subst /,_,$(patsubst %,cuckoo/%,$(CUCKOO_OBJS)))
DM_OBJS += $(CUCKOO_OBJS)
cuckoo_fingerprint.o: CFLAGS_debug := $(subst -O0,-O2,$(CFLAGS_debug))

NICKEL_OBJS = $(patsubst %.m,%.o,$(patsubst %.c,%.o,$(NICKEL_SRCS)))
NICKEL_OBJS := $(subst /,_,$(patsubst %,nickel/%,$(NICKEL_OBJS)))
$(CONFIG_NICKEL)DM_OBJS += $(NICKEL_OBJS)

VBOXDRV_OBJS = $(patsubst %.m,%.o,$(patsubst %.c,%.o,$(VBOXDRV_SRCS)))
VBOXDRV_OBJS := $(subst /,_,$(patsubst %,vbox-drivers/%,$(VBOXDRV_OBJS)))
$(CONFIG_VBOXDRV)DM_OBJS += $(VBOXDRV_OBJS)

$(WINDOWS)DM_OBJS += uxendm-res.o

# stderr redirect is done from constructor -- this needs to be last
# in the object file list, apparently constructors are executed in
# reverse link order. win32-backtrace.o is here to setup uxen backtrace early
$(WINDOWS)DM_OBJS += win32-backtrace.o
$(WINDOWS)DM_OBJS += win32-logging.o

EXTRA_CFLAGS += -Wp,-MD,.deps/$(subst /,_,$@).d -Wp,-MT,$@

$(DM_OBJS): $(YAJL_DEPS) .deps/.exists

uxendm$(EXE_SUFFIX): $(LIBVHD_DEPS) $(LIBUXENCTL_DEPS) $(LIBXC_DEPS)
uxendm$(EXE_SUFFIX): $(DM_OBJS)
	$(_W)echo Linking - $@
	$(_V)$(call link,$@,$(DM_OBJS) $(LDLIBS))

%.o: %.c
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) $(DM_CFLAGS) -c $< -o $@

%.o: %.m
	$(_W)echo Compiling - $@
	$(_V)$(COMPILE.m) $(EXTRA_CFLAGS) $(DM_CFLAGS) -c $< -o $@

%.o : %.rc
	$(_W)echo Compiling - $@
	$(_V)$(WINDRES) $(WINDRESFLAGS) $(WINDRES_TARGET_FORMAT_OPTION) $< -o $@

block-swap_%.o: block-swap/%.c
	$(_W)echo Compiling - $(subst _,/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) $(DM_CFLAGS) -c $< -o $@

hw_%.o: hw/%.c
	$(_W)echo Compiling - $(subst hw_,hw/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) $(DM_CFLAGS) -c $< -o $@

$(LIBELF_OBJS): CFLAGS += $(LIBELF_CFLAGS)
$(LIBELF_OBJS): CPPFLAGS += $(LIBELF_CPPFLAGS)
libelf_%.o: $(LIBELFDIR)/%.c
	$(_W)echo Compiling - $(subst libelf_,libelf/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

$(LZ4_OBJS): CFLAGS += $(LZ4_CFLAGS)
$(LZ4_OBJS): CPPFLAGS += $(LZ4_CPPFLAGS)
lz4_%.o: $(LZ4DIR)/%.c
	$(_W)echo Compiling - $(subst lz4_,lz4/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

$(CUCKOO_OBJS): CFLAGS += $(CUCKOO_CFLAGS)
$(CUCKOO_OBJS): CPPFLAGS += $(CUCKOO_CPPFLAGS)
cuckoo_%.o: $(CUCKOODIR)/%.c
	$(_W)echo Compiling - $(subst cuckoo_,cuckoo/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

proxy_%.o: proxy/%.c
	$(_W)echo Compiling - $(subst proxy_,proxy/,$@)
	$(_V)$(COMPILE.c) -I$(TOPDIR) $(EXTRA_CFLAGS) -c $< -o $@

nickel_http-parser_%.o: $(NICKELDIR)/http-parser/%.c
	$(_W)echo Compiling - $(subst nickel_http-parser_,nickel/http-parser/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

$(NICKEL_OBJS): CFLAGS += $(NICKEL_CFLAGS)
$(NICKEL_OBJS): CPPFLAGS += $(NICKEL_CPPFLAGS)
nickel_%.o: $(NICKELDIR)/%.c
	$(_W)echo Compiling - $(subst nickel_,nickel/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

nickel_dns_%.o: $(NICKELDIR)/dns/%.c
	$(_W)echo Compiling - $(subst nickel_dns_,nickel/dns/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

nickel_http_%.o: $(NICKELDIR)/http/%.c
	$(_W)echo Compiling - $(subst nickel_http_,nickel/http/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

$(VBOXDRV_OBJS): CFLAGS += -I$(VBOXDRVDIR) -I$(VBOX_INCLUDES)/include
$(VBOXDRV_OBJS): CFLAGS += -I$(VBOX_INCLUDES)/src/VBox/Runtime/include
$(VBOXDRV_OBJS): CFLAGS += -I$(TOPDIR)/vm-support/windows/uxensf/driver
$(VBOXDRV_OBJS): CFLAGS += -I$(TOPDIR)/vm-support/windows/uxenclipboard
$(VBOXDRV_OBJS): CFLAGS += -I$(TOPDIR)/dm
$(VBOXDRV_OBJS): CFLAGS += -I$(TOPDIR)
$(VBOXDRV_OBJS): CFLAGS += -I$(FILECRYPT_INCLUDES)
$(VBOXDRV_OBJS): CFLAGS += -DVBOX -DIN_RING3 -DVBOX_WITH_HGCM
$(VBOXDRV_OBJS): CFLAGS += -DVBOX_WITH_64_BITS_GUESTS -DARCH_BITS=64
$(VBOXDRV_OBJS): CFLAGS += -DRT_OS_WINDOWS -DLOG_ENABLED -DLOG_USE_C99
vbox-drivers_shared-folders_mappings.o: CFLAGS += -std=c99
vbox-drivers_shared-folders_vbsf.o: CFLAGS += -std=c99
vbox-drivers_shared-clipboard_rpc.o: CFLAGS += -I$(TOPDIR)/dm
vbox-drivers_%.o: $(VBOXDRVDIR)/%.c
	$(_W)echo Compiling - $(subst vbox-drivers_,vbox-drivers/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

vbox-drivers_rt_%.o: $(VBOXDRVDIR)/rt/%.c
	$(_W)echo Compiling - $(subst vbox-drivers_rt_,vbox-drivers/rt/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

vbox-drivers_shared-folders_%.o: $(VBOXDRVDIR)/shared-folders/%.c
	$(_W)echo Compiling - $(subst vbox-drivers_shared-folders_,vbox-drivers/shared-folders/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

vbox-drivers_shared-clipboard_%.o: $(VBOXDRVDIR)/shared-clipboard/%.c
	$(_W)echo Compiling - $(subst vbox-drivers_shared-clipboard_,vbox-drivers/shared-clipboard/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

$(QEMU_OBJS): CFLAGS += $(QEMU_CFLAGS)
$(QEMU_OBJS): CPPFLAGS += $(QEMU_CPPFLAGS)
qemu_%.o: $(QEMUDIR)/%.c
	$(_W)echo Compiling - $(subst qemu_,qemu/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

qemu_audio_%.o: $(QEMUDIR)/audio/%.c
	$(_W)echo Compiling - $(subst qemu_audio_,qemu/audio/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

qemu_hw_%.o: $(QEMUDIR)/hw/%.c
	$(_W)echo Compiling - $(subst qemu_hw_,qemu/hw/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

qemu_hw_ide_%.o: $(QEMUDIR)/hw/ide/%.c
	$(_W)echo Compiling - $(subst qemu_hw_ide_,qemu/hw/ide/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@

qemu_net_%.o: $(QEMUDIR)/net/%.c
	$(_W)echo Compiling - $(subst qemu_net_,qemu/net/,$@)
	$(_V)$(COMPILE.c) $(EXTRA_CFLAGS) -c $< -o $@


$(DISTDIR)/uxendm$(EXE_SUFFIX): uxendm$(EXE_SUFFIX)
	$(_W)echo Installing from $(abspath $(<D)) to $(DISTDIR)
	$(_W)echo Installing -- $(<F)
	$(_V)$(call install_exe,$<,$(DISTDIR))

check-build_info.h build_info.h:
	$(_W)echo Checking - source tree version info
	$(_V)( [ -e $(subst check-,,$@) ] && \
	       grep -q \
	         "\""$$(cd $(SRCROOT) && git log --pretty=format:%H -n 1)"\"" \
	         $(subst check-,,$@) ) || \
	     ( echo "#define UXEN_DM_CHANGESET \""$$(cd $(SRCROOT) && \
	         git log --pretty=format:%H -n 1 && git diff --quiet || \
	         echo -dirty)"\""; \
	       echo "#define UXEN_DM_BUILDDATE \""$$(LC_ALL=C date)"\""; \
	   ) >$(subst check-,,$@)


SDK_src_files = dict.c dict.h dict-rpc.c dict-rpc.h lib.c lib.h queue.h yajl.h
$(OSX)SDK_src_files += clock.h
$(OSX)SDK_src_files += compiler.h
$(OSX)SDK_src_files += config.h
$(OSX)SDK_src_files += debug.c
$(OSX)SDK_src_files += debug.h
$(OSX)SDK_src_files += ioh.h
$(OSX)SDK_src_files += os.h
$(OSX)SDK_src_files += osx.c
$(OSX)SDK_src_files += osx.h
$(OSX)SDK_src_files += typedef.h
SDK_src_files := $(patsubst %,$(SDKDIR_src)/dict/%,$(SDK_src_files))

dist: $(SDK_src_files)
$(SDK_src_files): $(SDKDIR_src)/dict/% : % $(SDKDIR_src)/dict/.exists
	$(_W)echo Installing from $(abspath $(<D)) to $(SDKDIR_src)/dict
	$(_W)echo Installing -- $(notdir $(SDK_src_files))
	$(_V)$(call install_data,$(patsubst %,$(<D)/%,$(notdir $(SDK_src_files))),$(SDKDIR_src)/dict)
	$(_V)touch $(SDKDIR_src)/dict/config.h


-include .deps/*.d

.PHONY: src-files
src-files:
	@ls $(patsubst %,$(SRCROOT)/%,$(DM_SRCS))
# $(patsubst %,$(LIBELFDIR)/%,$(LIBELF_SRCS)) $(patsubst %,$(LIBXCDIR)/%,$(LIBXC_SRCS)) $(patsubst %,$(UXENCTLDIR)/%,$(UXENCTL_SRCS))

src-files-qemu:
	@ls $(patsubst %,$(QEMUDIR)/%,$(QEMU_SRCS))

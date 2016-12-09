
SUBDIR_XEN := $(subst $(abspath $(XEN_ROOT))/,,$(abspath $(SRCDIR)))

HOSTCC ?= cc
HOSTCFLAGS ?= $(CFLAGS)

XEN_TARGET_ARCH  ?= x86_$(TARGET_HOST_BITS)
TARGET_ARCH      ?= x86

X86_32_only := $(if $(filter x86_32,$(XEN_TARGET_ARCH)),,not-)
X86_64_only := $(if $(filter x86_64,$(XEN_TARGET_ARCH)),,not-)
X86_64_elf_only := $(X86_64_only)
X86_64_pe_only := $(X86_64_only)

ifeq ($(UXEN_TARGET_FORMAT),elf)
TARGET_CC := $(XEN_TARGET_ARCH)-elf-gcc
TARGET_NM := $(XEN_TARGET_ARCH)-elf-nm
TARGET_LD := $(XEN_TARGET_ARCH)-elf-ld
TARGET_OBJCOPY := $(XEN_TARGET_ARCH)-elf-objcopy
TARGET_STRIP := $(XEN_TARGET_ARCH)-elf-strip
X86_64_pe_only := not-
TARGET_pe_only := not-
TARGET_elf_only :=
UXEN_TARGET_ABI ?= sysv
else ifeq ($(UXEN_TARGET_FORMAT),pe)
TARGET_CC = x86_64-w64-mingw32-long-gcc
TARGET_NM = x86_64-w64-mingw32-long-nm
TARGET_LD = x86_64-w64-mingw32-long-ld
TARGET_OBJCOPY = x86_64-w64-mingw32-long-objcopy
TARGET_STRIP = x86_64-w64-mingw32-long-strip
X86_64_elf_only := not-
TARGET_elf_only := not-
TARGET_pe_only :=
UXEN_TARGET_ABI ?= ms
else
$(error UXEN_TARGET_FORMAT $(UXEN_TARGET_FORMAT) not supported)
endif

ifeq ($(UXEN_TARGET_ABI),sysv)
TARGET_sysvabi_only := 
TARGET_msabi_only := not-
else ifeq ($(UXEN_TARGET_ABI),ms)
TARGET_sysvabi_only := not-
TARGET_msabi_only :=
else
$(error UXEN_TARGET_ABI $(UXEN_TARGET_ABI) not supported)
endif

ifeq ($(TARGET_HOST),windows)
TARGET_windows_only :=
TARGET_osx_only := not-
else ifeq ($(TARGET_HOST),osx)
TARGET_windows_only := not-
TARGET_osx_only :=
else
$(error invalid TARGET_HOST)
endif

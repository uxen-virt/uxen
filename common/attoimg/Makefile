#
# Copyright 2019, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

MAJOR    = 1.0
MINOR    = 0

ATTOIMG_SRCS-y       :=
ATTOIMG_SRCS-y       += libelf-loader.c libelf-tools.c
ATTOIMG_SRCS-y       += util.c mptables.c attoimg.c

ATTOIMG_TOOL_SRCS-y :=
ATTOIMG_TOOL_SRCS-y += main.c

CFLAGS += -I../../common
CFLAGS += -I../../common/include/xen-public

CFLAGS   += -Werror
CFLAGS   += -I.
ATTOIMG_LIB_OBJS := $(patsubst %.c,%.o,$(ATTOIMG_SRCS-y))

ATTOIMG_TOOL_OBJS := $(patsubst %.c,%.o,$(ATTOIMG_TOOL_SRCS-y))

LIB := libattoimg.a

.PHONY: all
all: build

build: libs tool

libs: $(LIB)

clean:
	rm -rf *.rpm $(LIB) *~ $(DEPS) \
            $(ATTOIMG_LIB_OBJS) $(ATTOIMG_TOOL_OBJS) attoimg

libattoimg.a: $(ATTOIMG_LIB_OBJS)
	$(AR) rc $@ $^

tool: $(ATTOIMG_TOOL_OBJS) libattoimg.a
	$(CC) $(LDFLAGS) -o attoimg $^ -L . -lattoimg

-include $(DEPS)


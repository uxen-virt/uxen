#
# Copyright 2016-2019, Bromium, Inc.
# Author: Paulian Marinca <paulian@marinca.net>
# SPDX-License-Identifier: ISC
#

CC ?= gcc

SRC = atto-wm.o

EXTRA_LIBS = -lX11

EXTRA_LDFLAGS = -L/usr/X11R6/lib
EXTRA_CFLAGS = -O2 -g -Wall -I/usr/X11R6/include

#DEBUG = -DDEBUG

all: atto-wm

atto-wm: $(SRC)
	$(CC) $(SRC) -o $@ $(EXTRA_CFLAGS) $(EXTRA_LDFLAGS) $(EXTRA_LIBS)

%.o : %.c
	$(CC) -c $(EXTRA_CFLAGS) $(DEBUG) $< -o $@

clean :
	rm -f *.o atto-wm

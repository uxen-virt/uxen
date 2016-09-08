#
# Copyright 2016, Bromium, Inc.
# Author: Paulian Marinca <paulian@marinca.net>
# SPDX-License-Identifier: ISC
#

CC = gcc

SRC = atto-wm.o

LIBS = -lX11

LDFLAGS = -L/usr/X11R6/lib
CFLAGS = -O2 -g -Wall -I/usr/X11R6/include

#DEBUG = -DDEBUG

all: atto-wm

atto-wm: $(SRC)
	gcc $(SRC) -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(DEBUG) $< -o $@

clean :
	rm -f *.o atto-wm

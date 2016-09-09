#
# Copyright 2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

CC ?= gcc

SRC = atto-agent.o

EXTRA_CFLAGS = -O2 -g -Wall -I../include -I../include/uxen

DEBUG = -DDEBUG

all: atto-agent

atto-agent: $(SRC)
	$(CC) $(SRC) -o $@ $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) $(LIBS)

%.o : %.c
	$(CC) -c $(EXTRA_CFLAGS) $(DEBUG) $< -o $@

clean :
	rm -f *.o atto-agent

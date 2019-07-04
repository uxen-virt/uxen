#
# Copyright 2016-2019, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

CC ?= gcc

SRC = atto-agent.o keyboard.c

EXTRA_CFLAGS = -O2 -g -Wall -I../include -I../include/uxen -I$(ATTOXEN_API_INC)

DEBUG = -DDEBUG

all: atto-agent

atto-agent: $(SRC)
	$(CC) $(SRC) -o $@ $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) $(LIBS)

%.o : %.c
	$(CC) -c $(EXTRA_CFLAGS) $(DEBUG) $< -o $@

clean :
	rm -f *.o atto-agent

#
# Copyright 2016, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

CC = gcc

SRC = atto-agent.o

CFLAGS = -O2 -g -Wall -I../include -I../include/uxen

DEBUG = -DDEBUG

all: atto-agent

atto-agent: $(SRC)
	gcc $(SRC) -o $@ $(CFLAGS) $(LDFLAGS) $(LIBS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(DEBUG) $< -o $@

clean :
	rm -f *.o atto-agent

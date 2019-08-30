#
# Copyright 2016-2019, Bromium, Inc.
# SPDX-License-Identifier: ISC
#

CC ?= gcc

SRC = atto-agent.o keyboard.c headctl.c
LIBS = -lX11

EXTRA_CFLAGS = -O2 -g -Wall -I../include -I../include/uxen -I$(ATTOXEN_API_INC) -I$(STAGING_INC) -L$(STAGING_LIB)
EXTRA_CFLAGS += -DDEFAULT_USER_NAME="\"$(ATTOVM_USERS_NORMAL_ACCOUNT)\""
EXTRA_CFLAGS += -DDEFAULT_VT="\"$(ATTOVM_USERS_AUTO_LOGIN_TTY)\""

DEBUG = -DDEBUG

all: atto-agent

atto-agent: $(SRC)
	$(CC) $(SRC) -o $@ $(CFLAGS) $(EXTRA_CFLAGS) $(LDFLAGS) $(LIBS)

%.o : %.c
	$(CC) -c $(EXTRA_CFLAGS) $(DEBUG) $< -o $@

clean :
	rm -f *.o atto-agent

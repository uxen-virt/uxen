/*
 *  uxendmctl.c
 *  uxen
 *
 * Copyright 2012-2015, Bromium, Inc.
 * Author: Christian Limpach <Christian.Limpach@gmail.com>
 * SPDX-License-Identifier: ISC
 *
 */

#define ERR_WINDOWS
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/stat.h>

DECLARE_PROGNAME;

#define BUFSIZE 255

HANDLE hin;
DWORD hinmode;

void
reset_term(void)
{
    if (hinmode)
	SetConsoleMode(hin, hinmode);
    else
	system("stty cooked echo");
}

void
usage(const char *progname)
{
    fprintf(stderr, "usage: %s [-h]"
	    "\n", progname);
    exit(1);
}

int
main(int argc, char **argv)
{
    int ret;
    DWORD nin, nout;
    HANDLE h[2] = { NULL, };
    HANDLE hout, hpipe = INVALID_HANDLE_VALUE;
    OVERLAPPED opipe;
    char buf[BUFSIZE], pipebuf[BUFSIZE];
    char *pipename = NULL;
    int server_mode;
    int i;

    setprogname(argv[0]);

    while (1) {
	int c, index = 0;
	static struct option long_options[] = {
	    {"help",          no_argument,       NULL, 'h'},
	    {"pipe",          required_argument, NULL, 'p'},
	    {"server",        no_argument,       NULL, 's'},
	    {NULL,   0,                 NULL, 0}
	};

	c = getopt_long(argc, argv, "hp:s", long_options, &index);
	if (c == -1)
	    break;

	switch (c) {
	case 'h':
	    usage(argv[0]);
	    /* NOTREACHED */
	case 'p':
	    pipename = optarg;
	    break;
	case 's':
	    server_mode = 1;
	    break;
	}
    }

    hout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hout == INVALID_HANDLE_VALUE)
	Werr(1, "GetStdHandle(STD_OUTPUT_HANDLE)");

    hin = GetStdHandle(STD_INPUT_HANDLE);
    if (hin == INVALID_HANDLE_VALUE)
	Werr(1, "GetStdHandle(STD_INPUT_HANDLE)");

    if (GetConsoleMode(hin, &hinmode)) {
	if (! SetConsoleMode(hin, hinmode &
			     ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)))
	    Werr(1, "SetConsoleMode(STD_INPUT_HANDLE,)");
	GetConsoleMode(hin, &nin);
	printf("console mode %ld\n", nin);
    } else {
	Werr(1, "GetConsoleMode(STD_INPUT_HANDLE,)");
	/* non-windows terminal -- broken :-( */
	hinmode = 0;
	system("stty raw -echo");
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
    }

    atexit(reset_term);

    if (pipename) {
	printf("pipe name: %s\n", pipename);
	if (server_mode) {
#define NSENDBUF 2048
#define NRECVBUF 2048
#define MAXCONNECT 1
#define NTIMEOUT 5000
	    hpipe = CreateNamedPipe(pipename,
				    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
				    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
				    PIPE_WAIT,
				    MAXCONNECT, NSENDBUF, NRECVBUF, NTIMEOUT,
				    NULL);
	    if (hpipe == INVALID_HANDLE_VALUE)
		Werr(1, "CreateNamedPipe(%s)", pipename);
	    ret = ConnectNamedPipe(hpipe, NULL);
	    if (!ret)
		Werr(1, "ConnectNamedPipe()");
	} else {
	    while (1) {
		hpipe = CreateFile(pipename, GENERIC_READ | GENERIC_WRITE,
				   0, NULL, OPEN_EXISTING,
				   FILE_FLAG_OVERLAPPED, NULL);
		if (hpipe != INVALID_HANDLE_VALUE)
		    break;
		if (/* GetLastError() != ERROR_FILE_NOT_FOUND && */
		    GetLastError() != ERROR_PIPE_BUSY)
		    Werr(1, "CreateFile(%s) %d", pipename, GetLastError());
		WaitNamedPipe(pipename, 1000); /* wait for 1s */
	    }
	}
	printf("connected\n");
	h[1] = CreateEvent(NULL, TRUE, FALSE, NULL);
	ZeroMemory(&opipe, sizeof(opipe));
	opipe.hEvent = h[1];
	ret = ReadFile(hpipe, pipebuf, sizeof(pipebuf), NULL, &opipe);
	if (!ret && GetLastError() != ERROR_IO_PENDING)
	    Werr(1, "ReadFile(hpipe)");
    }

    if (!h[1])
	errx(1, "no pipe or socket to connect to");

    h[0] = hin;

    while (1) {
	ret = WaitForMultipleObjectsEx(2, h, FALSE, INFINITE, TRUE);
	if (ret == WAIT_OBJECT_0) {
	    if (hinmode) {
		INPUT_RECORD r[BUFSIZE];
		ReadConsoleInput(h[0], r, BUFSIZE, &nin);
		nout = 0;
		for (i = 0; i < nin; i++) {
		    if (r[i].EventType == KEY_EVENT &&
			r[i].Event.KeyEvent.bKeyDown &&
			r[i].Event.KeyEvent.uChar.AsciiChar) {
			if (r[i].Event.KeyEvent.uChar.AsciiChar == '\r')
			    buf[nout++] = '\n';
			else
			    buf[nout++] = r[i].Event.KeyEvent.uChar.AsciiChar;
		    }
		}
		nin = nout;
	    } else {
		if (! ReadFile(h[0], buf, sizeof(buf), &nin, NULL))
		    break;
	    }
	    if (nin) {
		if (buf[0] == 3 /* || buf[0] == 4 */)
		    break;
		if (! WriteFile(hpipe, buf, nin, &nout, NULL))
		    break;
		if (! WriteFile(hout, buf, nin, &nout, NULL))
		    break;
	    }
	} else if (ret == WAIT_OBJECT_0 + 1) {
	    if (! GetOverlappedResult(hpipe, &opipe, &nin, TRUE))
		break;
	    if (! WriteFile(hout, pipebuf, nin, &nout, NULL))
		break;
	    ZeroMemory(&opipe, sizeof(opipe));
	    opipe.hEvent = h[1];
	    ret = ReadFile(hpipe, pipebuf, sizeof(pipebuf), NULL, &opipe);
	    if (!ret && GetLastError() != ERROR_IO_PENDING)
		Werr(1, "ReadFile(hpipe)");
	} else
	    break;
    }

    ret = 0;
// exit:
    return ret;
}

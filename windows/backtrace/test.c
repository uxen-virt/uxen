/*
 * Copyright 2013-2015, Bromium, Inc.
 * SPDX-License-Identifier: ISC
 */

#include <windows.h>

static void
foo()
{
	int *f = NULL;
	*f = 0;
}

static void
bar()
{
	foo();
}

int
main()
{
	LoadLibraryA("uxen-backtrace.dll");
	bar();

	return 0;
}

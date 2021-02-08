/*
 * shared library object that can be used to make grand children execute
 * in the original namespace
 *
 *   Copyright (C) 2021 Olaf Kirch <okir@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <dlfcn.h>



#define GLIBC_PATH		"/lib64/libc.so.6"

static void *			glibc_handle = NULL;

static void *
glibc_symbol(const char *name)
{
	void *sym;

	if (glibc_handle == NULL) {
		glibc_handle = dlopen(GLIBC_PATH, RTLD_LAZY | RTLD_GLOBAL);
		if (glibc_handle == NULL) {
			fprintf(stderr, "dlopen(%s) failed: %m\n", GLIBC_PATH);
			exit(66);
		}
	}

	sym = dlsym(glibc_handle, name);
	if (sym == NULL) {
		fprintf(stderr, "dlsym(%s) failed: %m\n", name);
		exit(66);
	}

	return sym;
}

int
fork(void)
{
	static int (*real_fork)() = NULL;

	if (real_fork == NULL)
		real_fork = glibc_symbol("fork");

	return real_fork();
}


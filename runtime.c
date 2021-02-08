/*
 * container runtime shim for wormhole
 *
 *   Copyright (C) 2020-2021 Olaf Kirch <okir@suse.de>
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

#include "profiles.h"
#include "runtime.h"
#include "tracing.h"
#include "util.h"

extern struct wormhole_container_runtime	wormhole_runtime_podman;
static struct wormhole_container_runtime *	wormhole_runtime;

static struct wormhole_container_runtime *
__wormhole_get_runtime(const char *name)
{
	if (name == NULL || !strcmp(name, "default"))
		return &wormhole_runtime_podman;

	if (!strcmp(name, "podman"))
		return &wormhole_runtime_podman;

	return NULL;
}

bool
wormhole_select_runtime(const char *name)
{
	struct wormhole_container_runtime *rt;

	rt = __wormhole_get_runtime(name);
	if (rt == NULL) {
		log_error("Unknown container runtime \"%s\"", name);
		return false;
	}

	wormhole_runtime = rt;
	return true;

}

bool
wormhole_container_exists(const char *name)
{
	return wormhole_runtime->container_exists(name);
}

bool
wormhole_container_start(const char *image_spec, const char *container_name)
{
	return wormhole_runtime->container_start(image_spec, container_name);
}

const char *
wormhole_container_mount(const char *container_name)
{
	return wormhole_runtime->container_mount(container_name);
}

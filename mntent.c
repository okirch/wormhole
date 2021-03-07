/*
 * Inspect /proc/mounts
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
#include <mntent.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "tracing.h"
#include "environment.h"
#include "util.h"

static wormhole_tree_state_t *
__wormhole_get_mount_state(const char *mtab, const char *root_dir)
{
	wormhole_tree_state_t *tree;
	FILE *mf;
	struct mntent *m;
	char root_path_buf[PATH_MAX];

	if (mtab == NULL)
		mtab = "/proc/mounts";

	if (root_dir) {
		const char *resolved_root;

		resolved_root = realpath(root_dir, root_path_buf);
		if (resolved_root == NULL) {
			log_error("realname(%s) failed: %m", root_dir);
			return NULL;
		}

		root_dir = resolved_root;
	}

	if ((mf = setmntent(mtab, "r")) == NULL) {
		log_error("Unable to open %s: %m", mtab);
		return NULL;
	}

	tree = wormhole_tree_state_new();

	while ((m = getmntent(mf)) != NULL) {
		const char *mount_point = m->mnt_dir;

		if (root_dir) {
			const char *relative_path;

			relative_path = fsutil_strip_path_prefix(mount_point, root_dir);
			if (relative_path == NULL) {
				trace("%s is not below %s", m->mnt_dir, root_dir);
				continue;
			}
			mount_point = relative_path;
		}
		wormhole_tree_state_set_system_mount(tree, mount_point, m->mnt_type, m->mnt_fsname);
	}

	endmntent(mf);

	return tree;
}

wormhole_tree_state_t *
wormhole_get_mount_state(const char *mtab)
{
	return __wormhole_get_mount_state(mtab, NULL);
}

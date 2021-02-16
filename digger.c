/*
 * wormhole digger
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
#include <limits.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>

#include "tracing.h"
#include "wormhole.h"
#include "profiles.h"
#include "config.h"
#include "util.h"
#include "buffer.h"

enum {
	OPT_BASE_ENVIRONMENT,
	OPT_OVERLAY_ROOT,
	OPT_PRIVILEGED_NAMESPACE,
};

struct option wormhole_options[] = {
	{ "debug",		no_argument,		NULL,	'd' },
	{ "base-environment",	required_argument,	NULL,	OPT_BASE_ENVIRONMENT },
	{ "overlay-root",	required_argument,	NULL,	OPT_OVERLAY_ROOT },
	{ "privileged-namespace", no_argument,		NULL,	OPT_PRIVILEGED_NAMESPACE },
	{ NULL }
};

const char *		opt_config_path = NULL;
const char *		opt_base_environment = NULL;
const char *		opt_overlay_root = NULL;
bool			opt_privileged_namespace = false;

static int		wormhole_digger(int argc, char **argv);

int
main(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv, "d", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'd':
			tracing_increment_level();
			break;

		case OPT_BASE_ENVIRONMENT:
			opt_base_environment = optarg;
			break;

		case OPT_OVERLAY_ROOT:
			opt_overlay_root = optarg;
			break;

		case OPT_PRIVILEGED_NAMESPACE:
			opt_privileged_namespace = true;
			break;

		default:
			log_error("Usage message goes here.");
			return 2;
		}
	}

	wormhole_common_load_config(opt_config_path);

	return wormhole_digger(argc - optind, argv + optind);
}

struct wormhole_digger_config {
	char **		argv;
};

static bool
wormhole_digger_setup_environment(struct wormhole_digger_config *cb)
{
	const char *command;

	/* Unshare the namespace so that any nonsense that happens in the subprocess we spawns
	 * stays local to that execution context.
	 * This should not be needed here any longer.
	 */
	if (geteuid() == 0 && !wormhole_create_namespace())
		return false;

	(void) chdir("/");

	setenv("PS1", "(wormhole) # ", 1);

	/* Caveat:
	 * There's a glitch in devpts that causes isatty() to fail inside the container,
	 * at least for pty slaves that were opened outside the environment.
	 *  readlink("/proc/self/fd/0", "/dev/pts/15", 4095) = 11
	 *  stat("/dev/pts/15", <ptr>) = -1 ENOENT (No such file or directory)
	 * This either needs to get fixed in the kernel, or we need to work around
	 * this by opening a pty pair here, and copy data inbetween _our_ tty and
	 * the slave tty.
	 */

	command = cb->argv[0];
	execvp(command, cb->argv);

	log_error("Unable to execute %s: %m", command);
	return false;
}

static inline bool
__init_working_dir(const char *parent_dir, const char *name, char *path_buf, size_t path_size)
{
	snprintf(path_buf, path_size, "%s/%s", parent_dir, name);
	if (!fsutil_makedirs(path_buf, 0755)) {
		log_error("Cannot create directory %s: %m", path_buf);
		return false;
	}

	return true;
}

static inline bool
__init_working_dir3(const char *parent_dir, const char *middle, const char *name, char *path_buf, size_t path_size)
{
	snprintf(path_buf, path_size, "%s/%s/%s", parent_dir, middle, name);
	if (!fsutil_makedirs(path_buf, 0755)) {
		log_error("Cannot create directory %s: %m", path_buf);
		return false;
	}

	return true;
}

static inline void
__remount(const char *new_root, const char *mp)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s%s", new_root, mp);
	if (!fsutil_mount_bind(mp, path, true))
		log_fatal("Failed to set up mount tree");
}

static bool
__string_in_list(const char *needle, const char **haystack)
{
	const char *straw;

	while ((straw = *haystack++) != NULL) {
		if (!strcmp(needle, straw))
			return true;
	}
	return false;
}

static bool
remount_filesystems(wormhole_tree_state_t *mnt_tree, const char *overlay_dir, const char *root_dir)
{
	/* We should use a better heuristic to identify these types of file systems. */
	static const char *virtual_filesystems[] = {
		"bpf",
		"cgroup",
		"cgroup2",
		"debugfs",
		"devpts",
		"devtmpfs",
		"efivarfs",
		"hugetlbfs",
		"mqueue",
		"proc",
		"pstore",
		"securityfs",
		"sysfs",
		"tmpfs",

		NULL
	};
	static const char *no_overlay_filesystems[] = {
		"fat",
		"vfat",

		NULL
	};

	wormhole_tree_walker_t *walk;
	wormhole_path_state_t *ps;
	const char *mount_point;


	walk = wormhole_tree_walk(mnt_tree);
	while ((ps = wormhole_tree_walk_next(walk, &mount_point)) != NULL) {
		const char *fstype;

		if (ps->state != WORMHOLE_PATH_STATE_SYSTEM_MOUNT)
			continue; /* should not happen */

		if (!strcmp(mount_point, "/")) {
			trace("Got root");
			continue;
		}

		fstype = ps->system_mount.type;

		if (__string_in_list(fstype, virtual_filesystems)) {
			trace("Just try to bind mount %s", mount_point);
			__remount(root_dir, mount_point);
			wormhole_tree_walk_skip_children(walk);
		} else if (__string_in_list(fstype, no_overlay_filesystems)) {
			trace("Ignoring %s, file system type %s does not support overlays", mount_point, fstype);
		} else if (fsutil_check_path_prefix(overlay_dir, mount_point)) {
			trace("Ignoring %s, because it's a parent directory of our overlay directory", mount_point);
		} else {
			char upper_dir[PATH_MAX], work_dir[PATH_MAX], dest_dir[PATH_MAX];

			trace("Trying to overlay %s %s (originally from %s)", mount_point, fstype, ps->system_mount.device);
			if (!__init_working_dir3(overlay_dir, "tree", mount_point, upper_dir, sizeof(upper_dir)))
				return false;

			if (!__init_working_dir3(overlay_dir, "work2", mount_point, work_dir, sizeof(work_dir)))
				return false;

			snprintf(dest_dir, sizeof(dest_dir), "%s%s", root_dir, mount_point);

			if (!fsutil_mount_overlay(mount_point, upper_dir, work_dir, dest_dir))
				return false;
		}
	}

	wormhole_tree_walk_end(walk);
	return true;
}

bool
smoke_and_mirrors(const char *overlay_dir)
{
	char lower_dir[PATH_MAX], upper_dir[PATH_MAX], work_dir[PATH_MAX], root_dir[PATH_MAX];
	wormhole_tree_state_t *mnt_tree;

	mnt_tree = wormhole_get_mount_state(NULL);

	if (!__init_working_dir(overlay_dir, "lower", lower_dir, sizeof(lower_dir))
	 || !__init_working_dir(overlay_dir, "tree", upper_dir, sizeof(upper_dir))
	 || !__init_working_dir(overlay_dir, "work", work_dir, sizeof(work_dir))
	 || !__init_working_dir(overlay_dir, "root", root_dir, sizeof(root_dir)))
		return false;

	/* User namespaces are a bit weird. This is the only way I got this to work. */
	if (!fsutil_mount_bind("/", lower_dir, true))
		return false;

	if (!fsutil_mount_overlay(lower_dir, upper_dir, work_dir, root_dir))
		return false;

	if (!remount_filesystems(mnt_tree, overlay_dir, root_dir)) {
		log_error("Failed to set up file system hierarchy");
		return false;
	}

	if (chroot(root_dir) < 0) {
		log_error("Unable to chroot to %s: %m", root_dir);
		return false;
	}

	wormhole_tree_state_free(mnt_tree);

	chdir("/");
	return true;
}

int
wormhole_digger(int argc, char **argv)
{
	struct wormhole_digger_config closure;
	char *shell_argv[] = { "/bin/bash", NULL };

	memset(&closure, 0, sizeof(closure));
	if (argc != 0) {
		closure.argv = argv;
	} else {
		shell_argv[0] = getenv("SHELL");
		if (shell_argv[0] == NULL)
			shell_argv[0] = "/bin/sh";
		closure.argv = shell_argv;
	}

	if (opt_overlay_root == NULL) {
		log_error("Please specify a root directory via --overlay-root");
		return false;
	}

	if (!fsutil_makedirs(opt_overlay_root, 0755))
		log_fatal("Unable to create overlay root at %s", opt_overlay_root);

	if (opt_privileged_namespace) {
		if (!wormhole_create_namespace())
			log_fatal("Unable to set up privileged namespace");
	} else {
		if (!wormhole_create_user_namespace())
			log_fatal("Unable to set up user namespace");
	}

	if (!fsutil_make_fs_private("/"))
		log_fatal("Unable to change file system root to private (no propagation)");

	if (opt_base_environment != 0) {
		/* Set up base environment */
		/* wormhole_client_namespace_request(opt_base_environment, wormhole_namespace_response_callback, &closure); */
	}

	if (!smoke_and_mirrors(opt_overlay_root))
		log_fatal("unable to set up transparent overlay");

	wormhole_digger_setup_environment(&closure);
	return 0;
}

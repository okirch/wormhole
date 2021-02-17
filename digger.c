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
	OPT_CLEAN,
};

struct option wormhole_options[] = {
	{ "debug",		no_argument,		NULL,	'd' },
	{ "base-environment",	required_argument,	NULL,	OPT_BASE_ENVIRONMENT },
	{ "overlay-root",	required_argument,	NULL,	OPT_OVERLAY_ROOT },
	{ "privileged-namespace", no_argument,		NULL,	OPT_PRIVILEGED_NAMESPACE },
	{ "clean",		no_argument,		NULL,	OPT_CLEAN },
	{ NULL }
};

const char *		opt_config_path = NULL;
const char *		opt_base_environment = NULL;
const char *		opt_overlay_root = NULL;
bool			opt_privileged_namespace = false;
bool			opt_clean = false;

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

		case OPT_CLEAN:
			opt_clean = true;
			break;

		default:
			log_error("Usage message goes here.");
			return 2;
		}
	}

	wormhole_common_load_config(opt_config_path);

	return wormhole_digger(argc - optind, argv + optind);
}

static bool
wormhole_digger_build(char **argv, const char *root_dir)
{
	int status;

	/* Unshare the namespace so that any nonsense that happens in the subprocess we spawns
	 * stays local to that execution context.
	 * This should not be needed here any longer.
	 */
	if (geteuid() == 0 && !wormhole_create_namespace())
		return false;

	(void) chdir("/");

	setenv("PS1", "(wormhole) # ", 1);

	/* FIXME: should we put all our subprocess into a cgroup that we can kill
	 * once we're done? */

	/* Caveat:
	 * There's a glitch in devpts that causes isatty() to fail inside the container,
	 * at least for pty slaves that were opened outside the environment.
	 *  readlink("/proc/self/fd/0", "/dev/pts/15", 4095) = 11
	 *  stat("/dev/pts/15", <ptr>) = -1 ENOENT (No such file or directory)
	 * This either needs to get fixed in the kernel, or we need to work around
	 * this by opening a pty pair here, and copy data inbetween _our_ tty and
	 * the slave tty.
	 */

	if (!wormhole_run_command_argv(argv, root_dir, &status))
		return false;

	if (!wormhole_child_status_okay(status)) {
		log_error("Command \"%s\" failed: %s", argv[0], wormhole_child_status_describe(status));
		return false;
	}

	trace("Command %s completed", argv[0]);
	return true;
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

static bool
__remount_filesystems(wormhole_tree_state_t *mnt_tree, const char *overlay_dir, const char *root_dir,
			wormhole_tree_state_t *assembled_tree)
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
		"nfs",	/* not working very well either */

		NULL
	};

	wormhole_tree_walker_t *walk;
	wormhole_path_state_t *ps;
	const char *mount_point;
	unsigned int mount_index = 0;

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

		if (strutil_string_in_list(fstype, virtual_filesystems)) {
			char dest_dir[PATH_MAX];

			trace("Trying to bind mount virtual FS %s (type %s)", mount_point, fstype);
			snprintf(dest_dir, sizeof(dest_dir), "%s%s", root_dir, mount_point);
			if (!fsutil_mount_bind(mount_point, dest_dir, true)) {
				log_error("Failed to set up mount tree");
				return false;
			}
			wormhole_tree_walk_skip_children(walk);

			wormhole_tree_state_set_bind_mounted(assembled_tree, mount_point);
		} else if (strutil_string_in_list(fstype, no_overlay_filesystems)) {
			trace("Ignoring %s, file system type %s does not support overlays", mount_point, fstype);
		} else if (fsutil_check_path_prefix(overlay_dir, mount_point)) {
			trace("Ignoring %s, because it's a parent directory of our overlay directory", mount_point);
		} else if (access(mount_point, X_OK) < 0) {
			trace("Ignoring potential overlay %s (type %s): inaccessible to this user", mount_point, fstype);
		} else {
			char subtree_dir[PATH_MAX];
			char upper_dir[PATH_MAX], work_dir[PATH_MAX], dest_dir[PATH_MAX];

			trace("Trying to overlay %s (type %s; originally from %s)", mount_point, fstype, ps->system_mount.device);
			snprintf(subtree_dir, sizeof(subtree_dir), "%s/subtree.%u", overlay_dir, mount_index++);

			if (!__init_working_dir(subtree_dir, "tree", upper_dir, sizeof(upper_dir)))
				return false;

			if (!__init_working_dir(subtree_dir, "work", work_dir, sizeof(work_dir)))
				return false;

			snprintf(dest_dir, sizeof(dest_dir), "%s%s", root_dir, mount_point);

			if (!fsutil_mount_overlay(mount_point, upper_dir, work_dir, dest_dir))
				return false;

			wormhole_tree_state_set_overlay_mounted(assembled_tree, mount_point, upper_dir);
		}
	}

	wormhole_tree_walk_end(walk);
	return true;
}

static wormhole_tree_state_t *
remount_filesystems(wormhole_tree_state_t *mnt_tree, const char *overlay_dir, const char *root_dir)
{
	wormhole_tree_state_t *assembled_tree;

	assembled_tree = wormhole_tree_state_new();
	if (!__remount_filesystems(mnt_tree, overlay_dir, root_dir, assembled_tree)) {
		wormhole_tree_state_free(assembled_tree);
		return NULL;
	}
	return assembled_tree;
}

wormhole_tree_state_t *
smoke_and_mirrors(const char *overlay_dir)
{
	char lower_dir[PATH_MAX], upper_dir[PATH_MAX], work_dir[PATH_MAX], root_dir[PATH_MAX];
	wormhole_tree_state_t *mnt_tree;
	wormhole_tree_state_t *assembled_tree;

	mnt_tree = wormhole_get_mount_state(NULL);

	if (!__init_working_dir(overlay_dir, "lower", lower_dir, sizeof(lower_dir))
	 || !__init_working_dir(overlay_dir, "tree", upper_dir, sizeof(upper_dir))
	 || !__init_working_dir(overlay_dir, "work", work_dir, sizeof(work_dir))
	 || !__init_working_dir(overlay_dir, "root", root_dir, sizeof(root_dir)))
		return NULL;

	/* User namespaces are a bit weird. This is the only way I got this to work. */
	if (!fsutil_mount_bind("/", lower_dir, true))
		return NULL;

	if (!fsutil_mount_overlay(lower_dir, upper_dir, work_dir, root_dir))
		return NULL;

	if (!fsutil_lazy_umount(lower_dir))
		return NULL;

	assembled_tree = remount_filesystems(mnt_tree, overlay_dir, root_dir);
	if (assembled_tree == NULL) {
		log_error("Failed to set up file system hierarchy");
		return NULL;
	}

	/* Tell the caller where to find the assembled tree */
	wormhole_tree_state_set_root(assembled_tree, root_dir);

	wormhole_tree_state_free(mnt_tree);
	return assembled_tree;
}

static bool
combine_tree(const char *overlay_root, wormhole_tree_state_t *assembled_tree)
{
	char tree_root[PATH_MAX];
	wormhole_tree_walker_t *walk;
	wormhole_path_state_t *state;
	const char *mount_point;

	snprintf(tree_root, sizeof(tree_root), "%s/tree", overlay_root);

	walk = wormhole_tree_walk(assembled_tree);
	while ((state = wormhole_tree_walk_next(walk, &mount_point)) != NULL) {
		const char *delta_dir;
		const char *mount_parent;
		char mount_dest[PATH_MAX];

		if (state->state != WORMHOLE_PATH_STATE_OVERLAY_MOUNTED)
			continue;

		delta_dir = state->overlay.upperdir;

		if (!fsutil_dir_exists(delta_dir)) {
			trace("Ignoring subtree for %s - %s is not a directory", mount_point, delta_dir);
			continue;
		}
		if (fsutil_dir_is_empty(delta_dir)) {
			trace("Ignoring subtree for %s - directory %s is empty", mount_point, delta_dir);
			continue;
		}

		trace("Found subtree at %s, %s exists and is not empty", mount_point, delta_dir);
		mount_parent = pathutil_dirname(mount_point);

		if (!__init_working_dir(tree_root, mount_parent, mount_dest, sizeof(mount_dest)))
			return false;

		snprintf(mount_dest, sizeof(mount_dest), "%s%s", tree_root, mount_point);
		if (rename(delta_dir, mount_dest) < 0) {
			log_error("Cannot merge %s into tree at %s: %m", delta_dir, mount_dest);
			return false;
		}

		trace("Renamed %s to %s", delta_dir, mount_dest);
	}

	wormhole_tree_walk_end(walk);
	return true;
}

static inline bool
remove_subdir(const char *dir, const char *name)
{
	char namebuf[PATH_MAX];

	snprintf(namebuf, sizeof(namebuf), "%s/%s", dir, name);
	return fsutil_remove_recursively(namebuf);
}

static bool
clean_tree(const char *overlay_root, wormhole_tree_state_t *assembled_tree)
{
	wormhole_tree_walker_t *walk;
	wormhole_path_state_t *state;
	const char *mount_point;
	const char *root_dir;

	walk = wormhole_tree_walk(assembled_tree);
	while ((state = wormhole_tree_walk_next(walk, &mount_point)) != NULL) {
		const char *subtree;

		if (state->state != WORMHOLE_PATH_STATE_OVERLAY_MOUNTED)
			continue;

		subtree = pathutil_dirname(state->overlay.upperdir);

		if (!fsutil_remove_recursively(subtree))
			return false;

		wormhole_tree_state_clear(assembled_tree, mount_point);
	}

	wormhole_tree_walk_end(walk);

	if (!remove_subdir(overlay_root, "work")
	 || !remove_subdir(overlay_root, "lower"))
		return false;

	root_dir = wormhole_tree_state_get_root(assembled_tree);
	if (root_dir && !fsutil_remove_recursively(root_dir))
		return false;

	return true;
}

int
wormhole_digger(int argc, char **argv)
{
	char *shell_argv[] = { "/bin/bash", NULL };
	wormhole_tree_state_t *assembled_tree;
	const char *root_dir;

	if (argc == 0) {
		shell_argv[0] = getenv("SHELL");
		if (shell_argv[0] == NULL)
			shell_argv[0] = "/bin/sh";
		argv = shell_argv;
	}

	if (opt_overlay_root == NULL) {
		log_error("Please specify a root directory via --overlay-root");
		return false;
	}

	if (fsutil_dir_exists(opt_overlay_root)) {
		if (!opt_clean) {
			log_error("Directory %s already exists. Please remove, or invoke me with --clean.", opt_overlay_root);
			return false;
		}

		if (!fsutil_remove_recursively(opt_overlay_root)) {
			log_error("Unable to clean up %s.", opt_overlay_root);
			return false;
		}
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
		wormhole_environment_t *env = NULL;

                if ((env = wormhole_environment_find(opt_base_environment)) == NULL)
			log_fatal("Unknown environment %s", opt_base_environment);

		if (!wormhole_environment_setup(env))
			log_fatal("Failed to set up base environment %s", opt_base_environment);
	}

	assembled_tree = smoke_and_mirrors(opt_overlay_root);
	if (assembled_tree == NULL)
		log_fatal("unable to set up transparent overlay");

	root_dir = wormhole_tree_state_get_root(assembled_tree);
	if (!wormhole_digger_build(argv, root_dir))
		log_fatal("failed to build environment");

	if (!fsutil_lazy_umount(root_dir)) {
		log_error("Unable to detach filesystem tree");
		return false;
	}

	trace("Now combine the tree\n");
	if (!combine_tree(opt_overlay_root, assembled_tree))
		log_fatal("failed to combine subtrees");

	if (!clean_tree(opt_overlay_root, assembled_tree))
		log_fatal("Error during cleanup");

	return 0;
}

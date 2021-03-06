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
	OPT_BIND_MOUNT_TYPE,
	OPT_BUILD_SCRIPT,
	OPT_BUILD_DIRECTORY,
};

struct option wormhole_options[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "debug",		no_argument,		NULL,	'd' },
	{ "base-environment",	required_argument,	NULL,	OPT_BASE_ENVIRONMENT },
	{ "overlay-root",	required_argument,	NULL,	OPT_OVERLAY_ROOT },
	{ "overlay-directory",	required_argument,	NULL,	OPT_OVERLAY_ROOT },
	{ "privileged-namespace", no_argument,		NULL,	OPT_PRIVILEGED_NAMESPACE },
	{ "clean",		no_argument,		NULL,	OPT_CLEAN },
	{ "bind-mount-type",	required_argument,	NULL,	OPT_BIND_MOUNT_TYPE },
	{ "build-script",	required_argument,	NULL,	OPT_BUILD_SCRIPT },
	{ "build-directory",	required_argument,	NULL,	OPT_BUILD_DIRECTORY },
	{ NULL }
};

const char *		opt_config_path = NULL;
const char *		opt_environment_name = NULL;
const char *		opt_base_environment = NULL;
const char *		opt_overlay_root = NULL;
bool			opt_privileged_namespace = false;
bool			opt_clean = false;
const char *		opt_build_script = NULL;
const char *		opt_build_directory = NULL;
const char *		opt_bind_mount_types[64];
unsigned int		opt_bind_mount_type_count;

static bool		wormhole_digger(int argc, char **argv);
static void		usage(int exval);

int
main(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv, "dh", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'h':
			usage(0);

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

		case OPT_BIND_MOUNT_TYPE:
			if (opt_bind_mount_type_count < 63)
				opt_bind_mount_types[opt_bind_mount_type_count++] = optarg;
			break;

		case OPT_BUILD_SCRIPT:
			opt_build_script = optarg;
			break;

		case OPT_BUILD_DIRECTORY:
			opt_build_directory = optarg;
			break;

		default:
			log_error("Error parsing command line");
			usage(2);
		}
	}

	wormhole_common_load_config(opt_config_path);

	if (!wormhole_digger(argc - optind, argv + optind)) {
		log_error("Failed to dig wormhole.");
		return 1;
	}

	return 0;
}

void
usage(int exval)
{
	FILE *f = exval? stderr : stdout;

	fprintf(f,
		"Usage:\n"
		"wormhole-digger [options] [--] [command] [args]\n"
		"  --help, -h\n"
		"     Display this help message\n"
		"  --debug, -d\n"
		"     Increase debugging verbosity\n"
		"  --clean\n"
		"     Clean up output directory first\n"
		"  --privileged-namespace\n"
		"     Create container using a regular namespace rather than a user namespace.\n"
		"  --base-environment <name>\n"
		"     Use <name> as the base environment for the container.\n"
		"  --overlay-directory <dirname>\n"
		"     Specify output directory as <dirname>.\n"
		"  --build-directory <dirname>\n"
		"     Mount <dirname> as /build and set the build command's working directory to it.\n"
		"  --build-script <path>\n"
		"     Mount <path> as /build.sh and execute this as the build command.\n"
	);
	exit(exval);
}

static bool
wormhole_digger_build(wormhole_environment_t *env, char **argv)
{
	struct procutil_command cmd;
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

	if (!wormhole_environment_make_command(env, &cmd, argv))
		return false;

	if (!procutil_command_run(&cmd, &status))
		return false;

	if (!procutil_child_status_okay(status)) {
		log_error("Command \"%s\" failed: %s", argv[0], procutil_child_status_describe(status));
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
__bind_mount_directory(wormhole_environment_t *env, const char *mount_point, const char *relative_dest_dir)
{
	char dest_dir[PATH_MAX];

	snprintf(dest_dir, sizeof(dest_dir), "%s%s", env->root_directory, relative_dest_dir);
	if (access(dest_dir, F_OK) < 0 && errno == ENOENT) {
		if (!fsutil_makedirs(dest_dir, 0755))
			trace("%s does not exist, and unable to create. This won't work", dest_dir);
	}

	if (!fsutil_mount_bind(mount_point, dest_dir, true)) {
		log_error("Failed to set up mount tree");
		return false;
	}

	wormhole_tree_state_set_bind_mounted(env->tree_state, relative_dest_dir);
	return true;
}

static bool
__bind_mount_file(wormhole_environment_t *env, const char *source_path, const char *relative_dest_path)
{
	char dest_path[PATH_MAX];

	snprintf(dest_path, sizeof(dest_path), "%s%s", env->root_directory, relative_dest_path);
	if (access(dest_path, F_OK) < 0 && errno == ENOENT) {
		if (!fsutil_create_empty(dest_path))
			trace("%s does not exist, and unable to create. This won't work", dest_path);
	}

	if (!fsutil_mount_bind(source_path, dest_path, true)) {
		log_error("Failed to set up mount tree");
		return false;
	}

	wormhole_tree_state_set_bind_mounted(env->tree_state, relative_dest_path);
	return true;
}

static bool
rebind_filesystem(wormhole_environment_t *env, const char *mount_point, const char *fstype)
{
	/* FIXME: check if we have already mounted this FS */
	if (access(mount_point, X_OK) < 0) {
		trace("Ignoring %s (type %s): inaccessible to this user", mount_point, fstype);
		return true;
	}

	trace("Trying to bind mount %s (type %s)", mount_point, fstype);
	return __bind_mount_directory(env, mount_point, mount_point);
}

static bool
remount_filesystems(wormhole_environment_t *env, wormhole_tree_state_t *mnt_tree,
			const char *overlay_dir)
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

	wormhole_tree_state_t *assembled_tree = env->tree_state;
	wormhole_tree_walker_t *walk;
	wormhole_path_state_t *ps;
	const char *root_dir = env->root_directory;
	const char *mount_point;
	unsigned int mount_index = 0;
	bool is_image_based = false;

	if (env->nlayers && env->layer[0]->type == WORMHOLE_LAYER_TYPE_IMAGE)
		is_image_based = true;

	walk = wormhole_tree_walk(mnt_tree);
	while ((ps = wormhole_tree_walk_next(walk, &mount_point)) != NULL) {
		const char *fstype;

		if (ps->state != WORMHOLE_PATH_STATE_SYSTEM_MOUNT)
			continue; /* should not happen given how we constructed mnt_tree */

		if (!strcmp(mount_point, "/")) {
			trace("Skipping root directory");
			continue;
		}

		fstype = ps->system_mount.type;

		if (strutil_string_in_list(fstype, virtual_filesystems)) {
			if (!rebind_filesystem(env, mount_point, fstype))
				return false;

			wormhole_tree_walk_skip_children(walk);
		} else if (strutil_string_in_list(fstype, opt_bind_mount_types)) {
			if (!rebind_filesystem(env, mount_point, fstype))
				return false;

			wormhole_tree_walk_skip_children(walk);
		} else if (strutil_string_in_list(fstype, no_overlay_filesystems)) {
			trace("Ignoring %s, file system type %s does not support overlays", mount_point, fstype);
		} else if (fsutil_check_path_prefix(overlay_dir, mount_point)) {
			trace("Ignoring %s, because it's a parent directory of our overlay directory", mount_point);
		} else if (access(mount_point, X_OK) < 0) {
			trace("Ignoring potential overlay %s (type %s): inaccessible to this user", mount_point, fstype);
		} else {
			char subtree_dir[PATH_MAX];
			char upper_dir[PATH_MAX], work_dir[PATH_MAX], dest_dir[PATH_MAX];

			if (is_image_based) {
				trace("Ignoring system mount %s (%s; device %s)", mount_point, fstype, ps->system_mount.device);
				continue;
			}

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

bool
smoke_and_mirrors(wormhole_environment_t *env, const char *overlay_dir)
{
	const char *image_root_dir = env->root_directory;
	char lower_dir[PATH_MAX], upper_dir[PATH_MAX], work_dir[PATH_MAX], root_dir[PATH_MAX];
	wormhole_tree_state_t *mnt_tree;

	if (image_root_dir == NULL
	 && env->nlayers
	 && env->layer[0]->type == WORMHOLE_LAYER_TYPE_IMAGE) {
		image_root_dir = env->layer[0]->directory;
		strutil_set(&env->orig_root_directory, image_root_dir);
	}

	mnt_tree = wormhole_get_mount_state(NULL);

	if (!__init_working_dir(overlay_dir, "lower", lower_dir, sizeof(lower_dir))
	 || !__init_working_dir(overlay_dir, "tree", upper_dir, sizeof(upper_dir))
	 || !__init_working_dir(overlay_dir, "work", work_dir, sizeof(work_dir))
	 || !__init_working_dir(overlay_dir, "root", root_dir, sizeof(root_dir)))
		return false;

	/* User namespaces are a bit weird. This is the only way I got this to work. */
	if (image_root_dir == NULL)
		image_root_dir = "/";
	if (!fsutil_mount_bind(image_root_dir, lower_dir, true))
		return false;

	if (!fsutil_mount_overlay(lower_dir, upper_dir, work_dir, root_dir))
		return false;

	trace("overlay mounted at %s", root_dir);
	if (!fsutil_lazy_umount(lower_dir))
		return false;

	/* root_dir becomes the new image root for this environment. */
	wormhole_environment_set_root_directory(env, root_dir);

	if (!wormhole_environment_setup(env)) {
		log_error("%s: failed to set up environment", __func__);
		return false;
	}

	// XXX do not remount these yet, defer until later and let the caller do that
	if (!remount_filesystems(env, mnt_tree, overlay_dir)) {
		log_error("Failed to set up file system hierarchy");
		return false;
	}

	wormhole_tree_state_free(mnt_tree);
	return true;
}

/*
 * Export a file named /provides to the container.
 * The build script should write to this file the capabilities provided by
 * this wormhole layer.
 */
static int	__provides_fd = -1;

static bool
mount_provides_file(wormhole_environment_t *env)
{
	char hostpath[PATH_MAX];
	int fd;

	fd = fsutil_tempfile("provides", hostpath, sizeof(hostpath));
	if (fd < 0)
		return false;

	if (!__bind_mount_file(env, hostpath, "/provides")) {
		log_error("Failed to set up /provides file");
		remove(hostpath);
		close(fd);
		return false;
	}

	remove(hostpath);
	__provides_fd = fd;
	return true;
}

static bool
update_provides(wormhole_environment_t *env)
{
	char line[256];
	FILE *fp;

	if (__provides_fd < 0)
		return true;

	if (!(fp = fdopen(__provides_fd, "r"))) {
		log_error("fdopen of provides_fd failed: %m");
		return false;
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		line[strcspn(line, "\r\n")] = '\0';

		trace("Image provides %s", line);
		strutil_array_append(&env->provides, line);
	}

	fclose(fp);

	return true;
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

		if (!fsutil_isdir(delta_dir)) {
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
	 || !remove_subdir(overlay_root, "lower")
	 || !remove_subdir(overlay_root, "tree/build.sh")
	 || !remove_subdir(overlay_root, "tree/build")
	 || !remove_subdir(overlay_root, "tree/provides"))
		return false;

	root_dir = wormhole_tree_state_get_root(assembled_tree);
	if (root_dir && !fsutil_remove_recursively(root_dir))
		return false;

	return true;
}

static bool
write_config(const char *root_dir, wormhole_environment_t *env)
{
	char pathname[PATH_MAX];
	struct wormhole_config *cfg;
	struct wormhole_environment_config *env_cfg;
	struct wormhole_layer_config *layer_cfg;
	bool ok;

	layer_cfg = calloc(1, sizeof(*layer_cfg));
	strutil_set(&layer_cfg->directory, "tree");

	env_cfg = calloc(1, sizeof(*env_cfg));
	strutil_set(&env_cfg->name, env->name);
	strutil_array_append_array(&env_cfg->requires, &env->requires);
	strutil_array_append_array(&env_cfg->provides, &env->provides);
	env_cfg->layers = layer_cfg;

	cfg = calloc(1, sizeof(*cfg));
	cfg->environments = env_cfg;

	snprintf(pathname, sizeof(pathname), "%s/.digger.conf", root_dir);

	ok = wormhole_config_write(cfg, pathname);
	wormhole_config_free(cfg);

	return ok;
}

static char **
make_argv_shell(void)
{
	static char *shell_argv[] = { "/bin/bash", NULL };

	shell_argv[0] = getenv("SHELL");
	if (shell_argv[0] == NULL)
		shell_argv[0] = "/bin/sh";
	return shell_argv;
}

bool
wormhole_digger(int argc, char **argv)
{
	wormhole_environment_t *env = NULL;
	wormhole_tree_state_t *assembled_tree;
	const char *root_dir;

	if (opt_overlay_root == NULL) {
		log_error("Please specify a root directory via --overlay-directory");
		return false;
	}

	if (fsutil_isdir(opt_overlay_root)) {
		if (!opt_clean) {
			log_error("Directory %s already exists. Please remove, or invoke me with --clean.", opt_overlay_root);
			return false;
		}

		if (!fsutil_remove_recursively(opt_overlay_root)) {
			log_error("Unable to clean up %s.", opt_overlay_root);
			return false;
		}
	}

	if (!fsutil_makedirs(opt_overlay_root, 0755)) {
		log_error("Unable to create overlay root at %s", opt_overlay_root);
		return false;
	}

	if (opt_privileged_namespace) {
		if (!wormhole_create_namespace()) {
			log_error("Unable to set up privileged namespace");
			return false;
		}
	} else {
		if (!wormhole_create_user_namespace()) {
			log_error("Unable to set up user namespace");
			return false;
		}
	}

	if (!fsutil_make_fs_private("/")) {
		log_error("Unable to change file system root to private (no propagation)");
		return false;
	}

	if (opt_environment_name == NULL)
		opt_environment_name = pathutil_const_basename(opt_overlay_root);

	if (opt_base_environment != 0) {
		/* Set up base environment */
                if ((env = wormhole_environment_by_capability(opt_base_environment)) == NULL) {
			log_error("Unknown environment %s", opt_base_environment);
			return false;
		}

		trace("Using environment %s (type %d)", env->name, env->layer[0]->type);

		env = wormhole_environment_new(opt_environment_name, env);
		strutil_array_append(&env->requires, opt_base_environment);
	} else {
		env = wormhole_environment_new(opt_environment_name, NULL);
	}

	if (!smoke_and_mirrors(env, opt_overlay_root)) {
		log_error("unable to set up transparent overlay");
		return false;
	}

	if (opt_build_directory) {
		trace("Trying to bind mount %s to /build", opt_build_directory);
		if (!__bind_mount_directory(env, opt_build_directory, "/build")) {
			log_error("Failed to set up build directory");
			return false;
		}

		wormhole_environment_set_working_directory(env, "/build");
	}

	if (opt_build_script) {
		trace("Trying to bind mount %s to /build.sh", opt_build_script);
		if (!__bind_mount_file(env, opt_build_script, "/build.sh")) {
			log_error("Failed to set up build script");
			return false;
		}

		*--argv = "/build.sh";
	}

	if (!mount_provides_file(env))
		return false;

	assembled_tree = env->tree_state;
	root_dir = env->root_directory;

	if (*argv == NULL)
		argv = make_argv_shell();

	if (!wormhole_digger_build(env, argv)) {
		log_error("failed to build environment");
		return false;
	}

	if (!fsutil_lazy_umount(root_dir)) {
		log_error("Unable to detach filesystem tree");
		return false;
	}

	trace("Now combine the tree\n");
	if (!combine_tree(opt_overlay_root, assembled_tree)) {
		log_error("failed to combine subtrees");
		return false;
	}

	if (!clean_tree(opt_overlay_root, assembled_tree)) {
		log_error("Error during cleanup");
		return false;
	}

	if (!update_provides(env))
		return false;

	if (!write_config(opt_overlay_root, env)) {
		log_error("failed to write config file");
		return false;
	}

	printf("Combined overlay tree is now in %s\n", opt_overlay_root);
	return true;
}

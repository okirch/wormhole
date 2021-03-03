/*
 * profile handling for wormhole
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
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <glob.h>

#include "wormhole.h"
#include "tracing.h"
#include "profiles.h"
#include "config.h"
#include "runtime.h"
#include "server.h"
#include "socket.h"
#include "util.h"

static wormhole_profile_t *	wormhole_profiles;
static wormhole_environment_t *	wormhole_environments;
static const char *		wormhole_client_path;

static bool			__wormhole_profiles_configure_environments(struct wormhole_environment_config *list);
static bool			__wormhole_profiles_configure_profiles(struct wormhole_profile_config *list);

static wormhole_environment_t *	wormhole_environment_new(const char *name);
static wormhole_profile_t *	wormhole_profile_new(const char *name);

struct wormhole_scaffold {
	const char *		source_dir;
	const char *		dest_dir;
};

static const char *
__wormhole_scaffold_insert_prefix(const char *prefix, const char *path)
{
	static char pathbuf[PATH_MAX];

	if (prefix == NULL)
		return path;

	snprintf(pathbuf, sizeof(pathbuf), "%s%s%s",
			prefix,
			(path[0] == '/'? "" : "/"),
			path);
	return pathbuf;
}

static const char *
__wormhole_scaffold_strip_prefix(const char *prefix, const char *path)
{
	if (prefix == NULL)
		return path;

	path = fsutil_strip_path_prefix(path, prefix);
	if (path == NULL  || *path == '\0')
		return NULL;
	return path;
}

static const char *
wormhole_scaffold_source_path(const struct wormhole_scaffold *scaffold, const char *path)
{
	return __wormhole_scaffold_insert_prefix(scaffold->source_dir, path);
}

static const char *
wormhole_scaffold_source_path_inverse(const struct wormhole_scaffold *scaffold, const char *path)
{
	return __wormhole_scaffold_strip_prefix(scaffold->source_dir, path);
}

static const char *
wormhole_scaffold_dest_path(const struct wormhole_scaffold *scaffold, const char *path)
{
	return __wormhole_scaffold_insert_prefix(scaffold->dest_dir, path);
}

/*
 * Initialize our internal data structures from config
 */
bool
wormhole_profiles_configure(struct wormhole_config *cfg)
{
	bool success = true;

	wormhole_client_path = cfg->client_path;
	if (wormhole_client_path == NULL)
		wormhole_client_path = WORMHOLE_CLIENT_PATH;

	if (!__wormhole_profiles_configure_environments(cfg->environments))
		success = false;
	if (!__wormhole_profiles_configure_profiles(cfg->profiles))
		success = false;
	return success;
}

wormhole_environment_t *
__wormhole_environment_from_config(struct wormhole_environment_config *cfg)
{
	wormhole_environment_t *env;

	env = wormhole_environment_new(cfg->name);
	env->config = cfg;

	return env;
}

static bool
__wormhole_environment_add_layer(wormhole_environment_t *env, struct wormhole_layer_config *layer)
{
	if (env->nlayers >= WORMHOLE_ENVIRONMENT_LAYER_MAX) {
		log_error("Environment %s requires too many layers", env->name);
		return false;
	}

	env->layer[env->nlayers++] = layer;
	return true;
}

static bool
__wormhole_environment_chase_layers(wormhole_environment_t *env, struct wormhole_environment_config *env_cfg)
{
	struct wormhole_layer_config *layer;

	for (layer = env_cfg->layers; layer; layer = layer->next) {
		/* If the layer refers to another environment, splice its layers into our list. */
		if (layer->type == WORMHOLE_LAYER_TYPE_REFERENCE) {
			const char *lower_name = layer->lower_layer_name;
			wormhole_environment_t *lower;

			if ((lower = wormhole_environment_find(lower_name)) == NULL) {
				log_error("Environment %s references lower layer \"%s\", which does not exist",
						env_cfg->name, lower_name);
				return false;
			}

			if (!__wormhole_environment_chase_layers(env, lower->config))
				return false;
		} else
		/* FIXME: we should check whether we already have this layer */
		if (!__wormhole_environment_add_layer(env, layer))
			return false;
	}

	return true;
}

bool
__wormhole_profiles_configure_environments(struct wormhole_environment_config *list)
{
	wormhole_environment_t **tail = &wormhole_environments;
	struct wormhole_environment_config *cfg;
	wormhole_environment_t *env;
	bool success = true;

	for (cfg = list; cfg; cfg = cfg->next) {
		if (!(env = __wormhole_environment_from_config(cfg)))
			return false;

		*tail = env;
		tail = &env->next;
	}

	for (env = wormhole_environments; env; env = env->next) {

		if (!__wormhole_environment_chase_layers(env, env->config))
			success = false;
	}

	return success;
}

static wormhole_profile_t *
__wormhole_profile_from_config(struct wormhole_profile_config *cfg)
{
	wormhole_environment_t *env = NULL;
	wormhole_profile_t *profile;

	if (cfg->environment) {
		if ((env = wormhole_environment_find(cfg->environment)) == NULL) {
			log_error("Profile %s references environment \"%s\", which does not exist",
					cfg->name, cfg->environment);
			return NULL;
		}
	}

	profile = wormhole_profile_new(cfg->name);
	profile->config = cfg;
	profile->environment = env;

	return profile;
}

bool
__wormhole_profiles_configure_profiles(struct wormhole_profile_config *list)
{
	wormhole_profile_t **tail = &wormhole_profiles;
	struct wormhole_profile_config *cfg;

	for (cfg = list; cfg; cfg = cfg->next) {
		wormhole_profile_t *profile;

		if (!(profile = __wormhole_profile_from_config(cfg)))
			return false;

		*tail = profile;
		tail = &profile->next;
	}

	return true;
}

wormhole_profile_t *
wormhole_profile_new(const char *name)
{
	wormhole_profile_t *profile;

	profile = calloc(1, sizeof(*profile));
	profile->name = strdup(name);

	return profile;
}

wormhole_profile_t *
wormhole_profile_find(const char *argv0)
{
	wormhole_profile_t *profile;
	const char *name;

	/* If the name hint we've been given by the client starts with a slash,
	 * we compare it against the wrappers and commands specified by any
	 * profile. */
	if (argv0[0] == '/') {
		const char *cmd;

		for (profile = wormhole_profiles; profile; profile = profile->next) {
			cmd = profile->config? profile->config->wrapper : NULL;

			if (cmd && !strcmp(argv0, cmd))
				return profile;
		}

		for (profile = wormhole_profiles; profile; profile = profile->next) {
			cmd = profile->config? profile->config->command : NULL;

			if (cmd && !strcmp(argv0, cmd))
				return profile;
		}
	}

	/* If the above failed, fall back to the original default behavior, which
	 * is to look for a profile that matches the basename of the path provided. */

	name = wormhole_const_basename(argv0);
	if (name == NULL || *name == '\0') {
		log_error("Cannot detect basename of executable");
		return NULL;
	}

	for (profile = wormhole_profiles; profile; profile = profile->next) {
		if (!strcmp(name, profile->name))
			return profile;
	}

	return NULL;
}

static wormhole_environment_t *
wormhole_environment_new(const char *name)
{
	wormhole_environment_t *env;

	env = calloc(1, sizeof(*env));
	env->name = strdup(name);
	env->nsfd = -1;

	return env;
}

void
wormhole_environment_set_fd(wormhole_environment_t *env, int fd)
{
	if (env->nsfd >= 0) {
		close(env->nsfd >= 0);
		env->nsfd = -1;
	}

	trace("Environment \"%s\": installing namespace fd %d", env->name, fd);
	env->nsfd = fd;
}

wormhole_environment_t *
wormhole_environment_find(const char *name)
{
	wormhole_environment_t *env;

	for (env = wormhole_environments; env; env = env->next) {
		if (!strcmp(env->name, name))
			return env;
	}

	return NULL;
}

const char *
wormhole_environment_path(wormhole_environment_t *env, const char *abs_path)
{
	static char pathbuf[PATH_MAX];

	if (env->root_directory) {
		snprintf(pathbuf, sizeof(pathbuf), "%s%s", env->root_directory, abs_path);
		return pathbuf;
	}

	return abs_path;
}

/*
 * Start a container for this image, and mount its file system.
 */
/* The following should be part of the container runtime facade */
static const char *
container_make_local_name(const char *image_name)
{
	static char local_buf[256];
	char *s;

	if (snprintf(local_buf, sizeof(local_buf), "wormhole_%s", image_name) >= sizeof(local_buf)) {
		log_error("Container image name \"%s\" is too long", image_name);
		return NULL;
	}

	if ((s = strchr(local_buf, ':')) != NULL)
		*s = '\0';

	while ((s = strchr(local_buf, '/')) != NULL)
		*s = '_';

	return local_buf;
}

static const char *
overlay_container_mount(const wormhole_environment_t *env, const char *container_image)
{
	const char *local_name;

	if (container_image == NULL) {
		log_error("Environment \"%s\" does not have a container image defined", env->name);
		return NULL;
	}

	if (!(local_name = container_make_local_name(container_image)))
		return NULL;

	if (!wormhole_container_exists(local_name)) {
		if (!wormhole_container_start(container_image, local_name))
			return NULL;
	}

	return wormhole_container_mount(local_name);
}

static bool
overlay_container_unmount(const wormhole_environment_t *env, const char *container_image, const char *mount_point)
{
	return true;
}

void
dump_mtab(const char *msg)
{
	FILE *fp;
	char line[256];

	printf("== mtab %s ==", msg);
	fp = fopen("/proc/mounts", "r");
	if (fp == NULL) {
		log_error("Unable to open /proc/mounts: %m");
		exit(7);
	}

	while (fgets(line, sizeof(line), fp) != NULL) {
		line[strcspn(line, "\n")] = '\0';
		printf("%s\n", line);
	}
	fclose(fp);
}

/*
 * pathinfo related functions
 */
static const char *
pathinfo_type_string(int type)
{
	switch (type) {
	case WORMHOLE_PATH_TYPE_HIDE:
		return "HIDE";
	case WORMHOLE_PATH_TYPE_BIND:
		return "BIND";
	case WORMHOLE_PATH_TYPE_BIND_CHILDREN:
		return "BIND_CHILDREN";
	case WORMHOLE_PATH_TYPE_OVERLAY:
		return "OVERLAY";
	case WORMHOLE_PATH_TYPE_OVERLAY_CHILDREN:
		return "OVERLAY_CHILDREN";
	case WORMHOLE_PATH_TYPE_MOUNT:
		return "MOUNT";
	case WORMHOLE_PATH_TYPE_WORMHOLE:
		return "WORMHOLE";
	}

	return "UNKNOWN";
}

static bool
_pathinfo_bind_one(wormhole_environment_t *environment, const char *source, const char *target)
{
	if (!fsutil_mount_bind(source, target, true))
		return false;

	wormhole_tree_state_set_bind_mounted(environment->tree_state, target);
	return true;
}

static bool
_pathinfo_overlay_one(wormhole_environment_t *environment,
		const char *source, const char *target,
		const char *workdir)
{
#if 1
	char lower_path_list[2 * PATH_MAX];

	snprintf(lower_path_list, sizeof(lower_path_list), "%s:%s", target, source);

	/* Overlay "source" on top of "target" and mount at path "target" */
	if (!fsutil_mount_overlay(lower_path_list, NULL, NULL, target))
		return false;
#else
	/* Overlay "source" on top of "target" and mount at path "target" */
	if (!fsutil_mount_overlay(target, source, workdir, target))
		return false;
#endif

	wormhole_tree_state_set_overlay_mounted(environment->tree_state, source, target);
	return true;
}

static bool
_pathinfo_mount_one(wormhole_environment_t *environment, const wormhole_path_info_t *pi,
			const char *dest)
{
	if (!fsutil_mount_virtual_fs(dest, pi->mount.fstype, pi->mount.options))
		return false;

	wormhole_tree_state_set_system_mount(environment->tree_state, dest, pi->mount.fstype, NULL);
	return true;
}

static bool
pathinfo_bind_path(wormhole_environment_t *environment, const wormhole_path_info_t *pi,
			const struct wormhole_scaffold *scaffold,
			const char *dest, const char *source)
{
	trace2("%s(%s, %s)", __func__, dest, source);
	return _pathinfo_bind_one(environment, source, dest);
}

static bool
pathinfo_overlay_path(wormhole_environment_t *environment, const wormhole_path_info_t *pi,
			const struct wormhole_scaffold *scaffold,
			const char *dest, const char *source)
{
	char pathbuf[PATH_MAX];
	const char *workdir;

	trace2("%s(%s, %s)", __func__, dest, source);

	snprintf(pathbuf, sizeof(pathbuf), "/work%s", dest);
	workdir = wormhole_scaffold_source_path(scaffold, pathbuf);

	if (!fsutil_makedirs(workdir, 0755)) {
		log_error("Failed to create overlay workdir for %s at %s", dest, workdir);
		return false;
	}

	return _pathinfo_overlay_one(environment, source, dest, workdir);
}

static bool
pathinfo_create_overlay(wormhole_environment_t *environment, const char *tempdir, const char *where)
{
	char upper[PATH_MAX], lower[PATH_MAX], work[PATH_MAX];

	snprintf(lower, sizeof(lower), "%s/lower", tempdir);
	snprintf(upper, sizeof(upper), "%s/upper", tempdir);
	snprintf(work, sizeof(work), "%s/work", tempdir);

	if (symlink(where, lower) < 0) {
		log_error("symlink(%s, %s): %m", where, lower);
		return false;
	}
	if (mkdir(upper, 0755) < 0) {
		log_error("mkdir(%s): %m", upper);
		return false;
	}
	if (mkdir(work, 0755) < 0) {
		log_error("mkdir(%s): %m", work);
		return false;
	}

	if (!fsutil_mount_overlay(lower, upper, work, where))
		return false;

	/* Don't set the upperdir; it's just a temporary directory that's no longer
	 * valid after we return. */
	wormhole_tree_state_set_overlay_mounted(environment->tree_state, where, NULL);
	return true;
}

static bool
pathinfo_bind_children(wormhole_environment_t *environment, const wormhole_path_info_t *pi,
		const struct wormhole_scaffold *scaffold,
		const char *dest, const char *source)
{
	struct fsutil_tempdir td;
	const char *tempdir;
	struct dirent *d;
	DIR *dirfd;
	unsigned int num_mounted = 0;
	bool ok = false;

	trace2("%s(%s, %s)", __func__, dest, source);

	dirfd = opendir(source);
	if (dirfd == NULL) {
		log_error("%s: unable to open dir %s: %m", environment->name, source);
		return false;
	}

	fsutil_tempdir_init(&td);

	tempdir = fsutil_tempdir_path(&td);
	if (!pathinfo_create_overlay(environment, tempdir, dest)) {
		log_error("unable to create overlay at \"%s\"", dest);
		goto out;
	}

	while ((d = readdir(dirfd)) != NULL) {
		char source_entry[PATH_MAX], target_entry[PATH_MAX];

		if (d->d_type != DT_DIR && d->d_type != DT_REG)
			continue;
		if (d->d_name[0] == '.' && (d->d_name[1] == '\0' || d->d_name[1] == '.'))
			continue;

		/* printf("Trying to mount %s from %s to %s\n", d->d_name, source, dest); */
		snprintf(source_entry, sizeof(source_entry), "%s/%s", source, d->d_name);
		snprintf(target_entry, sizeof(target_entry), "%s/%s", dest, d->d_name);

		/* FIXME: avoid mounting if source and target are exactly the same file;
		 * this happens a lot when you mount a /lib directory. */

		if (access(target_entry, F_OK) < 0 && errno == ENOENT) {
			if (d->d_type == DT_DIR)
				(void) mkdir(target_entry, 0700);
			else {
				int fd;

				fd = open(target_entry, O_CREAT, 0600);
				if (fd >= 0)
					close(fd);
			}
		}

		if (!_pathinfo_bind_one(environment, source_entry, target_entry))
			goto out;

		num_mounted ++;
	}

	trace("Mounted %u entries", num_mounted);
	ok = true;

out:
	fsutil_tempdir_cleanup(&td);
	if (dirfd)
		closedir(dirfd);
	return ok;
}

static bool
pathinfo_bind_wormhole(wormhole_environment_t *environment, const wormhole_path_info_t *pi, const struct wormhole_scaffold *scaffold)
{
	const char *dest;

	trace2("%s(%s)", __func__, pi->path);

	dest = wormhole_scaffold_dest_path(scaffold, pi->path);
	return _pathinfo_bind_one(environment, wormhole_client_path, dest);
}

static bool
pathinfo_process_glob(wormhole_environment_t *env, const wormhole_path_info_t *pi, const struct wormhole_scaffold *scaffold,
			bool (*func)(wormhole_environment_t *env, const wormhole_path_info_t *pi, const struct wormhole_scaffold *scaffold, const char *dest, const char *source))
{
	bool retval = false;
	char pattern[PATH_MAX];
	glob_t globbed;
	size_t n;
	int r;

	trace("pathinfo_process_glob(path=%s)", pi->path);

	/* We check for this in the config file parsing code, so an assert is good enough here. */
	assert(pi->path[0] == '/');

	/* Build the pattern to glob for.
	 * Overlay case: $overlay_root/$path
	 * Image case: $path
	 */
	strncpy(pattern, wormhole_scaffold_source_path(scaffold, pi->path), sizeof(pattern));

	r = glob(pattern, GLOB_NOSORT | GLOB_NOMAGIC | GLOB_TILDE, NULL, &globbed);
	if (r != 0) {
		/* I'm globsmacked. Why did it fail? */
		log_error("pathinfo expansion failed, glob(%s) returns %d", pattern, r);
		goto done;
	}

	for (n = 0; n < globbed.gl_pathc; ++n) {
		const char *source, *abs_path, *dest;

		source = globbed.gl_pathv[n];

		/* Get the un-prefixed path for $glob
		 * Overlay case: Strip $overlay_root from $overlay_root/$glob
		 * Image case: $glob
		 */
		abs_path = wormhole_scaffold_source_path_inverse(scaffold, source);
		if (abs_path == NULL) {
			log_error("%s: strange - glob expansion of %s returned path name %s", __func__,
					pattern, source);
			goto done;
		}

		dest = wormhole_scaffold_dest_path(scaffold, abs_path);

		if (!func(env, pi, scaffold, dest, source))
			goto done;
	}

	retval = true;

done:
	globfree(&globbed);
	return retval;
}

static bool
pathinfo_process_mount(wormhole_environment_t *env, const wormhole_path_info_t *pi,
			const struct wormhole_scaffold *scaffold)
{
	const char *dest;

	trace("%s(path=%s)", __func__, pi->path);

	/* We check for this in the config file parsing code, so an assert is good enough here. */
	assert(pi->path[0] == '/');

	dest = wormhole_scaffold_dest_path(scaffold, pi->path);

	if (!_pathinfo_mount_one(env, pi, dest))
		return false;

	return true;
}

static bool
pathinfo_process(wormhole_environment_t *env, const wormhole_path_info_t *pi, const struct wormhole_scaffold *scaffold)
{
	if (pi->type == WORMHOLE_PATH_TYPE_HIDE) {
		/* hiding is not yet implemented */
		log_error("Environment %s: do not know how to hide %s - no yet implemented", env->name, pi->path);
		return false;
	}

	switch (pi->type) {
	case WORMHOLE_PATH_TYPE_BIND:
		return pathinfo_process_glob(env, pi, scaffold, pathinfo_bind_path);

	case WORMHOLE_PATH_TYPE_BIND_CHILDREN:
		return pathinfo_process_glob(env, pi, scaffold, pathinfo_bind_children);

	case WORMHOLE_PATH_TYPE_OVERLAY:
		return pathinfo_process_glob(env, pi, scaffold, pathinfo_overlay_path);

#if 0
	case WORMHOLE_PATH_TYPE_OVERLAY_CHILDREN:
		return pathinfo_process_glob(env, pi, scaffold, pathinfo_overlay_children);
#endif

	case WORMHOLE_PATH_TYPE_MOUNT:
		return pathinfo_process_mount(env, pi, scaffold);

	case WORMHOLE_PATH_TYPE_WORMHOLE:
		return pathinfo_bind_wormhole(env, pi, scaffold);

	default:
		log_error("Environment %s: unsupported path_info type %s", env->name, pathinfo_type_string(pi->type));
		return false;
	}
}

/*
 * Some overlays contain shared libraries. Maintain a separate ld.so.cache inside the layer.
 */
static bool
wormhole_layer_ldconfig(wormhole_environment_t *env, const struct wormhole_layer_config *layer, const char *overlay_root)
{
	char overlay_etc[PATH_MAX];
	int verdict;
	bool ok = false, is_tempfile = false;

	snprintf(overlay_etc, sizeof(overlay_etc), "%s/etc", overlay_root);
	if (!fsutil_makedirs(overlay_etc, 0755)) {
		log_error("Environment %s: unable to create /etc directory for ld.so.cache", env->name);
		return false;
	}

	if (geteuid() == 0) {
		snprintf(overlay_etc, sizeof(overlay_etc), "%s/etc/ld.so.cache", overlay_root);

		verdict = fsutil_inode_compare("/etc/ld.so.cache", overlay_etc);
	} else {
		int fd;

		strncpy(overlay_etc, "/tmp/ld.so.XXXXXX.conf", sizeof(overlay_etc));
		if ((fd = mkstemps(overlay_etc, sizeof(".conf") - 1)) < 0) {
			log_error("Cannot create temp file for ld.so.conf: %m");
			return false;
		}

		is_tempfile = true;
		close(fd);

		verdict = -1;
	}

	/* If the layer has its own version of /etc/ld.so.cache that has a more recent time
	 * stamp than the "real" one, there's no need to regenerate.
	 */
	if (verdict < 0 || !(verdict & FSUTIL_FILE_YOUNGER)) {
		char command[PATH_MAX];

		trace2("Environment %s: updating ld.so.cache", env->name);

		/* We do not re-create links. The links inside the layer should be
		 * up-to-date (hopefully!); and touching links in layers below may
		 * fail. */
		snprintf(command, sizeof(command), "/sbin/ldconfig -X -C %s", overlay_etc);

		trace2("Running \"%s\"", command);
		if (system(command) != 0)
			log_warning("Environment %s: ldconfig failed", env->name);
	} else {
		trace2("Environment %s: ld.so.cache exists and is recent - not updating it", env->name);
	}

	/* Now bind mount it */
	ok = _pathinfo_bind_one(env, overlay_etc, "/etc/ld.so.cache");

	if (is_tempfile)
		unlink(overlay_etc);

	return ok;
}

static bool
wormhole_layer_setup(wormhole_environment_t *env, const struct wormhole_layer_config *layer)
{
	const char *overlay_root;
	const wormhole_path_info_t *pi;
	struct wormhole_scaffold scaffold;
	bool mounted = false;
	bool ok = true;
	unsigned int i;

	if (layer->image) {
		/* The overlay is provided via a container image. */
		overlay_root = overlay_container_mount(env, layer->image);
		if (!overlay_root)
			log_error("Environment %s: unable to mount container \"%s\"", env->name, layer->image);
		mounted = true;
	} else {
		assert(layer->directory);
		overlay_root = layer->directory;
	}

	if (layer->type == WORMHOLE_LAYER_TYPE_IMAGE) {
		if (env->root_directory != NULL) {
			log_error("Unable to set up image layer: enviornment root directory already set");
			return false;
		}

		env->root_directory = strdup(overlay_root);
		scaffold.source_dir = NULL;
	} else {
		scaffold.source_dir = overlay_root;
	}

	scaffold.dest_dir = env->root_directory;

	for (i = 0, pi = layer->path; ok && i < layer->npaths; ++i, ++pi) {
		trace("Environment %s: pathinfo %s: %s", env->name,
				pathinfo_type_string(pi->type), pi->path);
		ok = pathinfo_process(env, pi, &scaffold);
		trace("  result: %sok", ok? "" : "not ");
	}

	if (ok && layer->use_ldconfig)
		ok = wormhole_layer_ldconfig(env, layer, overlay_root);

	if (mounted && !overlay_container_unmount(env, layer->image, overlay_root)) {
		log_error("Environment %s: unable to unmount \"%s\": %m", env->name, overlay_root);
		ok = false;
	}

	return ok;
}

bool
wormhole_environment_setup(wormhole_environment_t *env)
{
	unsigned int i;

	if (env->failed)
		return false;

	if (env->tree_state)
		wormhole_tree_state_free(env->tree_state);
	env->tree_state = wormhole_tree_state_new();

	for (i = 0; i < env->nlayers; ++i) {
		struct wormhole_layer_config *layer = env->layer[i];

		if (i && layer->type == WORMHOLE_LAYER_TYPE_IMAGE) {
			log_error("Environment %s specifies an image container, but it's not the bottom most layer", env->name);
			return false;
		}

		if (!wormhole_layer_setup(env, layer))
			return false;
	}

	return true;
}

int
wormhole_profile_setup(wormhole_profile_t *profile, bool userns)
{
	wormhole_environment_t *env = profile->environment;

	/* No environment or no overlays - use the root context */
	if (env == NULL || env->nlayers == 0)
		return 0;

#if 0
	/* This does not look right in this place. */
	if (!fsutil_make_fs_private("/"))
                log_fatal("Unable to change file system root to private (no propagation)");
#endif

	if (userns) {
		if (!wormhole_create_user_namespace())
			return -1;
	} else {
		if (!wormhole_create_namespace())
			return -1;
	}

	if (!wormhole_environment_setup(env))
		return -1;

	return 0;
}

const char *
wormhole_profile_command(const wormhole_profile_t *profile)
{
	return profile->config->command;
}

int
wormhole_profile_namespace_fd(const wormhole_profile_t *profile)
{
	wormhole_environment_t *env;
	int fd = -1;

	if ((env = profile->environment) == NULL) {
		trace("Profile %s: returning namespace fd for host namespace", profile->name);
		fd = open("/proc/self/ns/mnt", O_RDONLY);
		if (fd < 0)
			log_error("Unable to open /proc/self/ns/mnt: %m");
	} else
	if (!env->failed && env->nsfd >= 0) {
		trace("Profile %s: returning namespace fd for environment \"%s\"", profile->name, env->name);
		fd = dup(env->nsfd);
		if (fd < 0)
			log_error("Unable to dup() namespace fd: %m");
	}

	return fd;
}

/*
 * wormhole layer capabilities
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


#include <sys/stat.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>

#include "wormhole.h"
#include "profiles.h"
#include "config.h"
#include "util.h"
#include "tracing.h"


/*
 * We keep a directory to map capability strings to wormhole config files.
 * A capability looks a lot like a $name-$version string used by package
 * managers like rpm.
 *
 * The directory contains a farm of symbolic links.
 * Each link represents a capability string, and it points at the config
 * file that defines a layer or image providing this capability.
 *
 * When requiring a capability, we try to resolve it by scanning this
 * directory for links that
 *  (a) match $name
 *  (b) have a $version that is greater than or equal the version
 *      required
 * If we encounter several such links, we return the one with the highest
 * version.
 *
 * IOW, the current system implies strict upward ABI compatibility.
 * This probably needs to be enhanced to resemble more something like
 * the semantic versioninig implemented by ruby's ~> operator
 */

/*
 * Similarly, we keep a second directory to map command names to
 * wormhole config files in the same way.
 */

#define WORMHOLE_CAPABILITY_VERSION_MAX		16

typedef struct wormhole_capability {
	char *			id;
	char *			name;
	unsigned int		name_len;

	unsigned int		version_len;
	struct wormhole_version_atom {
		unsigned int	numeric;
		char *		string;
	}			version[WORMHOLE_CAPABILITY_VERSION_MAX];
} wormhole_capability_t;

wormhole_capability_t *
wormhole_capability_new(void)
{
	wormhole_capability_t *cap;

	cap = calloc(1, sizeof(*cap));
	return cap;
}

void
wormhole_capability_free(wormhole_capability_t *cap)
{
	unsigned int i;

	strutil_set(&cap->id, NULL);
	strutil_set(&cap->name, NULL);
	for (i = 0; i < cap->version_len; ++i)
		strutil_set(&cap->version[i].string, NULL);
	free(cap);
}

enum {
	WORMHOLE_VERSION_MISMATCH	= 0,
	WORMHOLE_VERSION_EQUAL		= 0x0001,
	WORMHOLE_VERSION_LESS_THAN	= 0x0002,
	WORMHOLE_VERSION_GREATER_THAN	= 0x0004,
};

const char *
wormhole_capability_comparison_result(int c)
{
	switch (c) {
	case WORMHOLE_VERSION_MISMATCH:
		return "mismatch";
	case WORMHOLE_VERSION_EQUAL:
		return "equal";
	case WORMHOLE_VERSION_LESS_THAN:
		return "less than";
	case WORMHOLE_VERSION_GREATER_THAN:
		return "greater than";
	}

	return "bogus result";
}

int
wormhole_capability_compare(const wormhole_capability_t *a, const wormhole_capability_t *b)
{
	unsigned int i;

	if (strcmp(a->name, b->name) != 0)
		return WORMHOLE_VERSION_MISMATCH;

	for (i = 0; i < a->version_len && i < b->version_len; ++i) {
		const struct wormhole_version_atom *atom_a, *atom_b;

		atom_a = &a->version[i];
		atom_b = &b->version[i];

		/* trace("compare %u <> %u", atom_a->numeric, atom_b->numeric); */
		if (atom_a->numeric < atom_b->numeric)
			return WORMHOLE_VERSION_LESS_THAN;
		if (atom_a->numeric > atom_b->numeric)
			return WORMHOLE_VERSION_GREATER_THAN;

		if (atom_b->string == NULL) {
			/* 15rc is less than 15 */
			if (atom_a->string != NULL)
				return WORMHOLE_VERSION_LESS_THAN;
			/* both are NULL, and hence equal */
		} else {
			int rv;

			/* 15 is greater than 15rc */
			if (atom_a->string == NULL)
				return WORMHOLE_VERSION_GREATER_THAN;

			/* if both strings are non-empty, do a lexical
			 * string compare. Which is silly, but at least it
			 * has the advantage of working with suffixes like
			 * alpha, beta, gamma, or
			 * pre, rc */
			rv = strcmp(atom_a->string, atom_b->string);
			if (rv < 0)
				return WORMHOLE_VERSION_LESS_THAN;
			else if (rv > 0)
				return WORMHOLE_VERSION_GREATER_THAN;

			/* both strings are equal */
		}
	}

	if (a->version_len < b->version_len)
		return WORMHOLE_VERSION_LESS_THAN;
	if (a->version_len > b->version_len)
		return WORMHOLE_VERSION_GREATER_THAN;
	return WORMHOLE_VERSION_EQUAL;
}

bool
wormhole_capability_is_greater_or_equal(const wormhole_capability_t *a, const wormhole_capability_t *b)
{
	int c;

	c = wormhole_capability_compare(a, b);

	// trace2("wormhole_capability_compare(%s, %s) = %s", a->id, b->id, wormhole_capability_comparison_result(c));

	return !!(c & (WORMHOLE_VERSION_EQUAL | WORMHOLE_VERSION_GREATER_THAN));
}

static bool
__wormhole_capability_parse(const char *id, wormhole_capability_t *cap)
{
	char *dash, *word, *dot;

	strutil_set(&cap->id, id);
	strutil_set(&cap->name, id);

	if ((dash = strrchr(cap->name, '-')) == NULL || !isdigit(*dash)) {
		/* This is a name without a version */
		cap->name_len = strlen(cap->name);
		return false;
	}

	*dash++ = '\0';
	cap->name_len = strlen(cap->name);

	for (word = dash; word; word = dot) {
		struct wormhole_version_atom *atom;

		if (*word == '\0')
			return false;

		if (cap->version_len >= WORMHOLE_CAPABILITY_VERSION_MAX)
			return false;
		atom = &cap->version[cap->version_len++];

		dot = strchr(word, '.');
		if (dot)
			*dot++ = '\0';

		if (isdigit(*word)) {
			char *end;

			atom->numeric = strtoul(word, &end, 10);
			strutil_set(&atom->string, end);
		} else {
			strutil_set(&atom->string, word);
		}
	}

	return true;
}

wormhole_capability_t *
wormhole_capability_parse(const char *id)
{
	wormhole_capability_t *cap;

	cap = wormhole_capability_new();
	if (!__wormhole_capability_parse(id, cap)) {
		wormhole_capability_free(cap);
		return NULL;
	}

	return cap;
}

/*
 * Install capability
 */
static bool
__wormhole_capability_register(const char *capability_dir_path, const struct strutil_array *provides, const char *path)
{
	struct strutil_array install;
	unsigned int i;
	DIR *dir;
	bool ok;

	if (!(dir = opendir(capability_dir_path))) {
		log_error("Unable to open %s: %m", capability_dir_path);
		return false;
	}

	strutil_array_init(&install);

	for (i = 0; i < provides->count; ++i) {
		const char *id = provides->data[i];
		char target[PATH_MAX];

		if (readlinkat(dirfd(dir), id, target, sizeof(target)) >= 0) {
			if (strutil_equal(path, target)) {
				trace("Capability %s already installed, nothing to activate", id);
				continue;
			}

			log_error("Capability %s already provided by %s", id, target);
			goto failed;
		}

		if (errno != ENOENT) {
			log_error("Something's wrong with %s/%s: readlink failed: %m", capability_dir_path, id);
			goto failed;
		}

		strutil_array_append(&install, id);
	}

	for (i = 0; i < install.count; ++i) {
		const char *id = install.data[i];

		trace("Install capability %s for %s", id, path);
		if (symlinkat(path, dirfd(dir), id) < 0) {
			log_error("Unable to create symbolic link %s/%s: %m", capability_dir_path, id);
			goto failed;
		}
	}

	/* All is well */
	ok = true;

failed:
	closedir(dir);
	strutil_array_destroy(&install);

	return ok;
}

bool
wormhole_capability_register(const struct strutil_array *provides, const char *path)
{
	char real_path[PATH_MAX];

	if (provides->count == 0)
		return true;

	/* Make sure we use a fully qualified path as symlink target */
	if (realpath(path, real_path) == NULL) {
		log_error("%s is not a valid path: %m", path);
		return false;
	}
	path = real_path;

	/* FIXME: support per-user capability directory. */
	return __wormhole_capability_register(WORMHOLE_CAPABILITY_PATH, provides, path);
}

bool
wormhole_command_register(const struct strutil_array *names, const char *path)
{
	char real_path[PATH_MAX];

	if (names->count == 0)
		return true;

	/* Make sure we use a fully qualified path as symlink target */
	if (realpath(path, real_path) == NULL) {
		log_error("%s is not a valid path: %m", path);
		return false;
	}
	path = real_path;

	/* FIXME: support per-user capability directory. */
	return __wormhole_capability_register(WORMHOLE_COMMAND_REGISTRY_PATH, names, path);
}

/*
 * Uninstall capability
 */
bool
__wormhole_capability_unregister(const char *capability_dir_path, const struct strutil_array *provides, const char *path)
{
	struct strutil_array remove;
	unsigned int i;
	DIR *dir;
	bool ok;

	if (!(dir = opendir(capability_dir_path))) {
		log_error("Unable to open %s: %m", capability_dir_path);
		return false;
	}

	strutil_array_init(&remove);

	for (i = 0; i < provides->count; ++i) {
		const char *id = provides->data[i];
		char target[PATH_MAX];

		if (readlinkat(dirfd(dir), id, target, sizeof(target)) < 0) {
			trace("symlink for %s does not exist, nothing to deactivate", id);
			continue;
		}

		if (!strutil_equal(path, target)) {
			trace("Capability %s refers to a different config file", id);
			continue;
		}

		strutil_array_append(&remove, id);
	}

	for (i = 0; i < remove.count; ++i) {
		const char *id = remove.data[i];

		trace("Remove capability %s for %s", id, path);
		if (unlinkat(dirfd(dir), id, 0) < 0) {
			log_error("Unable to remove symbolic link %s/%s: %m", capability_dir_path, id);
			goto failed;
		}
	}

	/* All is well */
	ok = true;

failed:
	closedir(dir);
	strutil_array_destroy(&remove);

	return ok;
}

bool
wormhole_capability_unregister(const struct strutil_array *provides, const char *path)
{
	char real_path[PATH_MAX];

	if (provides->count == 0)
		return true;

	/* Make sure we use a fully qualified path as symlink target */
	if (realpath(path, real_path) == NULL) {
		log_error("%s is not a valid path: %m", path);
		return false;
	}
	path = real_path;

	/* FIXME: support per-user capability directory. */
	return __wormhole_capability_unregister(WORMHOLE_CAPABILITY_PATH, provides, path);
}

bool
wormhole_command_unregister(const struct strutil_array *names, const char *path)
{
	char real_path[PATH_MAX];

	if (names->count == 0)
		return true;

	/* Make sure we use a fully qualified path as symlink target */
	if (realpath(path, real_path) == NULL) {
		log_error("%s is not a valid path: %m", path);
		return false;
	}
	path = real_path;

	/* FIXME: support per-user capability directory. */
	return __wormhole_capability_unregister(WORMHOLE_COMMAND_REGISTRY_PATH, names, path);
}

/*
 * Garbage collect capabilities
 */
bool
__wormhole_capabilities_gc(const char *capability_dir_path)
{
	struct strutil_array stale;
	DIR *dir;
	struct dirent *d;
	unsigned int i;
	bool ok = true;

	if (!(dir = opendir(capability_dir_path))) {
		log_error("Unable to open %s: %m", capability_dir_path);
		return false;
	}

	strutil_array_init(&stale);

	while ((d = readdir(dir)) != NULL) {
		struct stat stb;

		if (d->d_name[0] == '.')
			continue;

		/* Check whether the symlink is stale. By default, fstatat
		 * will resolve symlinks. */
		if (fstatat(dirfd(dir), d->d_name, &stb, 0) < 0)
			strutil_array_append(&stale, d->d_name);
	}

	for (i = 0; i < stale.count; ++i) {
		const char *name = stale.data[i];

		trace("Removing stale capability %s", name);
		if (unlinkat(dirfd(dir), name, 0) < 0) {
			log_error("Unable to remove stale capability link %s/%s",
					capability_dir_path, name);
			ok = false;
		}
	}

	closedir(dir);

	strutil_array_destroy(&stale);
	return ok;
}

bool
wormhole_capabilities_gc(void)
{
	/* FIXME: support per-user capability directory. */
	return __wormhole_capabilities_gc(WORMHOLE_CAPABILITY_PATH);
}

static bool
wormhole_capability_get_path(const char *capability_dir_path, char **path_var, const char *name)
{
	char pathbuf[PATH_MAX], resolved_path[PATH_MAX];

	snprintf(pathbuf, sizeof(pathbuf), "%s/%s", capability_dir_path, name);
	if (!realpath(pathbuf, resolved_path)) {
		log_warning("Dangling capability link %s", pathbuf);
		return false;
	}

	strutil_set(path_var, resolved_path);
	return true;
}

char *
__wormhole_capability_get_best_match(const char *capability_dir_path, const char *id)
{
	wormhole_capability_t *search;
	wormhole_capability_t *best_version = NULL;
	char *best_path = NULL;
	DIR *dir;
	struct dirent *d;

	if (!(search = wormhole_capability_parse(id))) {
		log_error("Unable to parse capability string \"%s\"", id);
		return NULL;
	}

	if (!(dir = opendir(capability_dir_path))) {
		log_error("Unable to open %s: %m", capability_dir_path);
		goto done;
	}

	while ((d = readdir(dir)) != NULL) {
		if (d->d_name[0] == '.')
			continue;

		if (strncmp(d->d_name, search->name, search->name_len) == 0
		 && d->d_name[search->name_len] == '-') {
			wormhole_capability_t *cap;

			/* trace("Looking at cap link %s", d->d_name); */
			/* FIXME: do we need to strip ".conf" off the end? */

			if (!(cap = wormhole_capability_parse(d->d_name)))
				continue; /* silently skip unparseable capability names in the link farm */

			if (wormhole_capability_is_greater_or_equal(cap, search)
			 && (best_version == NULL || wormhole_capability_is_greater_or_equal(cap, best_version))
			 && wormhole_capability_get_path(capability_dir_path, &best_path, d->d_name)) {
				wormhole_capability_t *tmp;

				/* We found a better match than we had before.
				 * swap cap and best_version; free previous best_version.
				 */
				tmp = best_version;
				best_version = cap;
				cap = tmp;
			}

			if (cap)
				wormhole_capability_free(cap);
		}
	}

done:
	wormhole_capability_free(search);
	if (best_version)
		wormhole_capability_free(best_version);
	if (best_path)
		trace2("Using %s to satisfy requirement %s", best_path, id);
	return best_path;
}

char *
wormhole_capability_get_best_match(const char *id)
{
	/* FIXME: support per-user capability directory. */
	return __wormhole_capability_get_best_match(WORMHOLE_CAPABILITY_PATH, id);
}

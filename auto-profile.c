/*
 * Attempt at automatic profile creation
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
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <getopt.h>
#include <dirent.h>
#include <errno.h>
#include <assert.h>

#include "tracing.h"
#include "wormhole.h"
#include "profiles.h"
#include "util.h"

struct option wormhole_options[] = {
	{ "debug",		no_argument,		NULL,	'd' },
	{ "base-environment",	required_argument,	NULL,	'B' },
	{ "overlay-root",	required_argument,	NULL,	'R' },
	{ "environment-name",	required_argument,	NULL,	'N' },
	{ "output-file",	required_argument,	NULL,	'O' },
	{ NULL }
};

const char *		opt_base_environment = NULL;
const char *		opt_overlay_root = NULL;
const char *		opt_environment_name = NULL;
const char *		opt_output = NULL;

static int		wormhole_auto_profile(const char *);

int
main(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv, "d", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'd':
			tracing_increment_level();
			break;

		case 'B':
			opt_base_environment = optarg;
			break;

		case 'R':
			opt_overlay_root = optarg;
			break;

		case 'N':
			opt_environment_name = optarg;
			break;

		case 'O':
			opt_output = optarg;
			break;

		default:
			log_error("Usage message goes here.");
			return 2;
		}
	}

	return wormhole_auto_profile(opt_overlay_root);
}

struct dir_entry {
	struct dir_entry *	next;
	char *			name;
	int			type;
	int			action;
};

#define DIR_TREE_MAX_INSPECTED	32

struct dir_tree {
	const char *		root;

	unsigned int		num_inspected;
	char *			inspected[DIR_TREE_MAX_INSPECTED];

	bool			use_ldconfig;
	struct dir_entry *	path_info;
};

static inline struct dir_entry *
dir_entry_new(const char *name, int type, int action)
{
	struct dir_entry *de;

	de = calloc(1, sizeof(*de));
	if (name != NULL)
		de->name = strdup(name);
	de->type = type;
	de->action = action;

	return de;
}

static void
dir_tree_record_inspected(struct dir_tree *tree, const char *name)
{
	assert(tree->num_inspected < DIR_TREE_MAX_INSPECTED);
	tree->inspected[tree->num_inspected++] = strdup(name);
}

static void
dir_tree_add_pathinfo(struct dir_tree *tree, const char *path, int action)
{
	struct dir_entry *de, **pos;

	/* Find end of list */
	for (pos = &tree->path_info; (de = *pos) != NULL; pos = &de->next)
		;

	de = dir_entry_new(path, -1, action);
	*pos = de;
}

struct __make_path_state {
	struct __make_path_state *parent;
	char		path_buf[8][PATH_MAX];
	unsigned int	index;
};

static struct __make_path_state top_state;
static struct __make_path_state *__make_path_state = &top_state;

static void
__make_path_push(void)
{
	struct __make_path_state *s;

	s = calloc(1, sizeof(*s));
	s->parent = __make_path_state;
	__make_path_state = s;
}

static void
__make_path_pop(void)
{
	struct __make_path_state *s = __make_path_state;

	assert(s && s != &top_state);
	__make_path_state = s->parent;

	memset(s, 0xa5, sizeof(*s));
	free(s);
}

static const char *
__make_path(const char *root_path, const char *relative_path)
{
	struct __make_path_state *s = __make_path_state;
	char *buf;

	buf = s->path_buf[s->index];
	s->index = (s->index + 1) % 8;

	while (*relative_path == '/')
		++relative_path;

	snprintf(buf, PATH_MAX, "%s/%s", root_path, relative_path);
	return buf;
}

static const char *
make_path(const struct dir_tree *tree, const char *relative_path)
{
	return __make_path(tree->root, relative_path);
}

static int
__mode_to_dir_type(mode_t mode)
{
	if (S_ISREG(mode))
		return DT_REG;
	if (S_ISDIR(mode))
		return DT_DIR;
	if (S_ISCHR(mode))
		return DT_CHR;
	if (S_ISBLK(mode))
		return DT_BLK;
	if (S_ISLNK(mode))
		return DT_LNK;
	if (S_ISSOCK(mode))
		return DT_SOCK;
	if (S_ISFIFO(mode))
		return DT_FIFO;

	return DT_UNKNOWN;
}

static int
__get_dir_type(const char *path)
{
	struct stat stb;

	if (lstat(path, &stb) < 0)
		return -1;

	return __mode_to_dir_type(stb.st_mode);
}

static bool
__exists(const char *path, int type)
{
	struct stat stb;

	if (lstat(path, &stb) < 0)
		return false;

	if (type < 0)
		return true;

	return type == __mode_to_dir_type(stb.st_mode);
}

static bool
__isdir(const char *path)
{
	return __exists(path, DT_DIR);
}

static inline bool
exists(const struct dir_tree *tree, const char *relative_path, int type)
{
	return __exists(make_path(tree, relative_path), type);
}

typedef bool	__readdir_callback_fn_t(const char *dir_path, const struct dirent *d, void *closure);

static bool
__iterate_directory(const char *dir_path, __readdir_callback_fn_t *callback, void *closure, bool suppress_errors)
{
	DIR *dirfd;
	struct dirent *d;
	bool ok = true;

	trace2("%s(%s)", __func__, dir_path);

	dirfd = opendir(dir_path);
	if (dirfd == NULL) {
		if (!suppress_errors)
			log_error("unable to open dir %s: %m", dir_path);
		ok = false;
	}

	__make_path_push();
	while (ok && (d = readdir(dirfd)) != NULL) {
		if (d->d_name[0] == '.' && (d->d_name[1] == '\0' || d->d_name[1] == '.'))
			continue;

		ok = callback(dir_path, d, closure);
	}
	__make_path_pop();

	closedir(dirfd);
	return ok;
}

/*
 * __is_empty_dir returns true iff the given path refers to a directory
 * which is either empty, or only contains directories that are empty in
 * this sense.
 */
static bool
__is_empty_callback(const char *dir_path, const struct dirent *d, void *dummy)
{
	const char *path = __make_path(dir_path, d->d_name);
	int type;

	if ((type = __get_dir_type(path)) < 0) {
		log_error("cannot stat %s: %m", path);
		return false;
	}

	if (type != DT_DIR) {
		trace2("  %s not empty - found %s", dir_path, d->d_name);
		return false;
	}

	return __iterate_directory(path, __is_empty_callback, NULL, false);
}

static bool
__is_empty_dir(const char *path)
{
	trace2("%s(%s)", __func__, path);
	return __iterate_directory(path, __is_empty_callback, NULL, false);
}

static bool
is_empty_dir(const struct dir_tree *tree, const char *relative_path)
{
	const char *path = make_path(tree, relative_path);
	int type;

	if ((type = __get_dir_type(path)) < 0) {
		if (errno == ENOENT)
			return true;

		log_error("cannot stat %s: %m", path);
		return false;
	}

	if (type != DT_DIR) {
		log_error("%s is not a directory", path);
		return false;
	}

	return __iterate_directory(path, __is_empty_callback, NULL, true);
}

/*
 * rm -rf
 */
static bool	__remove_callback(const char *dir_path, const struct dirent *d, void *dummy);

static bool
__remove(const char *path, int type)
{
	trace2("%s(%s, %d)", __func__, path, type);
	if (type < 0 || type == DT_UNKNOWN) {
		type = __get_dir_type(path);
		if (type < 0) {
			if (errno == ENOENT)
				return true;
			log_error("unable to stat %s: %m", path);
			return false;
		}
	}

	if (type != DT_DIR) {
		if (unlink(path) >= 0)
			return true;

		if (errno == ENOENT)
			return true;
	} else {
		if (rmdir(path) >= 0)
			return true;

		if (errno == ENOENT)
			return true;

		if (errno != ENOTEMPTY)
			return false;

		if (!__iterate_directory(path, __remove_callback, NULL, false))
			return false;

		if (rmdir(path) >= 0)
			return true;
	}

	log_error("unable to remove %s: %m", path);
	return false;
}

static bool
__remove_callback(const char *dir_path, const struct dirent *d, void *dummy)
{
	return __remove(__make_path(dir_path, d->d_name), d->d_type);
}

static bool
check_and_remove(const struct dir_tree *tree, const char *relative_path, int type)
{
	const char *path = make_path(tree, relative_path);

	if (!__exists(path, type))
		return false;

	__remove(path, type);
	return true;
}

static bool
__selectively_remove_callback(const char *dir_path, const struct dirent *d, void *closure)
{
	const char **list = closure;

	if (!strutil_string_in_list(d->d_name, list)) {
		log_error("Unexpected file %s/%s", dir_path, d->d_name);
		return false;
	}

	trace("(Trying to) remove %s/%s", dir_path, d->d_name);
	return __remove(__make_path(dir_path, d->d_name), -1);
}

static bool
selectively_remove(const struct dir_tree *tree, const char *relative_path, const char **name_list)
{
	return __iterate_directory(make_path(tree, relative_path), __selectively_remove_callback, name_list, false);
}

static bool
overlay_unless_empty(struct dir_tree *tree, const char *name)
{
	dir_tree_record_inspected(tree, name);

	if (is_empty_dir(tree, name))
		return true;

	dir_tree_add_pathinfo(tree, __make_path("", name), WORMHOLE_PATH_TYPE_OVERLAY);
	return true;
}

static bool
must_be_empty(struct dir_tree *tree, const char *name)
{
	dir_tree_record_inspected(tree, name);

	if (is_empty_dir(tree, name))
		return true;

	log_error("Directory /%s should be empty but is not", name);
	return false;
}

/*
 * /etc is probably the directory that's most difficult to handle, as it's the
 * one place that everyone drops their config crap into.
 *
 * We need a flexible mechanism to handle these cases (and do so automatically
 * to the largest extent possible):
 *
 *  - files and directories that belong exclusively to the application that we
 *    wrap.
 *    These should be bind mounted.
 *    (should be specified on the command line)
 *  - files that should not be there, like passwd, group etc
 *    (should be an error)
 *  - subdirectories we should ignore
 *    (built-in list + command line)
 *  - subdirectories we should overlay
 *    These would usually be directories named $foo.d that are designed as
 *    a drop-in destination, like /etc/alternatives.
 *    (built-in list + command line)
 */
static bool
check_etc_visitor(const char *dir_path, const struct dirent *d, void *closure)
{
	struct dir_tree *tree = closure;
	const char *entry_path = __make_path(dir_path, d->d_name);
	static const char *ignore_dirs[] = {
		"rc.d",
		"init.d",
		NULL,
	};
	static const char *overlay_dirs[] = {
		"alternatives",
		NULL,
	};

	if (!__isdir(entry_path)) {
		log_error("Unexpected file /etc/%s in tree", d->d_name);
		return false;
	}

	if (__is_empty_dir(entry_path))
		return true;

	if (strutil_string_in_list(d->d_name, ignore_dirs)) {
		__remove(entry_path, DT_DIR);
		return true;
	}

	if (strutil_string_in_list(d->d_name, overlay_dirs)) {
		dir_tree_add_pathinfo(tree, __make_path("/etc", d->d_name), WORMHOLE_PATH_TYPE_OVERLAY);
		return true;
	}

	log_error("Unexpected directory /etc/%s in tree", d->d_name);
	return false;
}

static bool
check_etc(struct dir_tree *tree)
{
	const char *path;
	int type;

	dir_tree_record_inspected(tree, "etc");

	if (check_and_remove(tree, "etc/ld.so.cache", DT_REG)) {
		tree->use_ldconfig = true;
	}

	path = make_path(tree, "etc");
	if ((type = __get_dir_type(path)) < 0) {
		if (errno == ENOENT)
			return true;

		log_error("cannot stat %s: %m", path);
		return false;
	}

	if (type != DT_DIR) {
		log_error("%s is not a directory", path);
		return false;
	}

	if (!__iterate_directory(path, check_etc_visitor, tree, false))
		return false;

	return true;
}

/*
 * Inspect /dev
 * Maybe we should not overlay /dev to begin with...
 */
static bool
check_dev(struct dir_tree *tree)
{
	const char *ignore_devices[] = {
		"null",
		NULL
	};
	const char *path;
	int type;

	dir_tree_record_inspected(tree, "dev");

	path = make_path(tree, "dev");
	if ((type = __get_dir_type(path)) < 0) {
		if (errno == ENOENT)
			return true;

		log_error("cannot stat %s: %m", path);
		return false;
	}

	if (type != DT_DIR) {
		log_error("%s is not a directory", path);
		return false;
	}

	if (!selectively_remove(tree, "dev", ignore_devices))
		return false;

	return true;
}

/*
 * Handle /usr
 */
static bool
check_usr(struct dir_tree *tree)
{
	/* quietly remove the RPM directory */
	(void) check_and_remove(tree, "usr/sysimage/rpm", DT_DIR);

	return overlay_unless_empty(tree, "usr");
}

/*
 * Handle /var
 */
static bool
check_var(struct dir_tree *tree)
{
	/* quietly remove some transient directories */
	(void) check_and_remove(tree, "var/cache", DT_DIR);
	(void) check_and_remove(tree, "var/lib/zypp", DT_DIR);
	(void) check_and_remove(tree, "var/lib/YaST2", DT_DIR);
	(void) check_and_remove(tree, "var/log", DT_DIR);
	(void) check_and_remove(tree, "var/run", DT_DIR);

	return overlay_unless_empty(tree, "var");
}

/*
 * Scan the root of the tree for unexpected directories
 */
bool
__check_toplevel_dir_callback(const char *dir_path, const struct dirent *d, void *closure)
{
	struct dir_tree *tree = closure;

	if (strutil_string_in_list(d->d_name, (const char **) tree->inspected))
		return true;

	log_error("%s contains unexpected top-level file or directory \"%s\"", dir_path, d->d_name);
	return false;
}

static bool
check_unknown_dirs(struct dir_tree *tree)
{
#if 0
	unsigned int i;

	printf("inspected so far:\n");
	for (i = 0; i < tree->num_inspected; ++i)
		printf("  %s\n", tree->inspected[i]);
#endif

	return __iterate_directory(tree->root, __check_toplevel_dir_callback, tree, false);
}

static const char *
pathinfo_action_to_directive(int action)
{
	switch (action) {
	case WORMHOLE_PATH_TYPE_HIDE:
		return "hide";

	case WORMHOLE_PATH_TYPE_BIND:
		return "bind";

	case WORMHOLE_PATH_TYPE_BIND_CHILDREN:
		return "bind-children";

	case WORMHOLE_PATH_TYPE_OVERLAY:
		return "overlay";

	case WORMHOLE_PATH_TYPE_OVERLAY_CHILDREN:
		return "overlay-children";

	case WORMHOLE_PATH_TYPE_WORMHOLE:
		return "wormhole";

	default:
		return NULL;
	}
}

static bool
dump_config(FILE *fp, struct dir_tree *tree, const char *env_name)
{
	struct dir_entry *de;
	bool ok = true;

	fprintf(fp, "environment %s {\n", env_name);
	fprintf(fp, "\toverlay {\n");

	fprintf(fp, "\t\tdirectory %s\n", tree->root);
	fprintf(fp, "\n");

	if (tree->use_ldconfig) {
		fprintf(fp, "\t\tuse ldconfig\n");
		fprintf(fp, "\n");
	}

	for (de = tree->path_info; de; de = de->next) {
		const char *action = pathinfo_action_to_directive(de->action);

		if (action == NULL) {
			log_error("%s: unsupported action %d", de->name, de->action);
			ok = false;
			continue;
		}

		fprintf(fp, "\t\t%s %s\n", action, de->name);
	}
	fprintf(fp, "\t}\n");
	fprintf(fp, "}\n");

	return ok;
}

int
wormhole_auto_profile(const char *root_path)
{
	struct dir_tree	tree = {
		.root = root_path,
	};
	const char *env_name;
	FILE *fp;
	int retval = 0;
	bool remove_work = false;

	if (exists(&tree, "tree", DT_DIR)
	 && exists(&tree, "work", DT_DIR)) {
		log_info("This looks like a tree created by wormhole-digger, assuming the file system root is at %s/tree", tree.root);

		tree.root = strdup(make_path(&tree, "tree"));
		remove_work = true;

		if (opt_output && !strcmp(opt_output, "auto"))
			opt_output = strdup(__make_path(root_path, "environ.conf"));
	}

	if (!check_etc(&tree))
		retval = 1;

	if (!check_dev(&tree))
		retval = 1;

	if (!must_be_empty(&tree, "boot"))
		retval = 1;

	if (!overlay_unless_empty(&tree, "bin"))
		retval = 1;

	if (!overlay_unless_empty(&tree, "sbin"))
		retval = 1;

	if (!overlay_unless_empty(&tree, "lib"))
		retval = 1;

	if (!overlay_unless_empty(&tree, "lib64"))
		retval = 1;

	if (!overlay_unless_empty(&tree, "opt"))
		retval = 1;

	if (!check_usr(&tree))
		retval = 1;

	if (!check_var(&tree))
		retval = 1;

	if (!check_unknown_dirs(&tree))
		retval = 1;

	if (retval == 0 && tree.path_info == NULL) {
		log_error("Did not find anything interesting at %s", root_path);
		retval = 2;
	}

	if (retval) {
		printf("Aborting due to errors\n");
		return retval;
	}

	if ((env_name = opt_environment_name) == NULL)
		env_name = wormhole_const_basename(root_path);

	if (opt_output != NULL) {
		if (!strcmp(opt_output, "auto"))
			log_fatal("Don't know where to write output file (you requested \"auto\" mode)");

		fp = fopen(opt_output, "w");
		if (fp == NULL)
			log_fatal("Unable to open %s for writing: %m", opt_output);

		dump_config(fp, &tree, env_name);
		fclose(fp);

		printf("Environment definition written to %s\n", opt_output);
	} else {
		dump_config(stdout, &tree, env_name);
		fflush(stdout);
	}

	if (remove_work)
		__remove(__make_path(root_path, "work"), DT_DIR);
	return retval;
}

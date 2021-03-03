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
#include <ctype.h>

#include "tracing.h"
#include "wormhole.h"
#include "profiles.h"
#include "config.h"
#include "util.h"

struct option wormhole_options[] = {
	{ "debug",		no_argument,		NULL,	'd' },
	{ "quiet",		no_argument,		NULL,	'q' },
	{ "base-environment",	required_argument,	NULL,	'B' },
	{ "overlay-root",	required_argument,	NULL,	'R' },
	{ "environment-name",	required_argument,	NULL,	'N' },
	{ "output-file",	required_argument,	NULL,	'O' },
	{ "profile",		required_argument,	NULL,	'P' },
	{ "create-exclude-list",required_argument,	NULL,	'X' },
	{ NULL }
};

const char *		opt_base_environment = NULL;
const char *		opt_overlay_root = NULL;
const char *		opt_environment_name = NULL;
const char *		opt_output = NULL;
const char *		opt_profile = "autoprofile-default.conf";
const char *		opt_exclude_file = NULL;
bool			opt_quiet = false;

static int		wormhole_auto_profile(const char *);

int
main(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv, "dq", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'd':
			tracing_increment_level();
			break;

		case 'q':
			opt_quiet = true;
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

		case 'P':
			opt_profile = optarg;
			break;

		case 'O':
			opt_output = optarg;
			break;

		case 'X':
			opt_exclude_file = optarg;
			break;

		default:
			log_error("Usage message goes here.");
			return 2;
		}
	}

	return wormhole_auto_profile(opt_overlay_root);
}

struct __make_path_state {
	struct __make_path_state *parent;
	char		path_buf[8][PATH_MAX];
	unsigned int	index;
};

static struct __make_path_state top_state;
static struct __make_path_state *__make_path_state = &top_state;

static inline void
__make_path_push(void)
{
	struct __make_path_state *s;

	s = calloc(1, sizeof(*s));
	s->parent = __make_path_state;
	__make_path_state = s;
}

static inline void
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

	case WORMHOLE_PATH_TYPE_MOUNT:
		return "mount";

	case WORMHOLE_PATH_TYPE_WORMHOLE:
		return "wormhole";

	default:
		return NULL;
	}
}

static bool
dump_config(FILE *fp, const char *env_name, struct wormhole_layer_config *output)
{
	unsigned int i;
	bool ok = true;

	fprintf(fp, "environment %s {\n", env_name);
	fprintf(fp, "\tdefine-layer {\n");

	fprintf(fp, "\t\tdirectory %s\n", output->directory);
	fprintf(fp, "\n");

	if (output->use_ldconfig) {
		fprintf(fp, "\t\tuse ldconfig\n");
		fprintf(fp, "\n");
	}

	for (i = 0; i < output->npaths; ++i) {
		struct wormhole_path_info *pi = &output->path[i];

		const char *action = pathinfo_action_to_directive(pi->type);

		if (action == NULL) {
			log_error("%s: unsupported action %d", pi->path, pi->type);
			ok = false;
			continue;
		}

		fprintf(fp, "\t\t%s %s\n", action, pi->path);
	}
	fprintf(fp, "\t}\n");
	fprintf(fp, "}\n");

	return ok;
}

static const char *
__build_path(wormhole_tree_state_t *tree, const char *path)
{
	return __make_path(wormhole_tree_state_get_root(tree), path);
}

struct wormhole_layer_config *
alloc_layer_config(const char *tree_root)
{
	struct wormhole_layer_config *layer;

	layer = calloc(1, sizeof(*layer));
	layer->directory = strdup(tree_root);
	return layer;
}

struct dir_disposition {
	bool			ignore_empty;
	bool			ignore_empty_descendants;
};

struct dir_disposition *
dir_info_new(bool ignore_empty, bool ignore_empty_descendants)
{
	struct dir_disposition *info;

	info = calloc(1, sizeof(*info));
	info->ignore_empty = ignore_empty;
	info->ignore_empty_descendants = ignore_empty_descendants;

	return info;
}

static bool
perform_optional_directory(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output)
{
	return true;
}

static bool
perform_ignore(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output)
{
	const char *path = __build_path(tree, arg);

	if (fsutil_exists(path)) {
		if (!opt_quiet)
			log_info("Actively ignoring %s", arg);
		wormhole_tree_state_set_ignore(tree, arg);
	}

	return true;
}

static bool
perform_ignore_if_empty(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output)
{
	struct dir_disposition *dir_disposition;

	/* We can't decide right away; we have to wait until we've scanned the tree.
	 * For example, we may find a file in /etc/alternatives, but still ignore
	 * /etc itself unless there's anything else in there.
	 */
	dir_disposition = dir_info_new(true, false);
	wormhole_tree_state_set_user_data(tree, arg, dir_disposition);

	return true;
}

static bool
perform_ignore_empty_subdirs(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output)
{
	struct dir_disposition *dir_disposition;

	/* We can't decide right away; we have to wait until we've scanned the tree.
	 * For example, we may find a file in /etc/alternatives, but still ignore
	 * /etc itself unless there's anything else in there.
	 */
	dir_disposition = dir_info_new(true, true);
	wormhole_tree_state_set_user_data(tree, arg, dir_disposition);

	return true;
}

static inline void
__perform_bind(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output, const char *path)
{
	if (!opt_quiet)
		log_info("Binding %s", arg);
	wormhole_layer_config_add_path(output, WORMHOLE_PATH_TYPE_BIND, arg);
	wormhole_tree_state_set_bind_mounted(tree, arg);
}

static inline void
__perform_overlay(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output, const char *path)
{
	if (!opt_quiet)
		log_info("Overlaying %s", arg);
	wormhole_layer_config_add_path(output, WORMHOLE_PATH_TYPE_OVERLAY, arg);
	wormhole_tree_state_set_overlay_mounted(tree, arg, NULL);
}

static bool
perform_overlay(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output)
{
	const char *path = __build_path(tree, arg);

	if (!fsutil_isdir(path)) {
		log_error("Asked to overlay %s, but it does not exist", arg);
		return false;
	}

	__perform_overlay(tree, arg, output, path);
	return true;
}

static bool
perform_bind(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output)
{
	const char *path = __build_path(tree, arg);

	if (!fsutil_isdir(path)) {
		log_error("Asked to bind %s, but it does not exist", arg);
		return false;
	}

	__perform_bind(tree, arg, output, path);
	return true;
}

static inline bool
__is_empty(wormhole_tree_state_t *tree, const char *arg, const char *path)
{
	if (!fsutil_isdir(path))
		return true;

	if (fsutil_dir_is_empty(path)) {
		if (!opt_quiet)
			log_info("Ignoring empty directory %s", arg);
		wormhole_tree_state_set_ignore(tree, arg);
		return true;
	}

	return false;
}

static bool
perform_overlay_unless_empty(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output)
{
	const char *path = __build_path(tree, arg);

	if (!__is_empty(tree, arg, path))
		__perform_overlay(tree, arg, output, path);

	return true;
}

static bool
perform_bind_unless_empty(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output)
{
	const char *path = __build_path(tree, arg);

	if (!__is_empty(tree, arg, path))
		__perform_bind(tree, arg, output, path);

	return true;
}

static bool
perform_must_be_empty(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output)
{
	const char *path = __build_path(tree, arg);

	if (!fsutil_isdir(path))
		return true;

	if (fsutil_dir_is_empty(path)) {
		if (!opt_quiet)
			log_info("Ignoring empty directory %s", arg);
		wormhole_tree_state_set_ignore(tree, arg);
	} else {
		log_error("%s exists but is not empty. Adjust your config.", arg);
		return false;
	}

	return true;
}

static bool
perform_check_ldconfig(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output)
{
	const char *path;

	if (arg == NULL)
		arg = "/etc/ld.so.cache";
	path = __build_path(tree, arg);

	if (fsutil_exists(path)) {
		if (!opt_quiet)
			log_info("Found %s, configuring layer to use ldconfig", arg);
		wormhole_tree_state_set_ignore(tree, arg);
		output->use_ldconfig = true;
	}
	return true;
}

struct action {
	struct action *	next;

	unsigned int	line;
	char *		arg;
	bool		(*perform)(wormhole_tree_state_t *tree, const char *arg, struct wormhole_layer_config *output);
};

static struct action *
action_new(const char *arg)
{
	struct action *a;

	a = calloc(1, sizeof(*a));
	if (arg)
		a->arg = strdup(arg);
	return a;
}

static void
action_free(struct action *a)
{
	if (a->arg)
		free(a->arg);
	free(a);
}

struct autoprofile_config {
	char *		filename;
	struct action *	actions;
};

struct autoprofile_config *
autoprofile_config_new(const char *filename)
{
	struct autoprofile_config *config;

	config = calloc(1, sizeof(*config));
	config->filename = strdup(filename);
	return config;
}

void
autoprofile_config_free(struct autoprofile_config *config)
{
	struct action *a;

	while ((a = config->actions) != NULL) {
		config->actions = a->next;
		action_free(a);
	}

	if (config->filename)
		free(config->filename);

	free(config);
}

struct autoprofile_config *
load_autoprofile_config(const char *filename)
{
	struct autoprofile_config *config;
	struct action **pos;
	FILE *fp;
	char linebuf[1024];
	unsigned int lineno = 0;

	if (!(fp = fopen(filename, "r"))) {
		log_error("Cannot open config file %s: %m", filename);
		return NULL;
	}

	config = autoprofile_config_new(filename);
	pos = &config->actions;

	while ((fgets(linebuf, sizeof(linebuf), fp)) != NULL) {
		char *s, *kwd, *arg;
		struct action *a;

		linebuf[strcspn(linebuf, "\r\n")] = '\0';
		lineno++;

		for (s = linebuf; isspace(*s); ++s)
			;

		if (*s == '#' || *s == '\0')
			continue;

		kwd = strtok(s, " \t");
		if (!kwd)
			continue;

		arg = strtok(NULL, " \t");

		a = *pos = action_new(arg);
		pos = &a->next;

		if (!strcmp(kwd, "optional-directory")) {
			a->perform = perform_optional_directory;
		} else
		if (!strcmp(kwd, "overlay")) {
			a->perform = perform_overlay;
		} else
		if (!strcmp(kwd, "overlay-unless-empty")) {
			a->perform = perform_overlay_unless_empty;
		} else
		if (!strcmp(kwd, "bind")) {
			a->perform = perform_bind;
		} else
		if (!strcmp(kwd, "bind-unless-empty")) {
			a->perform = perform_bind_unless_empty;
		} else
		if (!strcmp(kwd, "must-be-empty")) {
			a->perform = perform_must_be_empty;
		} else
		if (!strcmp(kwd, "check-ldconfig")) {
			a->perform = perform_check_ldconfig;
		} else
		if (!strcmp(kwd, "ignore-if-empty")) {
			a->perform = perform_ignore_if_empty;
		} else
		if (!strcmp(kwd, "ignore-empty-subdirs")) {
			a->perform = perform_ignore_empty_subdirs;
		} else
		if (!strcmp(kwd, "ignore")) {
			a->perform = perform_ignore;
		} else {
			log_error("%s line %u: unknown keyword \"%s\"", filename, lineno, kwd);
			goto failed;
		}

		a->line = lineno;
	}

	fclose(fp);
	return config;

failed:
	autoprofile_config_free(config);
	fclose(fp);
	return NULL;
}

static bool
perform(struct autoprofile_config *config, wormhole_tree_state_t *tree, struct wormhole_layer_config *output)
{
	struct action *a;

	for (a = config->actions; a; a = a->next) {
		if (!a->perform(tree, a->arg, output)) {
			log_error("Error when executing autoprofile statement (%s:%u)", config->filename, a->line);
			return false;
		}
	}

	return true;
}

struct stray_dir_level {
	struct stray_dir_level *parent;

	struct dir_disposition	disposition;
	unsigned int		stray_count;
	unsigned int		stray_children;
};

struct stray_state {
	const char *		tree_root;
	unsigned int		tree_root_len;
	wormhole_tree_state_t *	tree;

	struct stray_dir_level *current;

	unsigned int		stray_count;
};

static inline void
__stray_count(struct stray_state *state, const char *d_path, int d_type)
{
	if (state->stray_count < 100)
		log_error("Stray %s: %s", (d_type == DT_DIR)? "directory" : "file", d_path);
	state->stray_count += 1;

	if (state->current) {
		state->current->stray_count += 1;
		state->current->stray_children += 1;
	}
}

static struct stray_dir_level *
__stray_enter_directory(struct stray_state *state)
{
	struct stray_dir_level *dir;

	dir = calloc(1, sizeof(*dir));
	dir->parent = state->current;
	state->current = dir;

	/* Inherit disposition from parent */
	if (dir->parent) {
		struct dir_disposition *dist = &dir->parent->disposition;

		if (dist->ignore_empty_descendants) {
			dir->disposition.ignore_empty = true;
			dir->disposition.ignore_empty_descendants = true;
		}
	}

	return dir;
}

static struct stray_dir_level *
__stray_leave_directory(struct stray_state *state)
{
	static struct stray_dir_level ret_dir;
	struct stray_dir_level *dir = state->current;

	if (dir == NULL)
		return NULL;

	state->current = dir->parent;
	dir->parent = NULL;

	/* percolate up the stray count */
	if (state->current)
		state->current->stray_count += dir->stray_count;
	else
		state->stray_count += dir->stray_count;

	ret_dir = *dir;
	free(dir);

	return &ret_dir;
}

static int
__check_for_stray_files_visitor(const char *dir_path, const struct dirent *d, int cbflags, void *closure)
{
	struct stray_state *state = (struct stray_state *) closure;
	const wormhole_path_state_t *path_state;
	const char *d_path;

	d_path = __make_path(dir_path, d->d_name);
	d_path += state->tree_root_len;

	path_state = wormhole_path_tree_get(state->tree, d_path);

	if (path_state && path_state->state != WORMHOLE_PATH_STATE_UNCHANGED)
		return FTW_SKIP;

	if (cbflags & FSUTIL_FTW_PRE_DESCENT) {
		struct stray_dir_level *dir;

		dir = __stray_enter_directory(state);
		if (path_state && path_state->user_data) {
			struct dir_disposition *disp = path_state->user_data;

			/* stick it into state->current */
			if (disp->ignore_empty)
				dir->disposition.ignore_empty = true;
			if (disp->ignore_empty_descendants) {
				dir->disposition.ignore_empty = true;
				dir->disposition.ignore_empty_descendants = true;
			}
		}
		return FTW_CONTINUE;
	}

	if (d->d_type != DT_DIR) {
		__stray_count(state, d_path, d->d_type);
		return FTW_CONTINUE;
	}

	if (cbflags & FSUTIL_FTW_POST_DESCENT) {
		struct stray_dir_level *dir = __stray_leave_directory(state);

		if (dir->stray_count == 0 && dir->disposition.ignore_empty_descendants) {
			if (!opt_quiet)
				log_info("Ignoring empty directory %s", d_path);
			wormhole_tree_state_set_ignore(state->tree, d_path);
			return FTW_CONTINUE;
		}
		if (dir->stray_children == 0 && dir->disposition.ignore_empty) {
			if (!opt_quiet)
				log_info("Ignoring empty directory %s", d_path);
			wormhole_tree_state_set_ignore(state->tree, d_path);
			return FTW_CONTINUE;
		}
		if (dir->stray_children + dir->stray_count)
			if (!opt_quiet)
				log_info("%s has %u children, %u descendants total", d_path, dir->stray_children, dir->stray_count);
	}

	__stray_count(state, d_path, d->d_type);
	return FTW_CONTINUE;
}

static bool
check_for_stray_files(wormhole_tree_state_t *tree)
{
	struct stray_state state = { NULL, };
	const char *tree_root = wormhole_tree_state_get_root(tree);

	memset(&state, 0, sizeof(state));
	state.tree_root = tree_root;
	state.tree_root_len = strlen(tree_root);
	state.tree = tree;

	if (!fsutil_ftw(tree_root, __check_for_stray_files_visitor, &state, FSUTIL_FTW_PRE_POST_CALLBACK | FSUTIL_FTW_ONE_FILESYSTEM))
		return false;

	if (state.stray_count != 0) {
		log_error("Found %u stray files or directories", state.stray_count);
		return false;
	}

	return true;
}

static bool
write_exclude_file(const char *exclude_file, wormhole_tree_state_t *tree)
{
	wormhole_tree_walker_t *walk;
	wormhole_path_state_t *ps;
	const char *path;
	FILE *fp;

	if (!strcmp(exclude_file, "-"))
		fp = stdout;
	else if (!(fp = fopen(exclude_file, "w"))) {
		log_error("Cannot open %s for writing: %m", exclude_file);
		return false;
	}

	walk = wormhole_tree_walk(tree);
	while ((ps = wormhole_tree_walk_next(walk, &path)) != NULL) {
		if (ps->state == WORMHOLE_PATH_STATE_IGNORED)
			fprintf(fp, "%s\n", path);
	}

	wormhole_tree_walk_end(walk);

	if (fp != stdout)
		fclose(fp);

	return true;
}

int
wormhole_auto_profile(const char *root_path)
{
	const char *subdir;
	const char *tree_root, *output_tree_root;
	const char *env_name;
	FILE *fp;
	int retval = 0;
	struct autoprofile_config *config;
	wormhole_tree_state_t *real_tree;
	struct wormhole_layer_config *output;

	tree_root = root_path;
	output_tree_root = root_path;

	subdir = __make_path(root_path, "tree");
	if (fsutil_isdir(subdir)) {
		if (!opt_quiet)
			log_info("This looks like a tree created by wormhole-digger, assuming the file system root is at %s", subdir);

		tree_root = strdup(subdir);

		if (opt_output && !strcmp(opt_output, "auto")) {
			opt_output = strdup(__make_path(root_path, "environ.conf"));
			output_tree_root = "tree";
		}
	}

	real_tree = wormhole_tree_state_new();
	wormhole_tree_state_set_root(real_tree, tree_root);

	config = load_autoprofile_config(opt_profile);
	if (config == NULL)
		return 1;

	output = alloc_layer_config(output_tree_root);

	if (!perform(config, real_tree, output))
		return 1;

	if (!check_for_stray_files(real_tree))
		return 1;

	if ((env_name = opt_environment_name) == NULL)
		env_name = wormhole_const_basename(root_path);

	if (opt_output != NULL && strcmp(opt_output, "-")) {
		if (!strcmp(opt_output, "auto"))
			log_fatal("Don't know where to write output file (you requested \"auto\" mode)");

		fp = fopen(opt_output, "w");
		if (fp == NULL)
			log_fatal("Unable to open %s for writing: %m", opt_output);

		dump_config(fp, env_name,  output);
		fclose(fp);

		printf("Environment definition written to %s\n", opt_output);
	} else {
		dump_config(stdout, env_name,  output);
		fflush(stdout);
	}

	if (opt_exclude_file)
		write_exclude_file(opt_exclude_file, real_tree);

	return retval;
}

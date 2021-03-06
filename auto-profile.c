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

enum {
	OPT_BASE_ENVIRONMENT,
	OPT_OVERLAY_ROOT,
	OPT_ENVIRONMENT_NAME,
	OPT_OUTPUT_FILE,
	OPT_PROFILE,
	OPT_REQUIRES,
	OPT_PROVIDES,
	OPT_CHECK_BINARIES,
	OPT_WRAPPER_DIRECTORY,
};

struct option wormhole_options[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "debug",		no_argument,		NULL,	'd' },
	{ "quiet",		no_argument,		NULL,	'q' },
	{ "base-environment",	required_argument,	NULL,	OPT_BASE_ENVIRONMENT },
	{ "overlay-root",	required_argument,	NULL,	OPT_OVERLAY_ROOT },
	{ "overlay-directory",	required_argument,	NULL,	OPT_OVERLAY_ROOT },
	{ "environment-name",	required_argument,	NULL,	OPT_ENVIRONMENT_NAME },
	{ "output-file",	required_argument,	NULL,	OPT_OUTPUT_FILE },
	{ "profile",		required_argument,	NULL,	OPT_PROFILE },
	{ "requires",		required_argument,	NULL,	OPT_REQUIRES },
	{ "provides",		required_argument,	NULL,	OPT_PROVIDES },
	{ "wrapper-directory",	required_argument,	NULL,	OPT_WRAPPER_DIRECTORY },
	{ "check-binaries",	required_argument,	NULL,	OPT_CHECK_BINARIES },

	/* obsolete/internal */
	{ "create-exclude-list",required_argument,	NULL,	'X' },
	{ NULL }
};

const char *		opt_base_environment = NULL;
const char *		opt_overlay_root = NULL;
const char *		opt_environment_name = NULL;
const char *		opt_output = NULL;
const char *		opt_profile = "default";
const char *		opt_exclude_file = NULL;
const char *		opt_wrapper_directory = NULL;
struct strutil_array	opt_check_binaries;
bool			opt_quiet = false;
struct strutil_array	opt_provides;
struct strutil_array	opt_requires;

static int		wormhole_auto_profile(const char *);
static void		usage(int exval);

struct autoprofile_state {
	wormhole_tree_state_t *		tree;

	struct wormhole_config *	config;
	struct wormhole_layer_config *	_layer;
};

int
main(int argc, char **argv)
{
	int c;

	while ((c = getopt_long(argc, argv, "dhq", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'h':
			usage(0);

		case 'd':
			tracing_increment_level();
			break;

		case 'q':
			opt_quiet = true;
			break;

		case OPT_BASE_ENVIRONMENT:
			opt_base_environment = optarg;
			break;

		case OPT_OVERLAY_ROOT:
			opt_overlay_root = optarg;
			break;

		case OPT_ENVIRONMENT_NAME:
			opt_environment_name = optarg;
			break;

		case OPT_PROFILE:
			opt_profile = optarg;
			break;

		case OPT_REQUIRES:
			strutil_array_append(&opt_requires, optarg);
			break;

		case OPT_PROVIDES:
			strutil_array_append(&opt_provides, optarg);
			break;

		case OPT_OUTPUT_FILE:
			opt_output = optarg;
			break;

		case OPT_WRAPPER_DIRECTORY:
			opt_wrapper_directory = optarg;
			break;

		case OPT_CHECK_BINARIES:
			strutil_array_append(&opt_check_binaries, optarg);
			break;

		case 'X':
			opt_exclude_file = optarg;
			break;

		default:
			log_error("Error parsing command line");
			usage(2);
		}
	}

	return wormhole_auto_profile(opt_overlay_root);
}

void
usage(int exval)
{
	FILE *f = exval? stderr : stdout;

	fprintf(f,
		"Usage:\n"
		"wormhole-autoprofile [options]\n"
		"  --help, -h\n"
		"     Display this help message\n"
		"  --debug, -d\n"
		"     Increase debugging verbosity\n"
		"  --quiet, -q\n"
		"     Suppress progress messages\n"
		"  --overlay-directory <dirname>\n"
		"     Specify directory containing the overlay tree.\n"
		"  --output-file <path>\n"
		"     Location to write the configuration file to (or \"auto\")\n"
		"  --base-environment <name>\n"
		"     The wormhole image/environment the new layer was based on\n"
		"  --environment-name <name>\n"
		"     Name of the environment to define (defaults to base name of --overlay-directory)\n"
		"  --requires <id>\n"
		"     Capability string will be copied to the generated config file\n"
		"  --provides <id>\n"
		"     Capability string will be copied to the generated config file\n"
		"  --check-binaries <path>\n"
		"     In addition to any directories listed in the profile, inspect the indicated path for executables\n"
		"  --wrapper-directory <path>\n"
		"     When auto-detecting executables, wrappers should be placed in the specified directory\n"
	);
	exit(exval);
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

static bool
try_read_digger_config(struct autoprofile_state *state, const char *base_dir)
{
	const char *digger_conf_path, *tree_root, *relative_tree_root;
	struct wormhole_config *cfg;

	digger_conf_path = __make_path(base_dir, ".digger.conf");
	if (!fsutil_exists(digger_conf_path))
		return true;

	if (!opt_quiet)
		log_info("This looks like a tree created by wormhole-digger");

	if (!(cfg = wormhole_config_load(digger_conf_path))) {
		log_error("Unable to read digger config file %s", digger_conf_path);
		return false;
	}

	if (!cfg->environments || cfg->environments->next) {
		log_error("%s: should contain exactly one environment", digger_conf_path);
		return false;
	}

	state->_layer = cfg->environments->layers;
	if (!state->_layer || state->_layer->next) {
		log_error("%s: should contain exactly one layer", digger_conf_path);
		return false;
	}

	tree_root = state->_layer->directory;
	if (tree_root == NULL) {
		log_error("%s: layer does not specify a directory", digger_conf_path);
		return false;
	}

	trace("%s: root is %s", __func__, tree_root);
	wormhole_tree_state_set_root(state->tree, tree_root);

	/* Usually, wormhole-digger will create the directory tree as $base_dir/tree;
	 * we would like to refer to the relative name (ie "tree") in the config file.
	 */
	if ((relative_tree_root = fsutil_strip_path_prefix(tree_root, base_dir)) != NULL) {
		while (*relative_tree_root == '/')
			++relative_tree_root;
		strutil_set(&state->_layer->directory, relative_tree_root);
	}

	/* Override the path that the config should be written to */
	if (strutil_equal(opt_output, "auto"))
		strutil_set(&cfg->path, __make_path(base_dir, "environ.conf"));
	else
		strutil_set(&cfg->path, opt_output);

	state->config = cfg;

#if 0
	subdir = __make_path(root_path, "tree");
	if (fsutil_isdir(subdir)) {
		if (!opt_quiet)
			log_info("This looks like a tree created by wormhole-digger, assuming the file system root is at %s", subdir);

		tree_root = strdup(subdir);

		if (opt_output && !strcmp(opt_output, "auto")) {
			opt_output = strdup(__make_path(root_path, "environ.conf"));
			output_tree_root = "tree";
		} else {
			output_tree_root = strdup(subdir);
		}
	}
#endif
	return true;
}

static void	autoprofile_state_set_environment(struct autoprofile_state *state, const char *name);
static void	autoprofile_state_create_layer(struct autoprofile_state *state, const char *root_directory);

bool
autoprofile_state_init(struct autoprofile_state *state, const char *tree_root)
{
	struct wormhole_config *config;

	memset(state, 0, sizeof(*state));

	state->tree = wormhole_tree_state_new();
	wormhole_tree_state_set_root(state->tree, tree_root);

	if (!try_read_digger_config(state, tree_root)) {
		log_error("bad overlay tree at %s", tree_root);
		return false;
	}

	if (state->config != NULL)
		return true; /* try_read_digger_config actually did read something */

	/* If the output tree is not under $tree_root/tree, then
	 * an output filename of "auto" does not make sense.
	 */
	if (strutil_equal(opt_output, "auto")) {
		log_error("Cannot determine path of output file (you requested \"auto\" mode)");
		return false;
	}

	config = calloc(1, sizeof(*config));
	strutil_set(&config->path, opt_output);
	state->config = config;

	autoprofile_state_set_environment(state, pathutil_const_basename(tree_root));
	autoprofile_state_create_layer(state, tree_root);

	return true;
}

void
autoprofile_state_set_environment(struct autoprofile_state *state, const char *name)
{
	struct wormhole_environment_config *env;

	if ((env = state->config->environments) == NULL) {
		env = calloc(1, sizeof(*env));
		state->config->environments = env;
	}

	strutil_set(&env->name, name);
}

static inline const char *
autoprofile_state_environment_name(const struct autoprofile_state *state)
{
	assert(state->config && state->config->environments);
	return state->config->environments->name;
}

void
autoprofile_state_set_requires(struct autoprofile_state *state, const struct strutil_array *names)
{
	struct wormhole_environment_config *env = state->config->environments;

	assert(env);
	strutil_array_append_array(&env->requires, names);
}

void
autoprofile_state_set_provides(struct autoprofile_state *state, const struct strutil_array *names)
{
	struct wormhole_environment_config *env = state->config->environments;

	assert(env);
	strutil_array_append_array(&env->provides, names);
}

void
autoprofile_state_create_layer(struct autoprofile_state *state, const char *root_directory)
{
	struct wormhole_environment_config *env = state->config->environments;
	struct wormhole_layer_config *layer;

	assert(env->layers == NULL);

	layer = calloc(1, sizeof(*layer));
	strutil_set(&layer->directory, root_directory);

	state->_layer = layer;
	env->layers = layer;
}

static inline struct wormhole_layer_config *
autoprofile_state_get_layer(const struct autoprofile_state *state)
{
	assert(state->_layer);
	return state->_layer;
}

static const char *
__build_path(wormhole_tree_state_t *tree, const char *path)
{
	return __make_path(wormhole_tree_state_get_root(tree), path);
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
perform_optional_directory(struct autoprofile_state *state, const char *arg)
{
	return true;
}

static bool
perform_ignore(struct autoprofile_state *state, const char *arg)
{
	wormhole_tree_state_t *tree = state->tree;
	const char *path = __build_path(tree, arg);

	if (fsutil_exists_nofollow(path)) {
		if (!opt_quiet)
			log_info("Actively ignoring %s", arg);
		wormhole_tree_state_set_ignore(tree, arg);
	}

	return true;
}

static bool
perform_ignore_if_empty(struct autoprofile_state *state, const char *arg)
{
	wormhole_tree_state_t *tree = state->tree;
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
perform_ignore_empty_subdirs(struct autoprofile_state *state, const char *arg)
{
	wormhole_tree_state_t *tree = state->tree;
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
perform_overlay(struct autoprofile_state *state, const char *arg)
{
	struct wormhole_layer_config *layer = autoprofile_state_get_layer(state);
	wormhole_tree_state_t *tree = state->tree;
	const char *path = __build_path(tree, arg);

	if (!fsutil_isdir(path)) {
		log_error("Asked to overlay %s, but it does not exist", arg);
		return false;
	}

	__perform_overlay(tree, arg, layer, path);
	return true;
}

static bool
perform_bind(struct autoprofile_state *state, const char *arg)
{
	struct wormhole_layer_config *layer = autoprofile_state_get_layer(state);
	wormhole_tree_state_t *tree = state->tree;
	const char *path = __build_path(tree, arg);

	if (!fsutil_isdir(path)) {
		log_error("Asked to bind %s, but it does not exist", arg);
		return false;
	}

	__perform_bind(tree, arg, layer, path);
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
perform_overlay_unless_empty(struct autoprofile_state *state, const char *arg)
{
	struct wormhole_layer_config *layer = autoprofile_state_get_layer(state);
	wormhole_tree_state_t *tree = state->tree;
	const char *path = __build_path(tree, arg);

	if (!__is_empty(tree, arg, path))
		__perform_overlay(tree, arg, layer, path);

	return true;
}

static bool
perform_bind_unless_empty(struct autoprofile_state *state, const char *arg)
{
	struct wormhole_layer_config *layer = autoprofile_state_get_layer(state);
	wormhole_tree_state_t *tree = state->tree;
	const char *path = __build_path(tree, arg);

	if (!__is_empty(tree, arg, path))
		__perform_bind(tree, arg, layer, path);

	return true;
}

static bool
perform_must_be_empty(struct autoprofile_state *state, const char *arg)
{
	wormhole_tree_state_t *tree = state->tree;
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
perform_check_ldconfig(struct autoprofile_state *state, const char *arg)
{
	struct wormhole_layer_config *layer = autoprofile_state_get_layer(state);
	wormhole_tree_state_t *tree = state->tree;
	const char *path;

	if (arg == NULL)
		arg = "/etc/ld.so.cache";
	path = __build_path(tree, arg);

	if (fsutil_exists(path)) {
		if (!opt_quiet)
			log_info("Found %s, configuring layer to use ldconfig", arg);
		wormhole_tree_state_set_ignore(tree, arg);
		layer->use_ldconfig = true;
	}
	return true;
}

static bool
perform_mount_tmpfs(struct autoprofile_state *state, const char *arg)
{
	struct wormhole_layer_config *layer = autoprofile_state_get_layer(state);
	wormhole_tree_state_t *tree = state->tree;
	const char *path = __build_path(tree, arg);
	wormhole_path_info_t *pi;

	if (!fsutil_isdir(path))
		return true;

	if (!opt_quiet)
		log_info("Mounting tmpfs on %s", arg);

	pi = wormhole_layer_config_add_path(layer, WORMHOLE_PATH_TYPE_MOUNT, arg);
	wormhole_path_info_set_mount_fstype(pi, "tmpfs");
	wormhole_tree_state_set_system_mount(tree, arg, "tmpfs", NULL);

	return true;
}

static bool
perform_check_binaries(struct autoprofile_state *state, const char *arg)
{
	wormhole_tree_state_t *tree = state->tree;
	const char *path = __build_path(tree, arg);
	DIR *dir;
	struct dirent *d;

	if (!opt_wrapper_directory)
		return true;

	if (!(dir = opendir(path)))
		return true;

	__make_path_push();
	while ((d = readdir(dir)) != NULL) {
		struct wormhole_profile_config *profile;
		char entry_path[PATH_MAX];

		if (d->d_name[0] == '.')
			continue;

		snprintf(entry_path, sizeof(entry_path), "%s/%s", arg, d->d_name);
		if (!fsutil_is_executable(__build_path(tree, entry_path)))
			continue;

		trace("Found binary %s", entry_path);

		profile = calloc(1, sizeof(*profile));
		strutil_set(&profile->name, d->d_name);
		strutil_set(&profile->command, entry_path);
		strutil_set(&profile->environment, autoprofile_state_environment_name(state));
		strutil_set(&profile->wrapper, __make_path(opt_wrapper_directory, d->d_name));

		profile->next = state->config->profiles;
		state->config->profiles = profile;
	}
	__make_path_pop();

	closedir(dir);

	return true;
}

struct action {
	struct action *	next;

	unsigned int	line;
	char *		arg;
	bool		(*perform)(struct autoprofile_state *state, const char *arg);
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
	int		env_type;
	bool		ignore_stray_files;

	struct action *	actions;
	struct action **action_tail;
};

struct autoprofile_config *
autoprofile_config_new(const char *filename)
{
	struct autoprofile_config *config;

	config = calloc(1, sizeof(*config));
	config->filename = strdup(filename);
	config->env_type = WORMHOLE_LAYER_TYPE_LAYER;

	config->action_tail = &config->actions;
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

static struct action *
__autoprofile_add_action(struct autoprofile_config *config, unsigned int lineno,
		const char *arg, bool (*perform)(struct autoprofile_state *state, const char *arg))
{
	struct action *a;

	a = action_new(arg);
	a->line = lineno;
	a->perform = perform;

	*(config->action_tail) = a;
	config->action_tail = &a->next;

	return a;
}

struct autoprofile_config *
load_autoprofile_config(const char *profile, const struct strutil_array *extra_check_binaries)
{
	static struct action_keyword {
		const char *		name;
		bool			(*perform)(struct autoprofile_state *state, const char *arg);
	} action_keywords[] = {
		{ "optional-directory",		perform_optional_directory },
		{ "overlay",			perform_overlay },
		{ "overlay-unless-empty",	perform_overlay_unless_empty },
		{ "bind",			perform_bind },
		{ "bind-unless-empty",		perform_bind_unless_empty },
		{ "must-be-empty",		perform_must_be_empty },
		{ "check-ldconfig",		perform_check_ldconfig },
		{ "ignore-if-empty",		perform_ignore_if_empty },
		{ "ignore-empty-subdirs",	perform_ignore_empty_subdirs },
		{ "ignore",			perform_ignore },
		{ "mount-tmpfs",		perform_mount_tmpfs },
		{ "check-binaries",		perform_check_binaries },
		{ NULL }
	};
	const char *filename;
	struct autoprofile_config *config;
	FILE *fp;
	char pathbuf[PATH_MAX];
	char linebuf[1024];
	unsigned int lineno = 0;


	if (strchr(profile, '/') != NULL) {
		filename = profile;
	} else {
		snprintf(pathbuf, sizeof(pathbuf), "%s/autoprofile-%s.conf", WORMHOLE_AUTOPROFILE_DIR_PATH, profile);
		filename = pathbuf;
	}

	if (!(fp = fopen(filename, "r"))) {
		log_error("Cannot open config file %s: %m", filename);
		return NULL;
	}

	config = autoprofile_config_new(filename);

	while ((fgets(linebuf, sizeof(linebuf), fp)) != NULL) {
		char *s, *kwd, *arg;

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

		if (strutil_equal(kwd, "ignore") && strutil_equal(arg, "strays")) {
			config->ignore_stray_files = true;
			continue;
		}

		if (!strcmp(kwd, "environment-type")) {
			if (!strcmp(arg, "image")) {
				config->env_type = WORMHOLE_LAYER_TYPE_IMAGE;
			} else if (!strcmp(arg, "layer")) {
				config->env_type = WORMHOLE_LAYER_TYPE_LAYER;
			} else {
				log_error("%s line %u: bad %s \"%s\"", filename, lineno, kwd, arg);
				goto failed;
			}
			continue;
		} else {
			struct action_keyword *akw;

			for (akw = action_keywords; akw->name; ++akw) {
				if (!strcmp(akw->name, kwd))
					break;
			}

			if (akw->perform == NULL) {
				log_error("%s line %u: unknown keyword \"%s\"", filename, lineno, kwd);
				goto failed;
			}

			__autoprofile_add_action(config, lineno, arg, akw->perform);
		}
	}

	fclose(fp);

	if (extra_check_binaries) {
		unsigned int i;

		for (i = 0; i < extra_check_binaries->count; ++i) {
			const char *path = extra_check_binaries->data[i];

			__autoprofile_add_action(config, 0, path, perform_check_binaries);
		}
	}

	return config;

failed:
	autoprofile_config_free(config);
	fclose(fp);
	return NULL;
}

static bool
autoprofile_process(struct autoprofile_config *config, struct autoprofile_state *state)
{
	struct wormhole_layer_config *layer = autoprofile_state_get_layer(state);
	struct action *a;

	for (a = config->actions; a; a = a->next) {
		if (!a->perform(state, a->arg)) {
			log_error("Error when executing autoprofile statement (%s:%u)", config->filename, a->line);
			return false;
		}
	}

	layer->type = config->env_type;
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
	struct autoprofile_config *config;
	struct autoprofile_state state;

	if (opt_base_environment)
		log_fatal("The --base-environment option is not yet implemented");

	if (!autoprofile_state_init(&state, root_path))
		return 1;


	config = load_autoprofile_config(opt_profile, &opt_check_binaries);
	if (config == NULL)
		return 1;

	if (opt_environment_name)
		autoprofile_state_set_environment(&state, opt_environment_name);

	autoprofile_state_set_requires(&state, &opt_requires);
	autoprofile_state_set_provides(&state, &opt_provides);

	if (!autoprofile_process(config, &state))
		return 1;

	if (!config->ignore_stray_files) {
		if (!check_for_stray_files(state.tree))
			return 1;
	}

	if (!opt_quiet && state.config->path)
		log_info("Writing configuration file to %s", state.config->path);
	if (!wormhole_config_write(state.config, state.config->path))
		return 1;

	if (opt_exclude_file)
		write_exclude_file(opt_exclude_file, state.tree);

	return 0;
}

/*
 * wormhole config file parsing
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

struct parser_state {
	struct parser_state *	included_from;
	const char *		filename;
	unsigned int		lineno;
	bool			failed;

	FILE *			fp;

	char			buffer[1024];
	char *			pos;
};

struct parser_obsolete_kwd {
	const char *		old_keyword;
	const char *		new_keyword;
	bool			warned;
};

static bool		parser_open(struct parser_state *ps, const char *filename, struct parser_state *included_from);
static void		parser_close(struct parser_state *ps);
static bool		parser_next_line(struct parser_state *ps);
static const char *	parser_next_word(struct parser_state *ps);
static bool		parser_expect_end_of_line(struct parser_state *ps, const char *keyword);
static void		parser_error(struct parser_state *, const char *, ...);
static void		parser_warning(struct parser_state *, const char *, ...);
static const char *	parser_check_obsolete_keyword(struct parser_state *, const char *kwd, struct parser_obsolete_kwd *);

static struct wormhole_config *__wormhole_config_new(void);

static bool		wormhole_config_process_file(struct wormhole_config *cfg, const char *filename, struct parser_state *included_from);
static bool		wormhole_config_process_include(struct wormhole_config *cfg, struct parser_state *included_from);
static bool		wormhole_config_process_profile(struct wormhole_config *cfg, struct parser_state *ps);
static bool		wormhole_config_process_environment(struct wormhole_config *cfg, struct parser_state *ps);
static bool		__wormhole_config_process_string(const char *keyword, char **var, struct parser_state *ps);

static void		wormhole_profile_config_free(struct wormhole_profile_config *profile);
static void		wormhole_environment_config_free(struct wormhole_environment_config *env);


struct wormhole_config *
wormhole_config_load(const char *filename)
{
	struct wormhole_config *cfg;

	cfg = __wormhole_config_new();
	if (!wormhole_config_process_file(cfg, filename, NULL)) {
		wormhole_config_free(cfg);
		return NULL;
	}

	return cfg;
}

/*
 * toplevel config object
 */
static struct wormhole_config *
__wormhole_config_new(void)
{
	struct wormhole_config *cfg;

	cfg = calloc(1, sizeof(*cfg));
	strutil_set(&cfg->client_path, WORMHOLE_CLIENT_PATH);
	return cfg;
}

void
wormhole_config_free(struct wormhole_config *cfg)
{
	struct wormhole_profile_config *profile;
	struct wormhole_environment_config *env;

	while ((profile = cfg->profiles) != NULL) {
		cfg->profiles = profile->next;
		wormhole_profile_config_free(profile);
	}

	while ((env = cfg->environments) != NULL) {
		cfg->environments = env->next;
		wormhole_environment_config_free(env);
	}

	strutil_set(&cfg->client_path, NULL);
	free(cfg);
}

/*
 * Profile configuration objects
 */
static struct wormhole_profile_config *
__wormhole_profile_config_new(const char *name)
{
	struct wormhole_profile_config *profile;

	profile = calloc(1, sizeof(*profile));
	profile->name = strdup(name);
	return profile;
}

static struct wormhole_profile_config *
wormhole_profile_config_new(struct wormhole_config *cfg, const char *name, struct parser_state *ps)
{
	struct wormhole_profile_config **pos, *profile;

	for (pos = &cfg->profiles; (profile = *pos) != NULL; pos = &profile->next) {
		if (!strcmp(profile->name, name)) {
			parser_error(ps, "duplicate declaration of profile \"%s\"", name);
			return NULL;
		}
	}

	*pos = __wormhole_profile_config_new(name);
	return *pos;
}

void
wormhole_profile_config_free(struct wormhole_profile_config *profile)
{
	strutil_set(&profile->name, NULL);
	strutil_set(&profile->wrapper, NULL);
	strutil_set(&profile->command, NULL);
	strutil_set(&profile->environment, NULL);
	free(profile);
}

/*
 * Overlay config object
 */
static struct wormhole_layer_config *
wormhole_layer_config_new(struct wormhole_environment_config *env, int type)
{
	struct wormhole_layer_config **pos, *layer;

	for (pos = &env->layers; (layer = *pos) != NULL; pos = &layer->next)
		;

	*pos = layer = calloc(1, sizeof(*layer));
	layer->type = type;
	return layer;
}

static void
wormhole_layer_config_free(struct wormhole_layer_config *layer)
{
	wormhole_path_info_t *pi;
	unsigned int i;

	strutil_set(&layer->directory, NULL);
	strutil_set(&layer->image, NULL);

	if (layer->path) {
		for (i = 0, pi = layer->path; i < layer->npaths; ++i, ++pi) {
			strutil_set(&pi->path, NULL);

			switch (pi->type) {
			case WORMHOLE_PATH_TYPE_MOUNT:
				strutil_set(&pi->mount.fstype, NULL);
				strutil_set(&pi->mount.device, NULL);
				strutil_set(&pi->mount.options, NULL);
				break;
			}
		}
	}
}

wormhole_path_info_t *
wormhole_layer_config_add_path(struct wormhole_layer_config *layer, int type, const char *path)
{
	wormhole_path_info_t *pi;

	if ((layer->npaths % 16) == 0) {
		if (layer->path == NULL) {
			layer->path = calloc(16, sizeof(layer->path[0]));
		} else {
			layer->path = realloc(layer->path, (layer->npaths + 16) * sizeof(layer->path[0]));
			memset(layer->path + layer->npaths, 0, 16 * sizeof(layer->path[0]));
		}

		if (layer->path == NULL)
			log_fatal("%s: out of memory", __func__);
	}

	pi = &layer->path[layer->npaths++];
	pi->type = type;

	if (path)
		pi->path = strdup(path);

	return pi;
}

static bool
wormhole_path_info_set_mount_fstype(wormhole_path_info_t *pi, const char *fstype)
{
	if (pi->type != WORMHOLE_PATH_TYPE_MOUNT) {
		log_error("%s: path %s is not a mount point", __func__, pi->path);
		return false;
	}

	strutil_set(&pi->mount.fstype, fstype);
	return true;
}

static bool
wormhole_path_info_set_mount_device(wormhole_path_info_t *pi, const char *device)
{
	if (pi->type != WORMHOLE_PATH_TYPE_MOUNT) {
		log_error("%s: path %s is not a mount point", __func__, pi->path);
		return false;
	}

	strutil_set(&pi->mount.device, device);
	return true;
}

static bool
wormhole_path_info_set_mount_options(wormhole_path_info_t *pi, const char *options)
{
	if (pi->type != WORMHOLE_PATH_TYPE_MOUNT) {
		log_error("%s: path %s is not a mount point", __func__, pi->path);
		return false;
	}

	strutil_set(&pi->mount.options, options);
	return true;
}

/*
 * Environment config object
 */
static struct wormhole_environment_config *
__wormhole_environment_config_new(const char *name)
{
	struct wormhole_environment_config *env;

	env = calloc(1, sizeof(*env));
	env->name = strdup(name);

	strutil_array_init(&env->provides);
	strutil_array_init(&env->requires);

	return env;
}

static struct wormhole_environment_config *
wormhole_environment_config_new(struct wormhole_config *cfg, const char *name, struct parser_state *ps)
{
	struct wormhole_environment_config **pos, *env;

	for (pos = &cfg->environments; (env = *pos) != NULL; pos = &env->next) {
		if (!strcmp(env->name, name)) {
			parser_error(ps, "duplicate declaration of environment \"%s\"", name);
			return NULL;
		}
	}

	*pos = __wormhole_environment_config_new(name);
	return *pos;
}

static void
wormhole_environment_config_free(struct wormhole_environment_config *env)
{
	struct wormhole_layer_config *layer;

	strutil_set(&env->name, NULL);

	/* free all overlays */
	while ((layer = env->layers) != NULL) {
		env->layers = layer->next;
		wormhole_layer_config_free(layer);
	}

	strutil_array_destroy(&env->provides);
	strutil_array_destroy(&env->requires);

	free(env);
}

/*
 * Function for processing an entire file
 */
static bool
__wormhole_config_process_file(void *cfg_obj, struct parser_state *ps, bool (*kwd_proc_fn)(void *, const char *, struct parser_state *))
{
	while (parser_next_line(ps)) {
		const char *kwd;

		if (!(kwd = parser_next_word(ps)))
			continue;

		if (!kwd_proc_fn(cfg_obj, kwd, ps))
			return false;
	}

	return true;
}

/*
 * Function for processing blocks enclosed in {}
 */
static bool
wormhole_config_process_block(void *block_obj, struct parser_state *ps, bool (*kwd_proc_fn)(void *, const char *, struct parser_state *))
{
	unsigned int start_line;
	const char *word;

	word = parser_next_word(ps);
	if (!word)
		return true;

	if (*word != '{') {
		parser_error(ps, "unexpected token \"%s\" at start of block", word);
		return false;
	}
	start_line = ps->lineno;

	while (parser_next_line(ps)) {
		const char *kwd;

		if (!(kwd = parser_next_word(ps)))
			continue;

		if (*kwd == '}')
			return true;

		if (!kwd_proc_fn(block_obj, kwd, ps))
			return false;
	}

	parser_error(ps, "end of file while looking for closing brace (starting at line %u)", start_line);
	return false;
}

/*
 * Process string atoms
 */
static bool
__wormhole_config_process_string(const char *keyword, char **var, struct parser_state *ps)
{
	const char *arg;

	arg = parser_next_word(ps);
	if (arg == NULL) {
		parser_error(ps, "missing argument to %s directive", keyword);
		return false;
	}

	strutil_set(var, arg);

	if (parser_next_word(ps) != NULL) {
		parser_error(ps, "unexpected noise after argument to %s directive", keyword);
		return false;
	}

	return true;
}

static bool
__wormhole_config_process_array_element(const char *keyword, struct strutil_array *array, struct parser_state *ps)
{
	const char *value;

	value = parser_next_word(ps);
	if (value == NULL) {
		parser_error(ps, "missing argument to %s directive", keyword);
		return false;
	}

	strutil_array_append(array, value);

	if (parser_next_word(ps) != NULL) {
		parser_error(ps, "unexpected noise after argument to %s directive", keyword);
		return false;
	}

	return true;
}


/*
 * Process toplevel directives
 */
static bool
__wormhole_config_toplevel_directive(void *cfg_obj, const char *kwd, struct parser_state *ps)
{
	struct wormhole_config *cfg = cfg_obj;

	if (!strcmp(kwd, "config")) {
		return wormhole_config_process_include(cfg, ps);
	} else if (!strcmp(kwd, "profile")) {
		return wormhole_config_process_profile(cfg, ps);
	} else if (!strcmp(kwd, "environment")) {
		return wormhole_config_process_environment(cfg, ps);
	} else if (!strcmp(kwd, "client-path")) {
		return __wormhole_config_process_string(kwd, &cfg->client_path, ps);
	}

	parser_error(ps, "unexpected keyword \"%s\"", kwd);
	return false;
}

bool
wormhole_config_process_file(struct wormhole_config *cfg, const char *filename, struct parser_state *included_from)
{
	struct parser_state ps;
	bool rv;

	if (!parser_open(&ps, filename, included_from))
		return false;

	rv = __wormhole_config_process_file(cfg, &ps, __wormhole_config_toplevel_directive);
	parser_close(&ps);

	if (ps.failed) {
		log_error("%s: parsing failed, but return value indicates success. please fix your code", __func__);
		return false;
	}

	return rv;
}

/*
 * Process "config" directive, which specifies another file or directory to include.
 */
static bool
__wormhole_config_process_include(struct wormhole_config *cfg, const char *filename, struct parser_state *ps)
{
	struct stat stb;

	if (stat(filename, &stb) < 0) {
		if (errno == ENOENT)
			return true;

		parser_error(ps, "cannot access \"%s\": %m", filename);
		return false;
	}

	if (S_ISREG(stb.st_mode))
		return wormhole_config_process_file(cfg, filename, ps);

	if (S_ISDIR(stb.st_mode)) {
		struct dirent *de;
		bool ok = true;
		DIR *d;

		if (!(d = opendir(filename))) {
			parser_error(ps, "cannot open directory \"%s\": %m", filename);
			return false;
		}

		while (ok && (de = readdir(d)) != NULL) {
			char childpath[PATH_MAX];

			if (de->d_name[0] == '.')
				continue;

			if (de->d_type != DT_REG && de->d_type != DT_DIR)
				continue;

			snprintf(childpath, sizeof(childpath), "%s/%s", filename, de->d_name);
			ok = __wormhole_config_process_include(cfg, childpath, ps);
		}

		closedir(d);
		return ok;
	}

	parser_error(ps, "cannot include \"%s\" - unsupported file type", filename);
	return false;
}

static bool
wormhole_config_process_include(struct wormhole_config *cfg, struct parser_state *ps)
{
	const char *filename;

	if (!(filename = parser_next_word(ps))) {
		parser_error(ps, "missing pathname");
		return false;
	}

	return __wormhole_config_process_include(cfg, filename, ps);
}

/*
 * Process profile {} block
 * profile "name" {
 *	wrapper /sbin/yast2
 *	command /sbin/yast2
 *	environment yast-env
 * }
 */
static bool
__wormhole_config_profile_directive(void *block_obj, const char *kwd, struct parser_state *ps)
{
	struct wormhole_profile_config *profile = block_obj;

	if (!strcmp(kwd, "wrapper"))
		return __wormhole_config_process_string(kwd, &profile->wrapper, ps);
	if (!strcmp(kwd, "command"))
		return __wormhole_config_process_string(kwd, &profile->command, ps);
	if (!strcmp(kwd, "environment"))
		return __wormhole_config_process_string(kwd, &profile->environment, ps);

	parser_error(ps, "unexpected keyword \"%s\" in profile block", kwd);
	return false;
}

static bool
wormhole_config_process_profile(struct wormhole_config *cfg, struct parser_state *ps)
{
	struct wormhole_profile_config *profile;
	const char *name;

	if ((name = parser_next_word(ps)) == NULL) {
		parser_error(ps, "missing name argument");
		return false;
	}

	if (!(profile = wormhole_profile_config_new(cfg, name, ps)))
		return false;

	return wormhole_config_process_block(profile, ps, __wormhole_config_profile_directive);
}

/*
 * Simple path directive (bind, overlay etc)
 */
static wormhole_path_info_t *
___wormhole_config_layer_add_path(struct wormhole_layer_config *layer, const char *kwd, int type, struct parser_state *ps)
{
	wormhole_path_info_t *pi;
	const char *path;

	pi = wormhole_layer_config_add_path(layer, type, NULL);

	path = parser_next_word(ps);
	if (path == NULL) {
		parser_error(ps, "missing path argument to %s directive", kwd);
		return NULL;
	}

	if (path == NULL || path[0] != '/') {
		parser_error(ps, "%s: invalid path \"%s\" - must specify an absolute path name", kwd, path);
		return NULL;
	}

	strutil_set(&pi->path, path);
	return pi;
}

static bool
__wormhole_config_layer_add_path(struct wormhole_layer_config *layer, const char *kwd, int type, struct parser_state *ps)
{
	if (___wormhole_config_layer_add_path(layer, kwd, type, ps) == NULL)
		return false;

	return parser_expect_end_of_line(ps, kwd);
}

static bool
__wormhole_config_layer_add_mount(struct wormhole_layer_config *layer, const char *kwd, struct parser_state *ps)
{
	wormhole_path_info_t *pi;
	const char *args[3];
	unsigned int nargs = 0;
	bool ok = false;

	pi = ___wormhole_config_layer_add_path(layer, kwd, WORMHOLE_PATH_TYPE_MOUNT, ps);
	if (pi == NULL)
		return false;

	for (nargs = 0; nargs < 3; ++nargs) {
		const char *arg;

		if (!(arg = parser_next_word(ps)))
			break;

		args[nargs] = arg;
	}

	switch (nargs) {
	case 0:
		log_error("Missing argument(s) to %s directive", kwd);
		return false;

	case 1:
		ok = wormhole_path_info_set_mount_fstype(pi, args[0]);
		break;

	case 2:
		ok = wormhole_path_info_set_mount_fstype(pi, args[0])
		  && wormhole_path_info_set_mount_options(pi, args[1]);
		break;

	case 3:
		ok = wormhole_path_info_set_mount_fstype(pi, args[0])
		  && wormhole_path_info_set_mount_device(pi, args[1])
		  && wormhole_path_info_set_mount_options(pi, args[2]);
		break;

	default:
		log_error("Too many argument(s) to %s directive", kwd);
		break;
	}

	return ok && parser_expect_end_of_line(ps, kwd);
}

/*
 * use <feature>
 */
static bool
__wormhole_config_process_feature(const char *kwd, struct wormhole_layer_config *layer, struct parser_state *ps)
{
	char *feature = NULL;
	bool ok = true;

	if (!__wormhole_config_process_string(kwd, &feature, ps))
		return false;

	if (!strcmp(feature, "ldconfig")) {
		layer->use_ldconfig = true;
	} else {
		parser_error(ps, "%s: unknown feature \"%s\"", kwd, feature);
		ok = false;
	}

	free(feature);
	return ok;
}

/*
 * Process overlay block
 */
static bool
__wormhole_config_overlay_directive(void *block_obj, const char *kwd, struct parser_state *ps)
{
	struct wormhole_layer_config *layer = block_obj;
	
	if (!strcmp(kwd, "directory"))
		return __wormhole_config_process_string(kwd, &layer->directory, ps);
	if (!strcmp(kwd, "image"))
		return __wormhole_config_process_string(kwd, &layer->image, ps);
	if (!strcmp(kwd, "use"))
		return __wormhole_config_process_feature(kwd, layer, ps);
	if (!strcmp(kwd, "bind"))
		return __wormhole_config_layer_add_path(layer, kwd, WORMHOLE_PATH_TYPE_BIND, ps);
	if (!strcmp(kwd, "bind-children"))
		return __wormhole_config_layer_add_path(layer, kwd, WORMHOLE_PATH_TYPE_BIND_CHILDREN, ps);
	if (!strcmp(kwd, "overlay"))
		return __wormhole_config_layer_add_path(layer, kwd, WORMHOLE_PATH_TYPE_OVERLAY, ps);
	if (!strcmp(kwd, "overlay-children"))
		return __wormhole_config_layer_add_path(layer, kwd, WORMHOLE_PATH_TYPE_OVERLAY_CHILDREN, ps);
	if (!strcmp(kwd, "mount"))
		return __wormhole_config_layer_add_mount(layer, kwd, ps);
	if (!strcmp(kwd, "wormhole"))
		return __wormhole_config_layer_add_path(layer, kwd, WORMHOLE_PATH_TYPE_WORMHOLE, ps);

	parser_error(ps, "unexpected keyword \"%s\" in overlay block", kwd);
	return false;
}

/*
 * Process environment {} block
 */
static bool
__wormhole_config_environment_directive(void *block_obj, const char *kwd, struct parser_state *ps)
{
	static struct parser_obsolete_kwd obsolete_keywords[] = {
		{ "overlay",	"define-layer"		},
		{ "layer",	"use-environment"	},
		{ NULL }
	};
	struct wormhole_environment_config *env = block_obj;

	kwd = parser_check_obsolete_keyword(ps, kwd, obsolete_keywords);

	if (!strcmp(kwd, "define-layer")) {
		struct wormhole_layer_config *layer;

		layer = wormhole_layer_config_new(env, WORMHOLE_LAYER_TYPE_LAYER);
		if (!wormhole_config_process_block(layer, ps, __wormhole_config_overlay_directive))
			return false;

		if ((layer->directory && layer->image)
		 || (!layer->directory && !layer->image)) {
			parser_error(ps, "layer needs to specify exactly one of \"directory\" and \"image\"");
			return false;
		}
		return true;
	}

	if (!strcmp(kwd, "define-image")) {
		struct wormhole_layer_config *layer;

		layer = wormhole_layer_config_new(env, WORMHOLE_LAYER_TYPE_IMAGE);
		if (!wormhole_config_process_block(layer, ps, __wormhole_config_overlay_directive))
			return false;

		if ((layer->directory && layer->image)
		 || (!layer->directory && !layer->image)) {
			parser_error(ps, "image needs to specify exactly one of \"directory\" and \"image\"");
			return false;
		}
		return true;
	}

	if (!strcmp(kwd, "use-environment")) {
		struct wormhole_layer_config *layer;

		layer = wormhole_layer_config_new(env, WORMHOLE_LAYER_TYPE_REFERENCE);
		if (!__wormhole_config_process_string(kwd, &layer->lower_layer_name, ps))
			return false;

		return true;
	}

	if (!strcmp(kwd, "provides"))
		return __wormhole_config_process_array_element(kwd, &env->provides, ps);

	if (!strcmp(kwd, "requires"))
		return __wormhole_config_process_array_element(kwd, &env->requires, ps);

	parser_error(ps, "unexpected keyword \"%s\" in environment block", kwd);
	return false;
}

static bool
wormhole_config_process_environment(struct wormhole_config *cfg, struct parser_state *ps)
{
	struct wormhole_environment_config *env;
	const char *name;

	if ((name = parser_next_word(ps)) == NULL) {
		parser_error(ps, "missing name argument");
		return false;
	}

	if (!(env = wormhole_environment_config_new(cfg, name, ps)))
		return false;

	return wormhole_config_process_block(env, ps, __wormhole_config_environment_directive);
}

/*
 * Parser functions
 */
bool
parser_open(struct parser_state *ps, const char *filename, struct parser_state *included_from)
{
	memset(ps, 0, sizeof(*ps));
	if (!(ps->fp = fopen(filename, "r"))) {
		log_error("Unable to open %s: %m", filename);
		return false;
	}

	ps->included_from = included_from;
	ps->filename = filename;
	ps->lineno = 0;

	return true;
}

bool
parser_next_line(struct parser_state *ps)
{
	if (fgets(ps->buffer, sizeof(ps->buffer), ps->fp) == NULL)
		return false;

	ps->pos = ps->buffer;
	ps->lineno += 1;
	return true;
}

const char *
parser_next_word(struct parser_state *ps)
{
	char *s, *word;

	if (ps->pos == NULL)
		return NULL;

	/* skip white space */
	for (s = ps->pos; isspace(*s); ++s)
		;

	if (*s == '\0' || *s == '#') {
		ps->pos = NULL;
		return NULL;
	}

	if (isalnum(*s) || *s == '/' || *s == '_') {
		word = s;

		while (*s) {
			if (isspace(*s)) {
				*s++ = '\0';
				break;
			}
			++s;
		}
	} else {
		static char _word[2];

		_word[0] = *s++;
		_word[1] = '\0';
		word = _word;
	}

	ps->pos = *s? s : NULL;
	return word;
}

bool
parser_expect_end_of_line(struct parser_state *ps, const char *keyword)
{
	if (parser_next_word(ps) != NULL) {
		parser_error(ps, "unexpected extra argument(s) to %s directive", keyword);
		return false;
	}

	return true;
}

void
parser_close(struct parser_state *ps)
{
	fclose(ps->fp);
	ps->fp = NULL;
}

const char *
parser_check_obsolete_keyword(struct parser_state *ps, const char *kwd, struct parser_obsolete_kwd *obsolete)
{
	struct parser_obsolete_kwd *o;

	for (o = obsolete; o->old_keyword; ++o) {
		if (strcmp(o->old_keyword, kwd))
			continue;

		if (!o->warned) {
			parser_warning(ps, "obsolete keyword \"%s\", please use \"%s\" instead",
					o->old_keyword, o->new_keyword);
			o->warned = true;
		}
		return o->new_keyword;
	}

	return kwd;
}

void
parser_error(struct parser_state *ps, const char *fmt, ...)
{
	char errmsg[1024];
        va_list ap;

        va_start(ap, fmt);
	vsnprintf(errmsg, sizeof(errmsg), fmt, ap);
        va_end(ap);

	log_error("%s:%d: %s", ps->filename, ps->lineno, errmsg);

	while (ps->included_from) {
		ps = ps->included_from;
		log_error("  included from %s:%u", ps->filename, ps->lineno);
	}

	ps->failed = true;
}

void
parser_warning(struct parser_state *ps, const char *fmt, ...)
{
	char errmsg[1024];
        va_list ap;

        va_start(ap, fmt);
	vsnprintf(errmsg, sizeof(errmsg), fmt, ap);
        va_end(ap);

	log_warning("%s:%d: %s", ps->filename, ps->lineno, errmsg);

	while (ps->included_from) {
		ps = ps->included_from;
		log_error("  included from %s:%u", ps->filename, ps->lineno);
	}
}

/*
 * Helpers
 */
#ifdef TEST
static void
dump_config(struct wormhole_config *cfg)
{
	struct wormhole_environment_config *env;
	struct wormhole_profile_config *profile;

	for (env = cfg->environments; env; env = env->next) {
		struct wormhole_layer_config *overlay;

		printf("environment %s:\n", env->name);
		for (overlay = env->layers; overlay; overlay = overlay->next) {
			unsigned int i;

			switch (overlay->type) {
			case WORMHOLE_LAYER_TYPE_LAYER:
				printf("    define-layer:\n");
				break;

			case WORMHOLE_LAYER_TYPE_IMAGE:
				printf("    define-image:\n");
				break;

			case WORMHOLE_LAYER_TYPE_REFERENCE:
				printf("    use-environment %s\n", overlay->lower_layer_name);
				continue;

			default:
				log_fatal("dont know layer type %d", overlay->type);
			}

			if (overlay->directory)
				printf("        directory %s\n", overlay->directory);
			if (overlay->image)
				printf("        image %s\n", overlay->image);

			for (i = 0; i < overlay->npaths; ++i) {
				wormhole_path_info_t *pi = &overlay->path[i];

				printf("        path type=%d path=\"%s\"\n", pi->type, pi->path);
			}
		}
	}

	for (profile = cfg->profiles; profile; profile = profile->next) {
		printf("profile %s:\n", profile->name);
		if (profile->command)
			printf("        command %s\n", profile->command);
		if (profile->environment)
			printf("        environment %s\n", profile->environment);
	}
}

int main(int argc, char **argv)
{
	const char *config_file = "wormhole.conf.sample";
	struct wormhole_config *cfg;

	tracing_increment_level();
	printf("%s\n", argv[1]);
	if (argc > 1)
		config_file = argv[1];

	if (!(cfg = wormhole_config_load(config_file)))
		log_fatal("Unable to load config");

	dump_config(cfg);
	return 0;
}
#endif

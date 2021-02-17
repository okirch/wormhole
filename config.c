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

static bool		parser_open(struct parser_state *ps, const char *filename, struct parser_state *included_from);
static void		parser_close(struct parser_state *ps);
static bool		parser_next_line(struct parser_state *ps);
static const char *	parser_next_word(struct parser_state *ps);
static void		parser_error(struct parser_state *, const char *, ...);

static void		set_string(char **var, const char *s);

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
	set_string(&cfg->client_path, WORMHOLE_CLIENT_PATH);
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

	set_string(&cfg->client_path, NULL);
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
	set_string(&profile->name, NULL);
	set_string(&profile->wrapper, NULL);
	set_string(&profile->command, NULL);
	set_string(&profile->environment, NULL);
	free(profile);
}

/*
 * Overlay config object
 */
static struct wormhole_layer_config *
wormhole_layer_config_new(struct wormhole_environment_config *env)
{
	struct wormhole_layer_config **pos, *overlay;

	for (pos = &env->overlays; (overlay = *pos) != NULL; pos = &overlay->next)
		;

	*pos = overlay = calloc(1, sizeof(*overlay));
	return overlay;
}

static void
wormhole_layer_config_free(struct wormhole_layer_config *overlay)
{
	wormhole_path_info_t *pi;
	unsigned int i;

	set_string(&overlay->directory, NULL);
	set_string(&overlay->image, NULL);

	for (i = 0, pi = overlay->path; i < overlay->npaths; ++i, ++pi) {
		set_string(&pi->path, NULL);
	}
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
	struct wormhole_layer_config *overlay;

	set_string(&env->name, NULL);

	/* free all overlays */
	while ((overlay = env->overlays) != NULL) {
		env->overlays = overlay->next;
		wormhole_layer_config_free(overlay);
	}

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

	set_string(var, arg);

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
 * overlay path directive
 */
static bool
__wormhole_config_overlay_add_path(struct wormhole_layer_config *overlay, const char *kwd, int type, struct parser_state *ps)
{
	wormhole_path_info_t *pi;

	if (overlay->npaths >= WORMHOLE_OVERLAY_PATH_MAX) {
		parser_error(ps, "too many paths in overlay");
		return false;
	}

	pi = &overlay->path[overlay->npaths++];
	pi->type = type;

	if (!__wormhole_config_process_string(kwd, &pi->path, ps))
		return false;

	if (pi->path == NULL || pi->path[0] != '/') {
		parser_error(ps, "%s: invalid path \"%s\" - must specify an absolute path name", kwd, pi->path);
		return false;
	}

	return true;
}

/*
 * use <feature>
 */
static bool
__wormhole_config_process_feature(const char *kwd, struct wormhole_layer_config *overlay, struct parser_state *ps)
{
	char *feature = NULL;
	bool ok = true;

	if (!__wormhole_config_process_string(kwd, &feature, ps))
		return false;

	if (!strcmp(feature, "ldconfig")) {
		overlay->use_ldconfig = true;
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
	struct wormhole_layer_config *overlay = block_obj;
	
	if (!strcmp(kwd, "directory"))
		return __wormhole_config_process_string(kwd, &overlay->directory, ps);
	if (!strcmp(kwd, "image"))
		return __wormhole_config_process_string(kwd, &overlay->image, ps);
	if (!strcmp(kwd, "use"))
		return __wormhole_config_process_feature(kwd, overlay, ps);
	if (!strcmp(kwd, "bind"))
		return __wormhole_config_overlay_add_path(overlay, kwd, WORMHOLE_PATH_TYPE_BIND, ps);
	if (!strcmp(kwd, "bind-children"))
		return __wormhole_config_overlay_add_path(overlay, kwd, WORMHOLE_PATH_TYPE_BIND_CHILDREN, ps);
	if (!strcmp(kwd, "overlay"))
		return __wormhole_config_overlay_add_path(overlay, kwd, WORMHOLE_PATH_TYPE_OVERLAY, ps);
	if (!strcmp(kwd, "overlay-children"))
		return __wormhole_config_overlay_add_path(overlay, kwd, WORMHOLE_PATH_TYPE_OVERLAY_CHILDREN, ps);
	if (!strcmp(kwd, "wormhole"))
		return __wormhole_config_overlay_add_path(overlay, kwd, WORMHOLE_PATH_TYPE_WORMHOLE, ps);

	parser_error(ps, "unexpected keyword \"%s\" in overlay block", kwd);
	return false;
}

/*
 * Process environment {} block
 */
static bool
__wormhole_config_environment_directive(void *block_obj, const char *kwd, struct parser_state *ps)
{
	struct wormhole_environment_config *env = block_obj;

	if (!strcmp(kwd, "overlay")) {
		struct wormhole_layer_config *overlay;

		overlay = wormhole_layer_config_new(env);
		if (!wormhole_config_process_block(overlay, ps, __wormhole_config_overlay_directive))
			return false;

		if ((overlay->directory && overlay->image)
		 || (!overlay->directory && !overlay->image)) {
			parser_error(ps, "overlay needs to specify exactly one of \"directory\" and \"image\"");
			return false;
		}
		return true;
	}

	if (!strcmp(kwd, "layer")) {
		struct wormhole_layer_config *overlay;

		overlay = wormhole_layer_config_new(env);
		if (!__wormhole_config_process_string(kwd, &overlay->lower_layer_name, ps))
			return false;

		return true;
	}

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

void
parser_close(struct parser_state *ps)
{
	fclose(ps->fp);
	ps->fp = NULL;
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

/*
 * Helpers
 */
static void
set_string(char **var, const char *s)
{
	if (*var) {
		free(*var);
		*var = NULL;
	}
	if (s)
		*var = strdup(s);
}

#ifdef TEST
static void
dump_config(struct wormhole_config *cfg)
{
	struct wormhole_environment_config *env;
	struct wormhole_profile_config *profile;

	for (env = cfg->environments; env; env = env->next) {
		struct wormhole_layer_config *overlay;

		printf("environment %s:\n", env->name);
		for (overlay = env->overlays; overlay; overlay = overlay->next) {
			unsigned int i;

			printf("    overlay:\n");
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

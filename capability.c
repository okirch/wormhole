/*
 * wormhole-capability
 *
 *   Copyright (C) 2021 Olaf Kirch <okir@suse.de>
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
#include <sched.h>
#include <stdlib.h>
#include <getopt.h>

#include "wormhole.h"
#include "profiles.h"
#include "config.h"
#include "util.h"
#include "tracing.h"

enum {
	OPT_FORCE,
	OPT_NO_PROFILE,
};

struct option wormhole_options[] = {
	{ "help",		no_argument,		NULL,	'h' },
	{ "debug",		no_argument,		NULL,	'd' },
	{ "force",		no_argument,		NULL,	OPT_FORCE },
	{ "no-profile",		no_argument,		NULL,	OPT_NO_PROFILE },
	{ NULL }
};

static bool		opt_force = false;
static bool		opt_install_profile = true;

static bool		wormhole_capability(int argc, char **argv);
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

		case OPT_FORCE:
			opt_force = true;
			break;

		case OPT_NO_PROFILE:
			opt_install_profile = false;
			break;

		default:
			log_error("Error parsing command line");
			usage(2);
		}
	}

	if (!wormhole_capability(argc - optind, argv + optind))
		return 1;

	return 0;
}

void
usage(int exval)
{
	FILE *f = exval? stderr : stdout;

	fprintf(f,
		"Usage:\n"
		"wormhole-capability [options] action [args]\n"
		"  --help, -h\n"
		"     Display this help message\n"
		"  --debug, -d\n"
		"     Increase debugging verbosity\n"
		"\n"
		"Supported actions:\n"
		"  activate <config-file>\n"
		"     Register capabilities provided by the given wormhole configuration file.\n"
		"  deactivate <config-file>\n"
		"     Unregister capabilities provided by the given wormhole configuration file.\n"
		"  prune\n"
		"     Remove any stale capabilities\n"
	);
	exit(exval);
}

static inline bool
__check_expected_args(const char *action, int argc, unsigned int num_expected)
{
	if (argc == 1 + num_expected)
		return true;

	if (argc > 1 + num_expected)
		log_error("wormhole-capability: too many arguments to \"%s\"", action);
	else
		log_error("wormhole-capability: missing arguments to \"%s\"", action);
	return false;
}

static bool
__get_capabilities(struct wormhole_config *config, struct strutil_array *provides)
{
	struct wormhole_environment_config *env_cfg;

	for (env_cfg = config->environments; env_cfg; env_cfg = env_cfg->next) {
		strutil_array_append_array(provides, &env_cfg->provides);
	}

	return true;
}

static bool
__get_commands(struct wormhole_config *config, struct strutil_array *commands, struct strutil_array *names)
{
	struct wormhole_profile_config *cmd_cfg;

	for (cmd_cfg = config->profiles; cmd_cfg; cmd_cfg = cmd_cfg->next) {
		const char *wrapper = cmd_cfg->wrapper;

		if (wrapper != NULL) {
			strutil_array_append(commands, wrapper);
			strutil_array_append(names, pathutil_const_basename(wrapper));
		}
	}

	return true;
}

/*
 * Create all wrapper symlinks pointing to /usr/bin/wormhole
 */
static bool
__create_wrappers(const struct strutil_array *commands, const char *client_path)
{
	unsigned int i;

	for (i = 0; i < commands->count; ++i) {
		const char *path = commands->data[i];

		if (fsutil_exists(path)) {
			if (fsutil_same_file(path, client_path)) {
				trace("%s already exists, nothing to be done", path);
				continue;
			}

			if (opt_force) {
				if (unlink(path) >= 0) {
					trace("force removed %s", path);
					continue;
				}
				trace("failed to force remove %s: %m", path);
			}

			log_error("%s exists, but does not point to %s", path, client_path);
			return false;
		}

		if (symlink(client_path, path) < 0) {
			log_error("Unable to create symbolic link %s: %m", path);
			return false;
		}

		trace("Created wrapper symlink %s -> %s", path, client_path);
	}

	return true;
}

/*
 * Remove wrapper symlinks
 */
static bool
__remove_wrappers(const struct strutil_array *commands, const char *client_path)
{
	unsigned int i;
	bool ok = true;

	for (i = 0; i < commands->count; ++i) {
		const char *path = commands->data[i];

		if (!fsutil_exists(path))
			continue;

		if (!fsutil_same_file(path, client_path)) {
			log_error("%s exists, but does not point to %s", path, client_path);
			ok = false;
			continue;
		}

		if (unlink(path) >= 0) {
			trace("removed wrapper symlink %s", path);
			continue;
		}

		log_error("unable to remove wrapper symlink %s: %m", path);
		ok = false;
	}

	return ok;
}

static bool
__capabilities_install(const char *path)
{
	struct strutil_array provides;
	struct strutil_array commands;
	struct strutil_array names;
	struct wormhole_config *config;

	if (!(config = wormhole_config_load(path))) {
		log_error("Unable to read %s", path);
		return false;
	}

	strutil_array_init(&provides);
	strutil_array_init(&commands);
	strutil_array_init(&names);

	if (!__get_capabilities(config, &provides))
		return false;

	if (!wormhole_capability_register(&provides, path))
		return false;

	if (opt_install_profile) {
		if (!__get_commands(config, &commands, &names))
			return false;

		if (!wormhole_command_register(&names, path))
			return false;

		if (!__create_wrappers(&commands, WORMHOLE_CLIENT_PATH))
			return false;
	}

	if (provides.count + commands.count == 0)
		log_warning("%s does not provide any capabilities or commands, nothing to be done", path);

	return true;
}

static bool
__capabilities_uninstall(const char *path)
{
	struct strutil_array provides;
	struct strutil_array commands;
	struct strutil_array names;
	struct wormhole_config *config;

	if (!(config = wormhole_config_load(path))) {
		log_error("Unable to read %s", path);
		return false;
	}

	strutil_array_init(&provides);
	strutil_array_init(&commands);
	strutil_array_init(&names);

	if (!__get_capabilities(config, &provides))
		return false;

	if (!wormhole_capability_unregister(&provides, path))
		return false;

	if (opt_install_profile) {
		if (!__get_commands(config, &commands, &names))
			return false;

		if (!wormhole_command_unregister(&names, path))
			return false;

		if (!__remove_wrappers(&commands, WORMHOLE_CLIENT_PATH))
			return false;
	}

	if (provides.count + commands.count == 0)
		log_warning("%s does not provide any capabilities or commands, nothing to be done", path);

	return true;
}

static bool
wormhole_capability(int argc, char **argv)
{
	const char *action;

	if (argc == 0) {
		log_error("wormhole-capability: missing action");
		usage(2);
	}

	action = argv[0];
	if (!strcmp(action, "prune")) {
		if (!__check_expected_args(action, argc, 0))
			return false;
		return wormhole_capabilities_gc();
	}

	if (!strcmp(action, "activate")) {
		if (!__check_expected_args(action, argc, 1))
			return false;

		return __capabilities_install(argv[1]);
	}

	if (!strcmp(action, "deactivate")) {
		if (!__check_expected_args(action, argc, 1))
			return false;

		return __capabilities_uninstall(argv[1]);
	}

	log_error("wormhole-capability: unsupported action \"%s\"", action);
	return false;
}

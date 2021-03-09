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
	{ NULL }
};

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
__get_capabilities(const char *path, struct strutil_array *provides)
{
	struct wormhole_config *config;
	struct wormhole_environment_config *env_cfg;

	if (!(config = wormhole_config_load(path))) {
		log_error("Unable to read %s", path);
		return false;
	}

	for (env_cfg = config->environments; env_cfg; env_cfg = env_cfg->next) {
		strutil_array_append_array(provides, &env_cfg->provides);
	}

	wormhole_config_free(config);
	return true;
}

static bool
wormhole_capability(int argc, char **argv)
{
	const char *action, *path;
	struct strutil_array provides;

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

	strutil_array_init(&provides);
	if (!strcmp(action, "activate")) {
		if (!__check_expected_args(action, argc, 1))
			return false;

		path = argv[1];
		if (!__get_capabilities(path, &provides))
			return false;

		if (provides.count == 0) {
			log_warning("%s does not provide any capabilities, nothing to be done", path);
			return true;
		}

		return wormhole_capability_register(&provides, path);
	}

	if (!strcmp(action, "deactivate")) {
		if (!__check_expected_args(action, argc, 1))
			return false;

		path = argv[1];
		if (!__get_capabilities(path, &provides))
			return false;

		if (provides.count == 0) {
			log_warning("%s does not provide any capabilities, nothing to be done", path);
			return true;
		}

		return wormhole_capability_unregister(&provides, path);
	}

	log_error("wormhole-capability: unsupported action \"%s\"", action);
	return false;
}

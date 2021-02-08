/*
 * wormhole
 *
 *   Copyright (C) 2020, 2021 Olaf Kirch <okir@suse.de>
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

static void			load_config(void);
static wormhole_profile_t *	find_profile(const char *argv0);
static void			run_command(wormhole_profile_t *profile, int argc, char **argv);

int
main(int argc, char **argv)
{
	wormhole_profile_t *profile;

	/* Someone trying to invoke us without argv0 doesn't deserve
	 * an error message. */
	if (argc == 0)
		return 2;

	load_config();

	profile = find_profile(argv[0]);
	run_command(profile, argc, argv);

	return 22;
}

static void
load_config(void)
{
	struct wormhole_config *config;
	const char *config_path;
	const char *debug;

	if ((debug = getenv("WORMHOLE_DEBUG")) != NULL) {
		int level = atoi(debug);

		tracing_set_level(level);
	}

	if ((config_path = getenv("WORMHOLE_CONFIG")) == NULL)
		config_path = WORMHOLE_CONFIG_PATH;

	if (!(config = wormhole_config_load(config_path)))
                log_fatal("Unable to load configuration file %s", config_path);

	if (!wormhole_profiles_configure(config))
		log_fatal("Bad configuration, cannot continue.");
}

static wormhole_profile_t *
find_profile(const char *argv0)
{
	char *command_name;
	wormhole_profile_t *profile;

	command_name = wormhole_command_path(argv0);
	if (command_name == NULL)
		log_fatal("Cannot determine command name from argv[0] (%s)", argv0);

	profile = wormhole_profile_find(command_name);
	if (profile == NULL)
		log_fatal("no profile for %s", command_name);

	if (profile->environment == NULL)
		log_fatal("No environment associated with profile %s", command_name);

	return profile;
}

static void
run_command(wormhole_profile_t *profile, int argc, char **argv)
{
	wormhole_environment_t *env = profile->environment;

	if (wormhole_profile_setup(profile, true) < 0)
                log_fatal("Failed to set up environment %s", env->name);

	trace("Looking good so far\n");
	execv(profile->config->command, argv);

	log_fatal("Unable to execute %s: %m", profile->config->command);
}

/*
 * common application code shared by several wormhole utilities
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
#include <limits.h>
#include <stdlib.h>

#include "wormhole.h"
#include "profiles.h"
#include "config.h"
#include "util.h"
#include "tracing.h"

static void
__wormhole_common_load_config(const char *config_path, bool must_exist)
{
	struct wormhole_config *config;

	if (access(config_path, R_OK) != 0) {
		if (must_exist)
			log_fatal("Configuration file %s does not exist", config_path);
		return;
	}

	if (!(config = wormhole_config_load(config_path)))
                log_fatal("Unable to load configuration file %s", config_path);

	if (!wormhole_profiles_configure(config))
		log_fatal("Bad configuration, cannot continue.");
}

static const char *
__wormhole_user_config_path(void)
{
	static char buf[PATH_MAX];
	char *homedir;

	if (strncmp(WORMHOLE_USER_CONFIG_PATH, "~/", 2) != 0)
		return WORMHOLE_USER_CONFIG_PATH;

	/* Replace the ~ with $HOME */
	if ((homedir = getenv("HOME")) == NULL)
		return NULL;

	snprintf(buf, sizeof(buf), homedir, "%s/%s", WORMHOLE_USER_CONFIG_PATH + 1);
	return buf;
}

void
wormhole_common_load_config(const char *opt_config_path)
{
	const char *config_path;
	const char *debug;

	if ((debug = getenv("WORMHOLE_DEBUG")) != NULL) {
		int level = atoi(debug);

		tracing_set_level(level);
	}

	if ((config_path = opt_config_path) == NULL)
		config_path = getenv("WORMHOLE_CONFIG");

	/* A config path specified explicitly (via command line or
	 * environment variable) must exist; if it does not, that's
	 * an error. */
	if (config_path) {
		__wormhole_common_load_config(config_path, true);
		return;
	}

	config_path = __wormhole_user_config_path();
	if (config_path)
		__wormhole_common_load_config(config_path, false);

	__wormhole_common_load_config(WORMHOLE_CONFIG_PATH, false);
}

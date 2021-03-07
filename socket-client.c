/*
 * socket-client
 *
 *   This is some leftover code that I'm keeping around in case
 *   some of it may be needed again later.
 *
 *   Right now, it's of absolutely no value.
 *
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

#include "tracing.h"
#include "wormhole.h"
#include "protocol.h"
#include "socket.h"
#include "util.h"

static struct option wormhole_options[] = {
	{ "debug",		no_argument,		NULL,	'd' },
	{ "environment",	required_argument,	NULL,	'E' },
	{ NULL }
};

static const char *	opt_environment = NULL;

typedef bool		wormhole_namespace_response_callback_fn_t(struct wormhole_message_namespace_response *msg, int nsfd, void *closure);

int
main(int argc, char **argv)
{
	const char *basename;
	int c;

	/* Someone trying to invoke us without argv0 doesn't deserve
	 * an error message. */
	if (argc == 0)
		return 2;

	basename = pathutil_const_basename(argv[0]);
	if (basename == NULL)
		return 2;

	if (strcmp(basename, "wormhole") != 0)
		return wormhole_client(argc, argv);

	while ((c = getopt_long(argc, argv, "d", wormhole_options, NULL)) != EOF) {
		switch (c) {
		case 'd':
			tracing_increment_level();
			break;

		case 'E':
			if (getuid() != 0)
				log_fatal("You must be root to use the --environment option");
			opt_environment = optarg;
			break;

		default:
			log_error("Usage message goes here.");
			return 2;
		}
	}

	return wormhole_client(argc - optind, argv + optind);
}

struct wormhole_namespace_closure {
	int		argc;
	char **		argv;
};

static bool
wormhole_namespace_response_callback(struct wormhole_message_namespace_response *msg, int nsfd, void *closure)
{
	struct wormhole_namespace_closure *cb = closure;

	/* Apply any environment variables sent to us by the server. */
	if (msg->environment_vars != NULL) {
		char **env = msg->environment_vars;
		unsigned int i;

		for (i = 0; env[i]; ++i)
			putenv(env[i]);
	}

	if (msg->server_socket) {
		setenv("WORMHOLE_SOCKET", msg->server_socket, 1);
	}

	if (setns(nsfd, CLONE_NEWNS) < 0) {
		log_error("setns: %m");
		return false;
	}

	/* Unshare the namespace so that any nonsense that happens in the subprocess we spawn
	 * stays local to that execution context. */
	if (unshare(CLONE_NEWNS) < 0) {
		log_error("unshare: %m");
		return false;
	}

	/* We no longer need this fd and should not pass it on to the executed command */
	close(nsfd);

	/* Drop uid/gid back to those of the calling user. */
	setgid(getgid());
	setuid(getuid());

	trace("I should now execute %s\n", msg->command);
	execv(msg->command, cb->argv);

	log_error("Unable to execute %s: %m", msg->command);
	return false;
}

int
wormhole_client(int argc, char **argv)
{
	struct wormhole_namespace_closure closure = { argc, argv };

	if (opt_environment == NULL)
		opt_environment = wormhole_command_path(argv[0]);

	if (!wormhole_client_namespace_request(opt_environment, wormhole_namespace_response_callback, &closure))
		return 1;

	return 12;
}

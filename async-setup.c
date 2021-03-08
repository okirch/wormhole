/*
 * async environment setup for wormhole
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
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sched.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <glob.h>

#include "wormhole.h"
#include "tracing.h"
#include "profiles.h"
#include "config.h"
#include "runtime.h"
#include "server.h"
#include "socket.h"
#include "util.h"

typedef struct wormhole_async_env_ctx	wormhole_async_env_ctx_t;
struct wormhole_async_env_ctx {
	wormhole_async_env_ctx_t **	prev;
	wormhole_async_env_ctx_t *	next;

	pid_t				child_pid;
	int				sock_id;

	wormhole_environment_t *	env;
};

static wormhole_async_env_ctx_t *	wormhole_async_env_ctx_list = NULL;

static inline void
wormhole_async_env_ctx_insert(wormhole_async_env_ctx_t **pos, wormhole_async_env_ctx_t *ctx)
{
	wormhole_async_env_ctx_t *next;

	ctx->next = *pos;
	ctx->prev = pos;

	if ((next = *pos) != NULL)
		next->prev = &ctx->next;

	*pos = ctx;
}

static inline void
wormhole_async_env_ctx_unlink(wormhole_async_env_ctx_t *ctx)
{
	wormhole_async_env_ctx_t *next;
	wormhole_async_env_ctx_t **prev;

	if ((next = ctx->next) != NULL)
		next->prev = ctx->prev;
	if ((prev = ctx->prev) != NULL)
		*prev = ctx->next;

	ctx->next = NULL;
	ctx->prev = NULL;
}

static wormhole_async_env_ctx_t *
wormhole_async_env_ctx_new(wormhole_environment_t *env)
{
	wormhole_async_env_ctx_t *ctx;

	ctx = calloc(1, sizeof(*ctx));
	ctx->env = env;

	ctx->next = wormhole_async_env_ctx_list;
	wormhole_async_env_ctx_list = ctx;

	return ctx;
}

static void
wormhole_async_env_ctx_release(wormhole_async_env_ctx_t *ctx)
{
	if (ctx->child_pid == 0 && ctx->sock_id == 0) {
		wormhole_async_env_ctx_unlink(ctx);
		free(ctx);
	}
}

static wormhole_async_env_ctx_t *
wormhole_async_env_ctx_for_pid(pid_t pid)
{
	wormhole_async_env_ctx_t **pos, *ctx;

	for (pos = &wormhole_async_env_ctx_list; (ctx = *pos) != NULL; pos = &ctx->next) {
		if (ctx->child_pid == pid)
			return ctx;
	}

	return NULL;
}

static wormhole_async_env_ctx_t *
wormhole_async_env_ctx_for_socket(const wormhole_socket_t *sock)
{
	wormhole_async_env_ctx_t **pos, *ctx;

	for (pos = &wormhole_async_env_ctx_list; (ctx = *pos) != NULL; pos = &ctx->next) {
		if (ctx->sock_id == sock->id)
			return ctx;
	}

	return NULL;
}

static wormhole_async_env_ctx_t *
wormhole_async_env_ctx_for_environment(wormhole_environment_t *env, bool create)
{
	wormhole_async_env_ctx_t *ctx;

	for (ctx = wormhole_async_env_ctx_list; ctx; ctx = ctx->next) {
		if (ctx->env == env)
			return ctx;
	}

	if (create)
		return wormhole_async_env_ctx_new(env);

	return NULL;
}

/*
 * Server side socket handler for receiving namespace fds passed back to us by
 * the async profile setup code.
 */
static bool
wormhole_environment_fd_received(wormhole_socket_t *s, struct buf *bp, int fd)
{
	wormhole_async_env_ctx_t *ctx;

	trace("%s(sock_id=%d)", __func__, s->id);
	if (fd < 0) {
		log_error("%s: missing file descriptor from client", __func__);
		return false;
	}

	ctx = wormhole_async_env_ctx_for_socket(s);
	if (ctx == NULL)
		return false;

	/* We need to dup the file descriptor, as our caller will close it */
	wormhole_environment_set_fd(ctx->env, dup(fd));
	buf_zap(bp);

	ctx->sock_id = 0;

	/* If we've collected both the child exit status and the response from the
	 * socket, we can release this context. */
	wormhole_async_env_ctx_release(ctx);

	return true;
}

static wormhole_socket_t *
wormhole_environment_create_fd_receiver(int fd)
{
	static struct wormhole_app_ops app_ops = {
		.received = wormhole_environment_fd_received,
		// .closed = wormhole_environment_fd_closed,
	};
	wormhole_socket_t *sock;

	sock = wormhole_connected_socket_new(fd, 0, 0);
	sock->app_ops = &app_ops;

	return sock;
}

/*
 * Check if async setup is in progress for this environment
 */
bool
wormhole_environment_async_check(wormhole_environment_t *env)
{
	wormhole_async_env_ctx_t *ctx;

	ctx = wormhole_async_env_ctx_for_environment(env, false);
	return ctx != NULL;
}

/*
 * Start async setup for this environment
 */
wormhole_socket_t *
wormhole_environment_async_setup(wormhole_environment_t *env, wormhole_profile_t *profile)
{
	wormhole_async_env_ctx_t *ctx;
	pid_t pid;
	int nsfd, sock_fd;

	ctx = wormhole_async_env_ctx_for_environment(env, true);
	if (ctx->child_pid || ctx->sock_id) {
		log_error("Async setup for env %s already in progress", env->name);
		return NULL;
	}

	pid = procutil_fork_with_socket(&sock_fd);
	if (pid < 0)
		return NULL;

	if (pid > 0) {
		wormhole_socket_t *sock;

		sock = wormhole_environment_create_fd_receiver(sock_fd);

		ctx->child_pid = pid;
		ctx->sock_id = sock->id;

		return sock;
	}

	if (wormhole_profile_setup(profile, false) < 0)
                log_fatal("Failed to set up environment for %s", profile->name);

        nsfd = open("/proc/self/ns/mnt", O_RDONLY);
        if (nsfd < 0)
                log_fatal("Cannot open /proc/self/ns/mnt: %m");

	if (wormhole_socket_sendmsg(sock_fd, "", 1, nsfd) < 0)
		log_fatal("unable to send namespace fd to parent: %m");

	trace("Successfully set up environment \"%s\"", env->name);
	exit(0);
}

/*
 * Async setup: the child process exited.
 */
wormhole_environment_t *
wormhole_environment_async_complete(pid_t pid, int status)
{
	wormhole_environment_t *env;
	wormhole_async_env_ctx_t *ctx;

	if (!(ctx = wormhole_async_env_ctx_for_pid(pid)))
		return NULL;

	ctx->child_pid = 0;
	env = ctx->env;

	if (!procutil_child_status_okay(status)) {
		log_error("Environment \"%s\": setup process failed (%s)", env->name,
				procutil_child_status_describe(status));
		env->failed = true;

		/* Setup failed, don't bother waiting for anything on this socket */
		ctx->sock_id = 0;
	} else {
		trace("Environment \"%s\": setup process complete", env->name);
		env->failed = false;
	}

	/* If we've collected both the child exit status and the response from the
	 * socket, we can release this context. */
	wormhole_async_env_ctx_release(ctx);

	return env;
}


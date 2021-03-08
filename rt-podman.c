/*
 * podman backend for wormhole
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

#include <sys/wait.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include "tracing.h"
#include "runtime.h"
#include "util.h"

/*
 * Run a podman command and capture (a single line of) output
 */
#define PODMAN_MAX_ARGS	64

static char **
podman_build_cmd(const char *subcmd, va_list ap)
{
	static const char *argv[PODMAN_MAX_ARGS];
	char *s;
	int i = 0;

	argv[i++] = "podman";
	argv[i++] = subcmd;

	while ((s = va_arg(ap, char *)) != NULL) {
		if (i + 2 >= PODMAN_MAX_ARGS) {
			log_error("Too many arguments to podman");
			return NULL;
		}
		argv[i++] = s;
	}
	argv[i] = NULL;

	return (char **) argv;
}

static int
podman_exec(char **argv, int *fdp)
{
	int pfd[2];
	pid_t pid;

	if (true)
		log_debug("About to run: %s", procutil_concat_argv(-1, argv));

	if (fdp == NULL) {
		pid = fork();
		if (pid < 0) {
			log_error("podman fork: %m");
			return -1;
		}

		if (pid == 0) {
			execvp("podman", argv);
			log_error("Cannot execute podman: %m");
			exit(5);
		}
	} else {
		if (pipe(pfd) < 0) {
			log_error("podman pipe: %m");
			return -1;
		}

		pid = fork();
		if (pid < 0) {
			log_error("podman fork: %m");
			close(pfd[0]);
			close(pfd[1]);
			return -1;
		}

		if (pid == 0) {
			close(pfd[0]);
			dup2(pfd[1], 1);
			dup2(pfd[1], 2);
			execvp("podman", argv);
			log_error("Cannot execute podman: %m");
			exit(5);
		}

		close(pfd[1]);
		*fdp = pfd[0];
	}

	return pid;
}

static inline bool
chop(char *line)
{
	line[strcspn(line, "\n")] = '\0';
	return line[0] != '\0';
}

static char *
podman_read_response(int fd)
{
	static char buffer[1024];
	char more[1024], *resp;
	bool first = true;
	FILE *fp;

	fp = fdopen(fd, "r");

	resp = fgets(buffer, sizeof(buffer), fp);
	if (resp)
		chop(resp);

	while (fgets(more, sizeof(more), fp)) {
		if (chop(more)) {
			if (first) {
				log_error("Warning; additional output from podman:");
				first = false;
			}
			log_error("%s", more);
		}
	}

	fclose(fp);
	return resp;
}

static int
podman_wait(pid_t pid)
{
	int status;

	while (waitpid(pid, &status, 0) < 0) {
		log_error("podman waitpid: %m");
		if (errno == ECHILD)
			return -1;
	}

	if (WIFSIGNALED(status)) {
		log_error("podman command crashed with signal %d", WTERMSIG(status));
		return -1;
	}

	if (!WIFEXITED(status)) {
		log_error("something happened to podman command - status %d", status);
		return -1;
	}

	return WEXITSTATUS(status);
}

static char *
podman_run_and_capture(char *subcmd, ...)
{
	va_list ap;
	char **argv;
	char *response;
	int fd, exitcode;
	pid_t pid;

	va_start(ap, subcmd);
	argv = podman_build_cmd(subcmd, ap);
	va_end(ap);

	if (argv == NULL)
		return NULL;

	pid = podman_exec(argv, &fd);
	if (pid < 0)
		return NULL;

	response = podman_read_response(fd);

	exitcode = podman_wait(pid);

	if (exitcode < 0)
		return NULL;

	if (exitcode != 0) {
		log_error("podman %s exited with non-zero status %d", subcmd, exitcode);
		return NULL;
	}

	return response;
}

static bool
podman_run(char *subcmd, ...)
{
	va_list ap;
	char **argv;
	int exitcode;
	pid_t pid;

	va_start(ap, subcmd);
	argv = podman_build_cmd(subcmd, ap);
	va_end(ap);

	if (argv == NULL)
		return NULL;

	pid = podman_exec(argv, NULL);
	if (pid < 0)
		return NULL;

	exitcode = podman_wait(pid);
	if (exitcode < 0)
		return NULL;

	return exitcode == 0;
}

static bool
podman_container_exists(const char *name)
{
	return podman_run("container", "exists", name, NULL);
}

static bool
podman_start(const char *image_spec, const char *container_name)
{
	return podman_run("create", "--name", container_name, image_spec, NULL);
}

static const char *
podman_mount(const char *container_name)
{
	return podman_run_and_capture("mount", container_name, NULL);
}

struct wormhole_container_runtime	wormhole_runtime_podman = {
	.container_exists		= podman_container_exists,
	.container_start		= podman_start,
	.container_mount		= podman_mount,
};

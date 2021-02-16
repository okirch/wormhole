/*
 * utility functions for wormhole
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

#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sched.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>

#include "tracing.h"
#include "util.h"


const char *
wormhole_concat_argv(int argc, char **argv)
{
	static char buffer[8192];
	unsigned int pos, n;
	int i;

	if (argc < 0) {
		for (argc = 0; argv[argc]; ++argc)
			;
	}

	pos = 0;
	for (i = 0; i < argc; ++i) {
		const char *s = argv[i];

		n = strlen(s);

		/* We need to be able to include 3 additional chars (space, and 2x") plus
		 * the ellipsis string " ..."
		 */
		if (pos + n >= sizeof(buffer) - 20) {
			strcpy(buffer + pos, " ...");
			break;
		}

		if (i)
			buffer[pos++] = ' ';
		if (strchr(s, ' ') == NULL) {
			strcpy(buffer + pos, s);
			pos += n;
		} else {
			buffer[pos++] = '"';
			strcpy(buffer + pos, s);
			pos += n;
			buffer[pos++] = '"';
		}
	}

	return buffer;
}

const char *
wormhole_const_basename(const char *path)
{
	const char *s;

	if (path == NULL)
		return NULL;

	s = strrchr(path, '/');
	if (s == NULL)
		return path;

	/* Path ends with a slash */
	if (s[1] == '\0')
		return NULL;

	return &s[1];
}

static const char *
wormhole_find_command(const char *argv0)
{
	static char cmdbuf[PATH_MAX];
	const char *path_env;
	char path[PATH_MAX], *s, *next;

	if ((path_env = getenv("PATH")) != NULL) {
		if (strlen(path_env) > sizeof(path))
			log_fatal("cannot resolve command - PATH too long");
		strncpy(path, path_env, sizeof(path));
	} else {
		if (confstr(_CS_PATH, path, sizeof(path)) >= sizeof(path))
			log_fatal("cannot resolve command - PATH confstr too long");
	}

	for (s = path; s != NULL; s = next) {
		if ((next = strchr(s, ':')) != NULL)
			*next++ = '\0';

		if (*s != '\0') {
			snprintf(cmdbuf, sizeof(cmdbuf), "%s/%s", s, argv0);
			if (access(cmdbuf, X_OK) == 0)
				return cmdbuf;
		} else {
			/* empty PATH component indicates CWD */
			if (access(argv0, X_OK) == 0)
				return argv0;
		}
	}

	return argv0;
}

char *
wormhole_command_path(const char *argv0)
{
	if (strchr(argv0, '/') == NULL)
		argv0 = wormhole_find_command(argv0);

	return strdup(argv0);
}

pid_t
wormhole_fork_with_socket(int *fdp)
{
	int fdpair[2];
	pid_t pid;

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fdpair) < 0) {
		log_error("%s: socketpair failed: %m", __func__);
		return -1;
	}

	if ((pid = fork()) < 0) {
		log_error("%s: fork failed: %m", __func__);
		close(fdpair[0]);
		close(fdpair[1]);
		return -1;
	}

	if (pid > 0) {
		*fdp = fdpair[0];
		close(fdpair[1]);
	} else {
		close(fdpair[0]);
		*fdp = fdpair[1];
	}

	return pid;
}

static bool
write_single_line(const char *filename, const char *buf)
{
	FILE *fp;

	trace("Writing to %s: %s\n", filename, buf);
	if ((fp = fopen(filename, "w")) == NULL) {
		log_error("Unable to open %s: %m", filename);
		return false;
	}

	fputs(buf, fp);
	if (fclose(fp) == EOF) {
		log_error("Error writing to %s: %m", filename);
		return false;
	}

	return true;
}


/*
 * Create namespace
 */
bool
wormhole_create_namespace(void)
{
	struct stat stb1, stb2;

	if (stat("/proc/self/ns/mnt", &stb1) < 0) {
		log_error("stat(\"/proc/self/ns/mnt\") failed: %m");
		return false;
	}

	if (unshare(CLONE_NEWNS) < 0) {
		log_error("unshare(CLONE_NEWNS) failed: %m");
		return false;
	}

	if (stat("/proc/self/ns/mnt", &stb2) < 0) {
		log_error("stat(\"/proc/self/ns/mnt\") failed: %m");
		return false;
	}
	if (stb1.st_dev == stb2.st_dev && stb1.st_ino == stb2.st_ino) {
		log_error("Something is not quite right");
		return false;
	}

	return true;
}

static bool
write_setgroups(const char *verb)
{
	return write_single_line("/proc/self/setgroups", "deny");
}

static int
write_uid_map(uid_t orig_uid)
{
	char buffer[256];

	snprintf(buffer, sizeof(buffer), "%d %d 1", orig_uid, orig_uid);
	return write_single_line("/proc/self/uid_map", buffer);
}

static int
write_gid_map(gid_t orig_gid)
{
	char buffer[256];

	snprintf(buffer, sizeof(buffer), "%d %d 1", orig_gid, orig_gid);
	return write_single_line("/proc/self/gid_map", buffer);
}

bool
wormhole_create_user_namespace(void)
{
	uid_t orig_uid;
	gid_t orig_gid;

	orig_uid = getuid();
	orig_gid = getgid();

	if (unshare(CLONE_NEWUSER|CLONE_NEWNS) < 0) {
		perror("unshare");
		return false;
	}

	if (!write_uid_map(orig_uid))
		return false;

	if (!write_setgroups("deny"))
		return false;

	if (!write_gid_map(orig_gid))
		return false;

	return true;
}

/*
 * Reap exited children
 */
static bool	have_waiting_children = false;

static void
reaper(int sig)
{
	have_waiting_children = true;
}

void
wormhole_install_sigchild_handler(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = reaper;
	sigaction(SIGCHLD, &act, NULL);
}

pid_t
wormhole_get_exited_child(int *status)
{
	pid_t pid;

	if (!have_waiting_children)
		return -1;

	have_waiting_children = false;
	pid = waitpid(-1, status, WNOHANG);

	if (pid < 0 && errno != ECHILD)
		return pid;

	have_waiting_children = true;
	return pid;
}

bool
wormhole_child_status_okay(int status)
{
	if (WIFSIGNALED(status))
		return false;

	if (!WIFEXITED(status))
		return false;

	return WEXITSTATUS(status) == 0;
}

const char *
wormhole_child_status_describe(int status)
{
	static char msgbuf[128];

	if (WIFSIGNALED(status)) {
		snprintf(msgbuf, sizeof(msgbuf), "crashed with signal %d", WTERMSIG(status));
	} else if (WIFEXITED(status)) {
		snprintf(msgbuf, sizeof(msgbuf), "exited with status %d", WEXITSTATUS(status));
	} else {
		snprintf(msgbuf, sizeof(msgbuf), "weird status word 0x%x", status);
	}
	return msgbuf;
}

void
fsutil_tempdir_init(struct fsutil_tempdir *td)
{
	memset(td, 0, sizeof(*td));
}

char *
fsutil_tempdir_path(struct fsutil_tempdir *td)
{
	if (td->path == NULL) {
		char dirtemplate[PATH_MAX];
		char *tempdir;

		if ((tempdir = getenv("TMPDIR")) == NULL)
			tempdir = "/tmp";
		snprintf(dirtemplate, sizeof(dirtemplate), "%s/mounts.XXXXXX", tempdir);

		tempdir = mkdtemp(dirtemplate);
		if (tempdir == NULL)
			log_fatal("Unable to create tempdir: %m\n");

		td->path = strdup(tempdir);

		if (!fsutil_mount_tmpfs(td->path))
			log_fatal("Unable to mount tmpfs in container: %m\n");

		td->mounted = true;
	}

	return td->path;
}

int
fsutil_tempdir_cleanup(struct fsutil_tempdir *td)
{
	if (td->path == NULL)
		return 0;

	if (td->mounted && umount2(td->path, MNT_DETACH) < 0) {
                log_error("Unable to unmount %s: %m", td->path);
		return -1;
        }

        if (rmdir(td->path) < 0) {
                log_error("Unable to remove temporary mountpoint %s: %m", td->path);
		return -1;
        }

	free(td->path);
	memset(td, 0, sizeof(*td));
	return 0;
}

static int
__fsutil_makedirs(char *path, int mode)
{
	char *slash;
	int ret;

	/* trace("%s(%s)", __func__, path); */
	if (mkdir(path, mode) == 0)
		return 0;

	slash = strrchr(path, '/');
	while (slash > path && slash[-1] == '/')
		--slash;
	slash[0] = '\0';

	ret = __fsutil_makedirs(path, mode);

	slash[0] = '/';
	if (ret >= 0)
		ret = mkdir(path, mode);

	return ret;
}

bool
fsutil_makedirs(const char *path, int mode)
{
	char path_copy[PATH_MAX];

	if (mkdir(path, mode) == 0 || errno == EEXIST)
		return true;

	if (errno != ENOENT)
		return false;

	if (strlen(path) + 1 > sizeof(path_copy)) {
		errno = ENAMETOOLONG;
		return false;
	}

	strcpy(path_copy, path);
	if (__fsutil_makedirs(path_copy, mode) < 0)
		return false;

	return true;
}

bool
fsutil_create_empty(const char *path)
{
	int fd;

	if ((fd = open(path, O_WRONLY|O_CREAT, 0644)) < 0)
		return false;
	close(fd);
	return true;
}

bool
fsutil_check_path_prefix(const char *path, const char *potential_prefix)
{
	unsigned int len;

	if (potential_prefix == NULL || path == NULL)
		return false;

	len = strlen(potential_prefix);
	if (strncmp(path, potential_prefix, len) != 0)
		return false;

	return path[len] == 0 || path[len] == '/';
}

/*
 * Rather special kind of file comparison
 */
int
fsutil_inode_compare(const char *path1, const char *path2)
{
	struct stat stb1, stb2;
	int verdict = FSUTIL_FILE_IDENTICAL;

	if (lstat(path1, &stb1) < 0)
		return FSUTIL_MISMATCH_MISSING;
	if (lstat(path2, &stb2) < 0)
		return FSUTIL_MISMATCH_MISSING;


	if ((stb1.st_mode & S_IFMT) != (stb2.st_mode & S_IFMT))
		return FSUTIL_MISMATCH_TYPE;

	if (S_ISREG(stb1.st_mode)) {
		if (stb1.st_size < stb2.st_size)
			verdict |= FSUTIL_FILE_SMALLER;
		else if (stb1.st_size > stb2.st_size)
			verdict |= FSUTIL_FILE_BIGGER;
	}

	if (stb1.st_mtime < stb2.st_mtime)
		verdict |= FSUTIL_FILE_YOUNGER;
	else if (stb1.st_mtime > stb2.st_mtime)
		verdict |= FSUTIL_FILE_OLDER;

	return verdict;
}

bool
fsutil_mount_overlay(const char *lowerdir, const char *upperdir, const char *workdir, const char *target)
{
	char options[3 * PATH_MAX];
	int flags = 0;

	if (upperdir == NULL) {
		snprintf(options, sizeof(options), "lowerdir=%s", lowerdir);
		flags |= MS_RDONLY;
	} else {
		snprintf(options, sizeof(options), "lowerdir=%s,upperdir=%s,workdir=%s",
				lowerdir, upperdir, workdir);

		/* Try to avoid nasty messages in dmesg */
		if (access(upperdir, W_OK) < 0) {
			trace("Looks like I'm not allowed to write to upperdir %s - mount overlay r/o", upperdir);
			flags |= MS_RDONLY;
		}
	}

	flags |= MS_LAZYTIME | MS_NOATIME;

	if (mount("wormhole", target, "overlay", flags, options) < 0) {
		log_error("Cannot mount overlayfs at %s: %m", target);
		trace("Options string was \"%s\"", options);
		return false;
	}

	trace2("mounted overlay of %s and %s to %s", lowerdir, upperdir, target);
	return true;
}

bool
fsutil_mount_bind(const char *source, const char *target)
{
	if (mount(source, target, NULL, MS_BIND, NULL) < 0) {
		log_error("Unable to bind mount %s to %s: %m", source, target);
		return false;
	}

	trace2("bind mounted %s to %s", source, target);
	return true;
}

bool
fsutil_mount_tmpfs(const char *where)
{
	trace("Mounting tmpfs at %s\n", where);
	if (mount("tmpfs", where, "tmpfs", 0, NULL) < 0)
		return false;

	return true;
}

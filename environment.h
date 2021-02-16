/*
 * environment.h
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

#ifndef _WORMHOLE_ENVIRONMENT_H
#define _WORMHOLE_ENVIRONMENT_H

/* fwd decl */
struct wormhole_profile;

enum {
	WORMHOLE_PATH_TYPE_HIDE,
	WORMHOLE_PATH_TYPE_BIND,
	WORMHOLE_PATH_TYPE_BIND_CHILDREN,
	WORMHOLE_PATH_TYPE_OVERLAY,
	WORMHOLE_PATH_TYPE_OVERLAY_CHILDREN,
	WORMHOLE_PATH_TYPE_WORMHOLE,
};

typedef struct wormhole_path_info {
	int			type;
	char *			path;
} wormhole_path_info_t;


enum {
	WORMHOLE_PATH_STATE_UNCHANGED = 0,
	WORMHOLE_PATH_STATE_SYSTEM_MOUNT,
	WORMHOLE_PATH_STATE_BIND_MOUNTED,
	WORMHOLE_PATH_STATE_OVERLAY_MOUNTED,
	WORMHOLE_PATH_STATE_FAKE_OVERLAY_MOUNTED,
};

typedef struct wormhole_tree_state	wormhole_tree_state_t;
typedef struct wormhole_tree_walker	wormhole_tree_walker_t;
typedef struct wormhole_path_state_node wormhole_path_state_node_t;

typedef struct wormhole_path_state {
	int			state;
	union {
		struct {
			char *	upperdir;
		} overlay;
		struct {
			char *	type;
			char *	device;
		} system_mount;
	};
} wormhole_path_state_t;

#define WORMHOLE_ENVIRONMENT_LAYER_MAX	8

typedef struct wormhole_environment wormhole_environment_t;
struct wormhole_environment {
	wormhole_environment_t *next;
	char *			name;

	struct wormhole_environment_config *config;

	unsigned int		nlayers;
	struct wormhole_overlay_config *layer[WORMHOLE_ENVIRONMENT_LAYER_MAX];

	int			nsfd;
	bool			failed;

	wormhole_tree_state_t *	tree_state;

	/* Information on the sub-daemon for this context. */
	struct {
		char *		socket_name;
		pid_t		pid;
	} sub_daemon;
};

extern wormhole_environment_t *	wormhole_environment_find(const char *name);
extern bool			wormhole_environment_setup(wormhole_environment_t *env);
extern bool			wormhole_environment_async_check(wormhole_environment_t *);
extern struct wormhole_socket *	wormhole_environment_async_setup(wormhole_environment_t *, struct wormhole_profile *);
extern wormhole_environment_t *	wormhole_environment_async_complete(pid_t pid, int status);

extern void			wormhole_environment_set_fd(wormhole_environment_t *env, int fd);

extern wormhole_tree_state_t *	wormhole_tree_state_new(void);
extern void			wormhole_tree_state_free(wormhole_tree_state_t *tree);
extern void			wormhole_tree_state_set_root(wormhole_tree_state_t *tree, const char *root_dir);
extern const char *		wormhole_tree_state_get_root(wormhole_tree_state_t *tree);
extern const wormhole_path_state_t *wormhole_path_tree_get(wormhole_tree_state_t *tree, const char *path);
extern void			wormhole_tree_state_set_system_mount(wormhole_tree_state_t *, const char *path, const char *type, const char *device);
extern void			wormhole_tree_state_set_bind_mounted(wormhole_tree_state_t *, const char *path);
extern void			wormhole_tree_state_set_overlay_mounted(wormhole_tree_state_t *, const char *path, const char *upperdir);
extern void			wormhole_tree_state_set_fake_overlay_mounted(wormhole_tree_state_t *, const char *path, const char *upperdir);
extern void			wormhole_tree_dump(wormhole_tree_state_t *tree);

extern wormhole_tree_walker_t *wormhole_tree_walk(wormhole_tree_state_t *tree);
extern wormhole_path_state_t *	wormhole_tree_walk_next(wormhole_tree_walker_t *t, const char **path_p);
extern void			wormhole_tree_walk_skip_children(wormhole_tree_walker_t *t);
extern void			wormhole_tree_walk_end(wormhole_tree_walker_t *t);

extern wormhole_tree_state_t *	wormhole_get_mount_state(const char *mtab);

#endif // _WORMHOLE_ENVIRONMENT_H
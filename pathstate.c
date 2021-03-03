/*
 * When constructing an overlay environment, keep track of what we've
 * done to which node.
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
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>

#include "wormhole.h"
#include "tracing.h"
#include "environment.h"

#undef DEBUG_PATHSTATE

#ifdef DEBUG_PATHSTATE
# define trace_path		trace3
#else
# define trace_path		notrace
#endif


struct wormhole_tree_state {
	char *				root_dir;

	wormhole_path_state_node_t *	root;
};

struct wormhole_path_state_node {
	wormhole_path_state_node_t *parent;
	wormhole_path_state_node_t *next;

	char *			name;

	wormhole_path_state_t	state;

	wormhole_path_state_node_t *children;
};

static inline void
wormhole_path_state_set_upperdir(wormhole_path_state_t *state, const char *path)
{
	strutil_set(&state->overlay.upperdir, path);
}

static inline void
wormhole_path_state_set_mount_info(wormhole_path_state_t *state, const char *type, const char *device)
{
	strutil_set(&state->system_mount.type, type);
	strutil_set(&state->system_mount.device, device);
}

static void
wormhole_path_state_clear(wormhole_path_state_t *state)
{
	switch (state->state) {
	case WORMHOLE_PATH_STATE_OVERLAY_MOUNTED:
	case WORMHOLE_PATH_STATE_FAKE_OVERLAY_MOUNTED:
		strutil_set(&state->overlay.upperdir, NULL);
		break;
	case WORMHOLE_PATH_STATE_SYSTEM_MOUNT:
		wormhole_path_state_set_mount_info(state, NULL, NULL);
		break;
	}
}

static wormhole_path_state_node_t *
wormhole_path_state_node_new(const char *name, wormhole_path_state_node_t *parent)
{
	wormhole_path_state_node_t *ps;

	ps = calloc(1, sizeof(*ps));

	if (name)
		ps->name = strdup(name);

	if (parent) {
		ps->next = parent->children;
		parent->children = ps;

		ps->parent = parent;
	}

	return ps;
}

static void
wormhole_path_state_node_free(wormhole_path_state_node_t *ps)
{
	wormhole_path_state_node_t *child;

	while ((child = ps->children) != NULL) {
		assert(child->parent == ps);

		ps->children = child->next;
		child->next = NULL;
		child->parent = NULL;

		wormhole_path_state_node_free(child);
	}

	wormhole_path_state_clear(&ps->state);

	if (ps->name)
		free(ps->name);
	free(ps);
}

const char *
__wormhole_path_state_type_string(const wormhole_path_state_t *state)
{
	switch (state->state) {
	case WORMHOLE_PATH_STATE_UNCHANGED:
		return "unchanged";
	case WORMHOLE_PATH_STATE_SYSTEM_MOUNT:
		return "system-mount";
	case WORMHOLE_PATH_STATE_BIND_MOUNTED:
		return "bind-mounted";
	case WORMHOLE_PATH_STATE_OVERLAY_MOUNTED:
		return "overlay-mounted";
	case WORMHOLE_PATH_STATE_FAKE_OVERLAY_MOUNTED:
		return "fake-overlay-mounted";
	}

	return "???";
}

static const char *
__wormhole_path_state_describe(const wormhole_path_state_t *state)
{
	static char buffer[1024];

	switch (state->state) {
	case WORMHOLE_PATH_STATE_SYSTEM_MOUNT:
		snprintf(buffer, sizeof(buffer), "system-mount type=%s device=%s",
				state->system_mount.type,
				state->system_mount.device);
		return buffer;

	case WORMHOLE_PATH_STATE_OVERLAY_MOUNTED:
	case WORMHOLE_PATH_STATE_FAKE_OVERLAY_MOUNTED:
		snprintf(buffer, sizeof(buffer), "%s upperdir=%s",
				__wormhole_path_state_type_string(state),
				state->overlay.upperdir);
		return buffer;
	}

	return __wormhole_path_state_type_string(state);
}

/*
 * Helper function to construct the full path of a path state node
 */
static inline char *
__path_prepend(const char *buf_base, char *buf_pos, const char *name)
{
	unsigned int left, name_len;

	left = buf_pos - buf_base;
	name_len = strlen(name);

	if (name_len + 1 > left)
		return NULL;

	buf_pos -= name_len;
	memcpy(buf_pos, name, name_len);

	*(--buf_pos) = '/';

	return buf_pos;
}

static const char *
wormhole_path_state_node_to_path(const wormhole_path_state_node_t *node)
{
	static char buffer[PATH_MAX];
	char *w;

	w = &buffer[sizeof(buffer) - 1];
	*w = '\0';

	while (node && w && node->name) {
		w = __path_prepend(buffer, w, node->name);
		node = node->parent;
	}

	if (w && *w == '\0')
		return "/";

	return w;
}

wormhole_path_state_node_t *
wormhole_path_state_node_lookup(wormhole_tree_state_t *tree, const char *path, bool create)
{
	wormhole_path_state_node_t *current;
	char *s, *path_copy;

	while (*path == '/')
		++path;

	path_copy = strdup(path);

	current = tree->root;
	for (s = strtok(path_copy, "/"); s && current; s = strtok(NULL, "/")) {
		wormhole_path_state_node_t *child;

		trace_path("Looking for %s below %s", s, wormhole_path_state_node_to_path(current));
		for (child = current->children; child != NULL; child = child->next) {
			if (!strcmp(child->name, s))
				break;
		}

		if (child || !create) {
			current = child;
		} else {
			trace_path("Creating new node \"%s\" as child of %s", s, wormhole_path_state_node_to_path(current));
			current = wormhole_path_state_node_new(s, current);
		}
	}

	free(path_copy);

	trace_path("%s(%s) returns node %s", __func__, path, wormhole_path_state_node_to_path(current));
	return current;
}

wormhole_tree_state_t *
wormhole_tree_state_new(void)
{
	wormhole_tree_state_t *tree;

	tree = calloc(1, sizeof(*tree));
	tree->root = wormhole_path_state_node_new(NULL, NULL);
	return tree;
}

void
wormhole_tree_state_free(wormhole_tree_state_t *tree)
{
	wormhole_path_state_node_free(tree->root);
	strutil_set(&tree->root_dir, NULL);
	free(tree);
}

void
wormhole_tree_state_set_root(wormhole_tree_state_t *tree, const char *root_dir)
{
	strutil_set(&tree->root_dir, root_dir);
}

const char *
wormhole_tree_state_get_root(wormhole_tree_state_t *tree)
{
	return tree->root_dir;
}

const wormhole_path_state_t *
wormhole_path_tree_get(wormhole_tree_state_t *tree, const char *path)
{
	wormhole_path_state_node_t *ps;

	ps = wormhole_path_state_node_lookup(tree, path, false);
	if (ps == NULL)
		return NULL;

	return &ps->state;
}

static inline wormhole_path_state_node_t *
__wormhole_tree_state_set(wormhole_tree_state_t *tree, const char *path, int new_state)
{
	wormhole_path_state_node_t *ps;

	ps = wormhole_path_state_node_lookup(tree, path, true);
	assert(ps);

	wormhole_path_state_clear(&ps->state);

	ps->state.state = new_state;
	return ps;
}

void
wormhole_tree_state_clear(wormhole_tree_state_t *tree, const char *path)
{
	/* trace2("path state unchanged at %s", path); */
	__wormhole_tree_state_set(tree, path, WORMHOLE_PATH_STATE_UNCHANGED);
}

void
wormhole_tree_state_set_system_mount(wormhole_tree_state_t *tree, const char *path, const char *type, const char *device)
{
	wormhole_path_state_node_t *ps;

	trace2("path state system_mount at %s", path);
	ps = __wormhole_tree_state_set(tree, path, WORMHOLE_PATH_STATE_SYSTEM_MOUNT);
	wormhole_path_state_set_mount_info(&ps->state, type, device);
}

void
wormhole_tree_state_set_bind_mounted(wormhole_tree_state_t *tree, const char *path)
{
	trace2("path state bind_mounted at %s", path);
	__wormhole_tree_state_set(tree, path, WORMHOLE_PATH_STATE_BIND_MOUNTED);
}

void
wormhole_tree_state_set_overlay_mounted(wormhole_tree_state_t *tree, const char *path, const char *upperdir)
{
	wormhole_path_state_node_t *ps;

	trace("path state overlay_mounted at %s: upper=%s", path, upperdir);
	ps = __wormhole_tree_state_set(tree, path, WORMHOLE_PATH_STATE_OVERLAY_MOUNTED);
	wormhole_path_state_set_upperdir(&ps->state, upperdir);
}

void
wormhole_tree_state_set_fake_overlay_mounted(wormhole_tree_state_t *tree, const char *path, const char *upperdir)
{
	wormhole_path_state_node_t *ps;

	trace("path state fake_overlay_mounted at %s: upper=%s", path, upperdir);
	ps = __wormhole_tree_state_set(tree, path, WORMHOLE_PATH_STATE_FAKE_OVERLAY_MOUNTED);
	wormhole_path_state_set_upperdir(&ps->state, upperdir);
}

void
wormhole_tree_state_set_ignore(wormhole_tree_state_t *tree, const char *path)
{
	trace2("path state ignored at %s", path);
	__wormhole_tree_state_set(tree, path, WORMHOLE_PATH_STATE_IGNORED);
}

void
wormhole_tree_state_set_user_data(wormhole_tree_state_t *tree, const char *path, void *user_data)
{
	wormhole_path_state_node_t *ps;

	ps = wormhole_path_state_node_lookup(tree, path, true);
	ps->state.user_data = user_data;
}

void *
wormhole_tree_state_get_user_data(wormhole_tree_state_t *tree, const char *path)
{
	wormhole_path_state_node_t *ps;

	ps = wormhole_path_state_node_lookup(tree, path, false);
	if (ps == NULL)
		return NULL;
	return ps->state.user_data;
}

struct wormhole_tree_walker {
	wormhole_tree_state_t *		tree;
	wormhole_path_state_node_t *	pos;
	bool				skip_children;
};

void
wormhole_tree_dump(wormhole_tree_state_t *tree)
{
	wormhole_path_state_node_t *node = tree->root;
	unsigned int indent = 0;

	while (node) {
#if 0
		printf("%*.*s%2d %s\n", indent, indent, "",
				node->state.state,
				wormhole_path_state_node_to_path(node));
#else
		printf("%*.*s%s (%s)\n", indent, indent, "", node->name?: "/", __wormhole_path_state_describe(&node->state));
#endif

		if (node->children) {
			node = node->children;
			indent ++;
		} else {
			while (node) {
				if (node->next) {
					node = node->next;
					break;
				}

				node = node->parent;
				indent --;
			};
		}
	}
}

wormhole_tree_walker_t *
wormhole_tree_walk(wormhole_tree_state_t *tree)
{
	wormhole_tree_walker_t *t;

	t = calloc(1, sizeof(*t));
	t->tree = tree;
	t->pos = tree->root;

	/* wormhole_tree_dump(tree); */

	return t;
}

void
wormhole_tree_walk_end(wormhole_tree_walker_t *t)
{
	memset(t, 0, sizeof(*t));
	free(t);
}

static wormhole_path_state_node_t *
__traverse_right(wormhole_path_state_node_t *node)
{
	do {
		trace_path("looking for siblings of %s", wormhole_path_state_node_to_path(node));
		if (node->next) {
			node = node->next;
			break;
		}

		trace_path("no more siblings of %s, going up", wormhole_path_state_node_to_path(node));

		node = node->parent;
	} while (node);

	return node;
}

static wormhole_path_state_node_t *
__traverse_down(wormhole_path_state_node_t *node, bool skip_children)
{
	trace_path("%s(%s)", __func__, wormhole_path_state_node_to_path(node));
	while (node) {
		if (node->children && !skip_children) {
			trace_path(" inspecting children of %s (%d)", wormhole_path_state_node_to_path(node), node->state.state);
			node = node->children;
		} else {
			node = __traverse_right(node);
		}

		if (node && node->state.state > 0)
			break;

		skip_children = false;
	}

	return node;
}

wormhole_path_state_t *
wormhole_tree_walk_next(wormhole_tree_walker_t *t, const char **path_p)
{
	wormhole_path_state_node_t *node;
	const char *path;

	if (t->pos == NULL)
		return NULL;

	if (!(node = __traverse_down(t->pos, t->skip_children))) {
		t->pos = NULL;
		return NULL;
	}

	t->skip_children = false;
	t->pos = node;

	path = wormhole_path_state_node_to_path(node);

	if (path_p)
		*path_p = path;

	trace_path("%s() returns %s", __func__, path);
	return &node->state;
}

void
wormhole_tree_walk_skip_children(wormhole_tree_walker_t *t)
{
	trace_path("Going to skip children of %s", wormhole_path_state_node_to_path(t->pos));
	t->skip_children = true;
}

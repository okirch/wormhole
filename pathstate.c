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
	wormhole_path_state_node_t *	root;
};

struct wormhole_path_state_node {
	wormhole_path_state_node_t *parent;
	wormhole_path_state_node_t *next;

	char *			name;

	wormhole_path_state_t	state;

	wormhole_path_state_node_t *children;
};

static void
__set_string(char **var, const char *value)
{
	if (*var) {
		free(*var);
		*var = NULL;
	}

	if (value)
		*var = strdup(value);
}

static inline void
wormhole_path_state_set_upperdir(wormhole_path_state_t *state, const char *path)
{
	__set_string(&state->overlay.upperdir, path);
}

static inline void
wormhole_path_state_set_mount_info(wormhole_path_state_t *state, const char *type, const char *device)
{
	__set_string(&state->system_mount.type, type);
	__set_string(&state->system_mount.device, device);
}

static void
wormhole_path_state_clear(wormhole_path_state_t *state)
{
	switch (state->state) {
	case WORMHOLE_PATH_STATE_OVERLAY_MOUNTED:
	case WORMHOLE_PATH_STATE_FAKE_OVERLAY_MOUNTED:
		__set_string(&state->overlay.upperdir, NULL);
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
	free(tree);
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

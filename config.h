/*
 * config.h
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

#ifndef _WORMHOLE_CONFIG_H
#define _WORMHOLE_CONFIG_H

struct wormhole_profile_config {
	struct wormhole_profile_config *next;

	char *			name;
	char *			wrapper;
	char *			command;
	char *			environment;
};

enum {
	WORMHOLE_LAYER_TYPE_LAYER,
	WORMHOLE_LAYER_TYPE_REFERENCE,
	WORMHOLE_LAYER_TYPE_IMAGE,
};

struct wormhole_layer_config {
	struct wormhole_layer_config *next;

	int			type;

	char *			directory;
	char *			image;
	char *			lower_layer_name;

	bool			use_ldconfig;

	unsigned int		npaths;
	wormhole_path_info_t *	path;
};

struct wormhole_environment_config {
	struct wormhole_environment_config *next;

	char *			name;

	struct wormhole_layer_config *layers;
};

struct wormhole_config {
	char *			client_path;
	struct wormhole_profile_config *profiles;
	struct wormhole_environment_config *environments;
};

extern struct wormhole_config *	wormhole_config_load(const char *filename);
extern void			wormhole_config_free(struct wormhole_config *cfg);

extern wormhole_path_info_t *	wormhole_layer_config_add_path(struct wormhole_layer_config *layer, int type, const char *path);

#endif // _WORMHOLE_CONFIG_H


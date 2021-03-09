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

#include "types.h"

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

	struct strutil_array	provides;
	struct strutil_array	requires;

	struct wormhole_layer_config *layers;
};

struct wormhole_config {
	struct wormhole_config *next;

	/* Path the config file was loaded from */
	char *			path;

	/* Pathname to the wormhole client 
	 * XXX is this really needed?
	 */
	char *			client_path;

	struct wormhole_profile_config *profiles;
	struct wormhole_environment_config *environments;
};

extern const struct wormhole_config *wormhole_config_get(const char *filename);
extern struct wormhole_config *	wormhole_config_load(const char *filename);
extern bool			wormhole_config_write(const struct wormhole_config *cfg, const char *filename);
extern void			wormhole_config_free(struct wormhole_config *cfg);

extern wormhole_path_info_t *	wormhole_layer_config_add_path(struct wormhole_layer_config *layer, int type, const char *path);
extern bool			wormhole_path_info_set_mount_fstype(wormhole_path_info_t *pi, const char *fstype);
extern bool			wormhole_path_info_set_mount_device(wormhole_path_info_t *pi, const char *device);
extern bool			wormhole_path_info_set_mount_options(wormhole_path_info_t *pi, const char *options);

#endif // _WORMHOLE_CONFIG_H


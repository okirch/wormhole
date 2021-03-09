/*
 * wormhole.h
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

#ifndef _WORMHOLE_H
#define _WORMHOLE_H

#define WORMHOLE_SOCKET_PATH		"/var/run/wormhole.sock"
#define WORMHOLE_AUTOPROFILE_DIR_PATH	"/etc/wormhole"
#define WORMHOLE_CONFIG_PATH		"/etc/wormhole/wormhole.conf"
#define WORMHOLE_USER_CONFIG_PATH	"~/.wormhole/config"
#define WORMHOLE_CLIENT_PATH		"/usr/bin/wormhole"

#define WORMHOLE_CAPABILITY_PATH	"/var/lib/wormhole/capability"
#define WORMHOLE_COMMAND_REGISTRY_PATH	"/var/lib/wormhole/command"

extern void		wormhole_common_load_config(const char *opt_config_path);


/*
 * The following is really socket-client stuff...
 */

struct wormhole_message_namespace_response;
typedef bool		wormhole_namespace_response_callback_fn_t(struct wormhole_message_namespace_response *msg, int nsfd, void *closure);

extern int		wormhole_client(int argc, char **argv);

extern bool		wormhole_client_namespace_request(const char *query_string,
					wormhole_namespace_response_callback_fn_t *callback, void *closure);

#endif // _WORMHOLE_H


/*
 * protocol.h
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

#ifndef _WORMHOLE_PROTOCOL_H
#define _WORMHOLE_PROTOCOL_H

#include <stdint.h>
#include "buffer.h"

struct wormhole_message {
	uint16_t	version;
	uint16_t	reserved;
	uint16_t	opcode;
	uint16_t	payload_len;
};

#define WORMHOLE_PROTOCOL_VERSION_MAJOR	0
#define WORMHOLE_PROTOCOL_VERSION_MINOR	1
#define WORMHOLE_PROTOCOL_VERSION	((WORMHOLE_PROTOCOL_VERSION_MAJOR << 8) | WORMHOLE_PROTOCOL_VERSION_MINOR)
#define WORMHOLE_PROTOCOL_STRING_MAX	128

#define WORMHOLE_PROTOCOL_MAJOR(v)	((v) >> 8)
#define WORMHOLE_PROTOCOL_MINOR(v)	((v) & 0xFF)

enum {
	WORMHOLE_OPCODE_STATUS = 0,

	WORMHOLE_OPCODE_NAMESPACE_REQUEST = 1,
	WORMHOLE_OPCODE_NAMESPACE_RESPONSE = 2,
};

enum {
	WORMHOLE_STATUS_OK = 0,
	WORMHOLE_STATUS_ERROR = 1,
};

struct wormhole_message_status {
	uint32_t		status;
};

struct wormhole_message_namespace_request {
	char *			profile;
};

struct wormhole_message_namespace_response {
	uint32_t		status;

	char *			command;
	char *			server_socket;
	char **			environment_vars;
};

struct wormhole_message_parsed {
	struct wormhole_message	hdr;
	union {
		struct wormhole_message_status status;
		struct wormhole_message_namespace_request namespace_request;
		struct wormhole_message_namespace_response namespace_response;
	} payload;
};

extern struct buf *	wormhole_message_build_status(unsigned int status);
extern struct buf *	wormhole_message_build_namespace_request(const char *name);
extern struct buf *	wormhole_message_build_namespace_response(unsigned int status,
					const char *cmd, const char **env,
					const char *socket_name);

extern bool		wormhole_message_complete(struct buf *bp);
extern struct wormhole_message_parsed *wormhole_message_parse(struct buf *bp, uid_t sender_uid);
extern void		wormhole_message_free_parsed(struct wormhole_message_parsed *pmsg);

#endif // _WORMHOLE_PROTOCOL_H



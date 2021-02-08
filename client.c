/*
 * client.c
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
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "tracing.h"
#include "wormhole.h"
#include "protocol.h"
#include "socket.h"
#include "util.h"
#include "buffer.h"

/* Note - the socket handling is a bit hodge podge here.
 * I'm currently using some code from socket.c, because I'm lazy and don't want to
 * write another copy of the SCM_RIGHTS handling stuff here.
 * On the other hand, pulling lots of code from socket.c into a setuid binary makes
 * it harder to audit this stuff, so I may end up doing just that...
 */

static int
wormhole_send_namespace_request(wormhole_socket_t *s, const char *cmd)
{
	struct buf *bp;
	int rv = 0;

	bp = wormhole_message_build_namespace_request(cmd);
	rv = send(s->fd, buf_head(bp), buf_available(bp), 0);
	if (rv < 0)
		log_error("send: %m");

	buf_free(bp);
	return rv;
}

static struct buf *
wormhole_recv_response(wormhole_socket_t *s, int *resp_fd)
{
	struct buf *bp = buf_alloc();

	*resp_fd = -1;
	while (!wormhole_message_complete(bp)) {
		int received, fd;

		received = wormhole_socket_recvmsg(s->fd, buf_tail(bp), buf_tailroom(bp), &fd);
		if (received < 0) {
			log_error("recvmsg: %m");
			goto failed;
		}

		if (received == 0) {
			log_error("%s: EOF on socket while waiting for complete message", __func__);
			goto failed;
		}

		__buf_advance_tail(bp, received);
		if (fd >= 0)
			*resp_fd = fd;
	}

	return bp;

failed:
	if (*resp_fd >= 0) {
		close(*resp_fd);
		*resp_fd = -1;
	}
	buf_free(bp);
	return NULL;
}

bool
wormhole_client_namespace_request(const char *query_string,
		wormhole_namespace_response_callback_fn_t *callback, void *closure)
{
	wormhole_socket_t *s = NULL;
	struct wormhole_message_parsed *pmsg = NULL;
	struct buf *bp = NULL;
	int nsfd = -1;
	bool rv = false;

	s = wormhole_connect(WORMHOLE_SOCKET_PATH, NULL);
	if (s == NULL) {
		log_error("Unable to connect to wormhole daemon");
		goto failed;
	}

	if (wormhole_send_namespace_request(s, query_string) < 0)
		goto failed;

	if (!(bp = wormhole_recv_response(s, &nsfd)))
		goto failed;

	pmsg = wormhole_message_parse(bp, 0);
	if (pmsg == NULL) {
		log_error("Unable to parse server response!");
		goto failed;
	}

	switch (pmsg->hdr.opcode) {
	case WORMHOLE_OPCODE_STATUS:
		if (pmsg->payload.status.status != WORMHOLE_STATUS_OK) {
			log_error("Server returns error status %d!", pmsg->payload.status.status);
			goto failed;
		}
		break;

	case WORMHOLE_OPCODE_NAMESPACE_RESPONSE:
		if (pmsg->payload.namespace_response.status != WORMHOLE_STATUS_OK) {
			log_error("Server returns error status %d!", pmsg->payload.namespace_response.status);
			goto failed;
		}

		if (nsfd < 0) {
			log_error("Server did not send us a namespace FD");
			goto failed;
		}

		rv = callback(&pmsg->payload.namespace_response, nsfd, closure);
		break;

	default:
		log_error("Unexpected opcode %d in server response!", pmsg->hdr.opcode);
		goto failed;
	}

failed:
	if (pmsg)
		wormhole_message_free_parsed(pmsg);
	if (bp)
		buf_free(bp);
	if (nsfd >= 0)
		close(nsfd);
	return rv;
}

/*
 * wormhole - socket handling
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

#ifndef _WORMHOLE_SOCKET_H
#define _WORMHOLE_SOCKET_H

#include "buffer.h"

struct pollfd;

typedef struct wormhole_socket wormhole_socket_t;

struct wormhole_socket {
	wormhole_socket_t **prevp;
	wormhole_socket_t *next;

	unsigned int	id;
	int		fd;

	const struct wormhole_socket_ops {
		bool	(*poll)(wormhole_socket_t *, struct pollfd *);
		bool	(*process)(wormhole_socket_t *, struct pollfd *);
	} *ops;

	struct wormhole_app_ops {
		void	(*new_socket)(wormhole_socket_t *);
		bool	(*received)(wormhole_socket_t *, struct buf *, int);
	} *app_ops;

	/* FIXME: add idle timeout */
	time_t		timeout;

	uid_t		uid;
	gid_t		gid;

	bool		recv_closed;
	bool		send_closed;

	struct buf *	recvbuf;
	int		recvfd;

	struct buf *	sendbuf;
	int		sendfd;
};

#define WORMHOLE_SOCKET_MAX	1024

extern wormhole_socket_t * wormhole_sockets;
extern unsigned int		wormhole_socket_count;

extern wormhole_socket_t *	wormhole_listen(const char *path, struct wormhole_app_ops *app_ops);
extern wormhole_socket_t *	wormhole_connect(const char *path, struct wormhole_app_ops *app_ops);

extern wormhole_socket_t *	wormhole_accept_connection(int fd);
extern wormhole_socket_t *	wormhole_socket_find(unsigned int id);
extern void			wormhole_socket_fail(wormhole_socket_t *);
extern void			wormhole_socket_free(wormhole_socket_t *conn);
extern wormhole_socket_t *	wormhole_connected_socket_new(int fd, uid_t uid, gid_t gid);

extern void			wormhole_drop_recvbuf(wormhole_socket_t *s);
extern void			wormhole_drop_sendbuf(wormhole_socket_t *s);
extern void			wormhole_drop_recvfd(wormhole_socket_t *s);
extern void			wormhole_drop_sendfd(wormhole_socket_t *s);

extern void			wormhole_socket_enqueue(wormhole_socket_t *s, struct buf *bp, int fd);

extern void			wormhole_install_socket(wormhole_socket_t *);
extern void			wormhole_uninstall_socket(wormhole_socket_t *);

extern int			wormhole_socket_recvmsg(int fd, void *buffer, size_t buf_sz, int *fdp);
extern int			wormhole_socket_sendmsg(int sock_fd, void *payload, unsigned int payload_len, int fd);

#endif // _WORMHOLE_SOCKET_H

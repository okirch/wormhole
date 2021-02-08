/*
 * buffer.h
 *
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

#ifndef _BUF_H
#define _BUF_H

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#define BUF_SZ		1024
#define QUEUE_SZ	(64 * BUF_SZ)

struct buf {
	struct buf *	next;
	unsigned char	data[BUF_SZ];
	unsigned int	head, tail;
};

struct queue {
	unsigned long	size;
	struct buf *	head;
};

extern struct buf *	buf_alloc(void);
extern void		buf_free(struct buf *bp);
extern unsigned int	buf_put(struct buf *bp, const void *p, unsigned int len);
extern unsigned long	buf_get(struct buf *bp, void *p, unsigned long size);
extern void		buf_consumed(struct buf **list, unsigned long amount);

extern void		queue_init(struct queue *);
extern void		queue_destroy(struct queue *);
extern unsigned long	queue_available(const struct queue *);
extern unsigned long	queue_tailroom(const struct queue *);
extern bool		queue_full(const struct queue *);
extern void		queue_append(struct queue *, const void *, size_t);
extern const void *	queue_get(struct queue *q, void *p, size_t count);
extern const void *	queue_peek(const struct queue *q, void *p, size_t count);
extern void		queue_advance_head(struct queue *q, size_t count);
extern void		queue_transfer(struct queue *dstq, struct queue *srcq, size_t count);

static inline unsigned int
buf_tailroom(const struct buf *bp)
{
	return BUF_SZ - bp->tail;
}

static inline unsigned int
buf_available(const struct buf *bp)
{
	return bp->tail - bp->head;
}

static inline const void *
buf_head(const struct buf *bp)
{
	if (bp->head == bp->tail)
		return NULL;

	return bp->data + bp->head;
}

static inline void
__buf_advance_head(struct buf *bp, unsigned int len)
{
	assert(bp->tail - bp->head >= len);
	bp->head += len;
}

static inline void *
buf_tail(struct buf *bp)
{
	if (bp->tail == BUF_SZ)
		return NULL;

	return bp->data + bp->tail;
}

static inline void
__buf_advance_tail(struct buf *bp, unsigned int len)
{
	assert(BUF_SZ - bp->tail >= len);
	bp->tail += len;
}

static inline void
buf_zap(struct buf *bp)
{
	bp->head = bp->tail = 0;
}

#endif /* _BUF_H */

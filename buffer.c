/*
 * buffer.c
 *
 * Buffer handling functions
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "buffer.h"

struct buf *
buf_alloc(void)
{
	struct buf *bp;

	bp = calloc(1, sizeof(*bp));
	return bp;
}

void
buf_free(struct buf *bp)
{
	memset(bp, 0xaa, sizeof(*bp));
	free(bp);
}

unsigned int
buf_put(struct buf *bp, const void *p, unsigned int len)
{
	unsigned int space;

	space = buf_tailroom(bp);
	if (space < len)
		len = space;

	memcpy(bp->data + bp->tail, p, len);
	bp->tail += len;

	return len;
}

unsigned long
buf_get(struct buf *bp, void *p, unsigned long size)
{
	unsigned long total = 0;

	while (bp != NULL && total < size) {
		unsigned int avail;
		struct buf *next;

		assert(bp);
		next = bp->next;

		avail = buf_available(bp);
		if (total + avail > size) {
			avail = size - total;
			next = NULL;
		}

		memcpy(p + total, buf_head(bp), avail);

		total += avail;
		size -= avail;

		bp = next;
	}

	return total;
}

void
buf_consumed(struct buf **list, unsigned long amount)
{
	struct buf *bp;

	while (amount) {
		unsigned int avail;

		bp = *list;
		assert(bp);

		avail = buf_available(bp);
		if (avail > amount) {
			__buf_advance_head(bp, amount);
			return;
		}

		amount -= avail;
		*list = bp;
		buf_free(bp);
	}
}

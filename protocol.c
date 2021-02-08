/*
 * wormhole wire protocol
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


#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "protocol.h"
#include "tracing.h"

#define PROTOCOL_TRACING

#define WORMHOLE_PROTO_TYPE_INT32	'i'
#define WORMHOLE_PROTO_TYPE_STRING	's'
#define WORMHOLE_PROTO_TYPE_ARRAY	'A'

struct buf *
wormhole_message_build(int opcode, const struct buf *payload)
{
	unsigned int payload_len = buf_available(payload);
	struct wormhole_message msg;
	struct buf *bp = buf_alloc();

	if (payload_len >= 0x10000)
		return NULL;

	memset(&msg, 0, sizeof(msg));
	msg.version = htons(WORMHOLE_PROTOCOL_VERSION);
	msg.opcode = htons(opcode);
	msg.payload_len = htons(payload_len);

	buf_put(bp, &msg, sizeof(msg));

	/* Now copy the payload into the message */
	if (payload_len) {
		const void *data = buf_head(payload);

		if (!buf_put(bp, data, payload_len))
			return NULL;
	}
	return bp;
}

static inline bool
__wormhole_message_put_type_and_size(struct buf *bp, char type, size_t len)
{
	unsigned char size;

	if (len >= 256)
		return false;
	size = len;

	return buf_put(bp, &type, 1)
	    && buf_put(bp, &size, 1);
}

static inline bool
__wormhole_message_put(struct buf *bp, char type, const void *datum, size_t len)
{
	return __wormhole_message_put_type_and_size(bp, type, len)
	    && buf_put(bp, datum, len);
}

static inline bool
wormhole_message_put_int32(struct buf *bp, uint32_t value)
{
	value = htonl(value);

	return __wormhole_message_put(bp, WORMHOLE_PROTO_TYPE_INT32, &value, sizeof(value));
}

static inline bool
__wormhole_buffer_get(struct buf *bp, void *ptr, size_t len)
{
	if (!buf_get(bp, ptr, len))
		return false;
	__buf_advance_head(bp, len);
	return true;
}

static inline char
__wormhole_message_get_type_and_size(struct buf *bp, size_t *size_p)
{
	unsigned char type, size;

	if (!__wormhole_buffer_get(bp, &type, 1) || !__wormhole_buffer_get(bp, &size, 1))
		return '\0';

	if (type != WORMHOLE_PROTO_TYPE_INT32
	 && type != WORMHOLE_PROTO_TYPE_STRING
	 && type != WORMHOLE_PROTO_TYPE_ARRAY)
		return '\0';

	*size_p = size;
	return type;
}

static inline bool
wormhole_message_get_int32(struct buf *bp, uint32_t *value)
{
	size_t size;

	if (__wormhole_message_get_type_and_size(bp, &size) != WORMHOLE_PROTO_TYPE_INT32)
		return false;

	if (size != sizeof(*value))
		return false;

	if (!__wormhole_buffer_get(bp, value, size))
		return false;

	*value = ntohl(*value);
	return true;
}

static inline bool
wormhole_message_put_string(struct buf *bp, const char *s)
{
	if (s == NULL)
		s = "";
	return __wormhole_message_put(bp, WORMHOLE_PROTO_TYPE_STRING, s, strlen(s) + 1);
}

static inline char *
wormhole_message_get_string(struct buf *bp)
{
	size_t size;
	char *ret;

	if (__wormhole_message_get_type_and_size(bp, &size) != WORMHOLE_PROTO_TYPE_STRING)
		return false;

	if (size == 0)
		return false;

	/* Extract the NUL terminated string from the buffer */
	ret = malloc(size);
	if (__wormhole_buffer_get(bp, ret, size) && ret[size - 1] == '\0')
		return ret;

	free(ret);
	return NULL;
}

static bool
wormhole_message_put_string_array(struct buf *bp, const char **array)
{
	unsigned int i, count;

	if (array == NULL)
		return __wormhole_message_put_type_and_size(bp, WORMHOLE_PROTO_TYPE_ARRAY, 0);

	for (count = 0; array[count]; ++count)
		;

	if (!__wormhole_message_put_type_and_size(bp, WORMHOLE_PROTO_TYPE_ARRAY, count))
		return false;

	for (i = 0; i < count; ++i) {
		if (!wormhole_message_put_string(bp, array[i]))
			return false;
	}

	return true;
}

static inline void
wormhole_message_free_string_array(char **array)
{
	unsigned int i;

	for (i = 0; array[i]; ++i)
		free(array[i]);
	free(array);
}

static char **
wormhole_message_get_string_array(struct buf *bp)
{
	size_t count;
	unsigned int i;
	char **ret;

	if (__wormhole_message_get_type_and_size(bp, &count) != WORMHOLE_PROTO_TYPE_ARRAY)
		return NULL;

	ret = calloc(count + 1, sizeof(ret[0]));
	for (i = 0; i < count; ++i) {
		ret[i] = wormhole_message_get_string(bp);
		if (ret[i] == NULL)
			goto failed;
	}

	return ret;

failed:
	wormhole_message_free_string_array(ret);
	return NULL;
}

struct buf *
wormhole_message_build_status(unsigned int status)
{
	struct buf *payload = buf_alloc();
	struct buf *msg = NULL;

	if (wormhole_message_put_int32(payload, status))
		msg =  wormhole_message_build(WORMHOLE_OPCODE_STATUS, payload);

	buf_free(payload);
	return msg;
}

static bool
wormhole_message_parse_status(struct buf *payload, struct wormhole_message_parsed *pmsg)
{
	return wormhole_message_get_int32(payload, &pmsg->payload.status.status);
}

struct buf *
wormhole_message_build_namespace_request(const char *name)
{
	struct buf *payload = buf_alloc();
	struct buf *msg = NULL;

	if (wormhole_message_put_string(payload, name))
		msg = wormhole_message_build(WORMHOLE_OPCODE_NAMESPACE_REQUEST, payload);

	buf_free(payload);
	return msg;
}

static bool
wormhole_message_parse_namespace_request(struct buf *payload, struct wormhole_message_namespace_request *msg)
{
	msg->profile = wormhole_message_get_string(payload);
	if (msg->profile == NULL)
		return false;

	return true;
}

static void
wormhole_message_destroy_namespace_request(struct wormhole_message_namespace_request *msg)
{
	if (msg->profile != NULL)
		free(msg->profile);
}

struct buf *
wormhole_message_build_namespace_response(unsigned int status, const char *cmd, const char **env,
		const char *socket_name)
{
	struct buf *payload = buf_alloc();
	struct buf *msg = NULL;

	if (!wormhole_message_put_int32(payload, status))
		goto done;

	if (status == WORMHOLE_STATUS_OK) {
		if (!wormhole_message_put_string(payload, cmd))
			goto done;

		if (!wormhole_message_put_string(payload, socket_name))
			goto done;

		if (!wormhole_message_put_string_array(payload, env))
			goto done;
	}

	msg = wormhole_message_build(WORMHOLE_OPCODE_NAMESPACE_RESPONSE, payload);

done:
	buf_free(payload);
	return msg;
}

static bool
wormhole_message_parse_namespace_response(struct buf *payload, struct wormhole_message_namespace_response *msg)
{
	if (!wormhole_message_get_int32(payload, &msg->status))
		return false;

	if (msg->status == WORMHOLE_STATUS_OK) {
		msg->command = wormhole_message_get_string(payload);
		if (msg->command == NULL)
			return false;

		msg->server_socket = wormhole_message_get_string(payload);
		if (msg->server_socket == NULL)
			return false;

		msg->environment_vars = wormhole_message_get_string_array(payload);
		if (msg->environment_vars == NULL)
			return false;
	}

	return true;
}

static void
wormhole_message_destroy_namespace_response(struct wormhole_message_namespace_response *msg)
{
	if (msg->command != NULL)
		free(msg->command);
	if (msg->server_socket != NULL)
		free(msg->server_socket);

	if (msg->environment_vars != NULL)
		wormhole_message_free_string_array(msg->environment_vars);
}

static inline bool
__wormhole_message_protocol_compatible(const struct wormhole_message *msg)
{
	return (WORMHOLE_PROTOCOL_MAJOR(msg->version) == WORMHOLE_PROTOCOL_VERSION_MAJOR);
}

static bool
__wormhole_message_dissect_header(struct buf *bp, struct wormhole_message *msg, bool consume)
{
	unsigned int hdrlen = sizeof(struct wormhole_message);

	if (buf_get(bp, msg, hdrlen) < hdrlen)
		return false;

	msg->version = ntohs(msg->version);
	msg->opcode = ntohs(msg->opcode);
	msg->payload_len = ntohs(msg->payload_len);

	if (buf_available(bp) < hdrlen + msg->payload_len)
		return false;

	if (consume)
		__buf_advance_head(bp, hdrlen);

	return true;
}

static struct buf *
wormhole_message_get_payload(struct buf *bp, struct wormhole_message_parsed *pmsg)
{
	unsigned int payload_len = pmsg->hdr.payload_len;
	struct buf *payload;

	if (buf_available(bp) < payload_len) {
		trace("%s: hdr.payload_len = %u exceeds available data from buffer (%u bytes)",
				payload_len, buf_available(bp));
		return NULL;
	}

	/* Copy the message payload to a separate buffer. */
	payload = buf_alloc();
	if (!buf_put(payload, buf_head(bp), payload_len)) {
		buf_free(payload);
		return NULL;
	}

	/* Consume the message payload */
	__buf_advance_head(bp, payload_len);

	return payload;
}


bool
wormhole_message_complete(struct buf *bp)
{
	struct wormhole_message msg;

	return __wormhole_message_dissect_header(bp, &msg, false);
}

struct wormhole_message_parsed *
wormhole_message_parse(struct buf *bp, uid_t sender_uid)
{
	struct wormhole_message_parsed *pmsg;
	struct buf *payload = NULL;

	pmsg = calloc(1, sizeof(*pmsg));

	if (!__wormhole_message_dissect_header(bp, &pmsg->hdr, true)) {
		/* should not happen. */
		log_fatal("%s: unable to parse message header", __func__);
	}

#ifdef PROTOCOL_TRACING
	trace("Received message header: protocol version %u opcode %u payload_len %u",
			pmsg->hdr.version,
			pmsg->hdr.opcode,
			pmsg->hdr.payload_len);
#endif

	if (!__wormhole_message_protocol_compatible(&pmsg->hdr)) {
                log_error("message from uid %d: incompatible protocol message (version 0x%x)",
				sender_uid, pmsg->hdr.version);
                goto failed;
        }

	if (pmsg->hdr.payload_len > BUF_SZ) {
		log_error("message from uid %d: payload of %u bytes too big",
				sender_uid, pmsg->hdr.payload_len);
		goto failed;
	}

	if (!(payload = wormhole_message_get_payload(bp, pmsg)))
		goto failed;

#ifdef PROTOCOL_TRACING
	if (tracing_level >= 2) {
		unsigned int i, base, count = buf_available(payload);
		const unsigned char *data = buf_head(payload);

		printf("Dump of message payload (%u bytes)\n", count);
		for (base = 0; base < count; base += 16) {
			printf("%04x:", base);
			for (i = 0; base + i < count && i < 16; ++i) {
				printf(" %02x", data[base + i]);
			}
			while (i++ < 16)
				printf("   ");

			printf("     ");
			for (i = 0; base + i < count && i < 16; ++i) {
				char cc = data[base + i];

				if (isprint(cc))
					printf("%c", cc);
				else
					printf(".");
			}
			printf("\n");
		}
	}
#endif

	switch (pmsg->hdr.opcode) {
	case WORMHOLE_OPCODE_STATUS:
		if (!wormhole_message_parse_status(payload, pmsg))
			goto failed;
		break;

	case WORMHOLE_OPCODE_NAMESPACE_REQUEST:
		if (!wormhole_message_parse_namespace_request(payload, &pmsg->payload.namespace_request))
			goto failed;
		break;

	case WORMHOLE_OPCODE_NAMESPACE_RESPONSE:
		if (!wormhole_message_parse_namespace_response(payload, &pmsg->payload.namespace_response))
			goto failed;
		break;

	default:
		log_error("message from uid %d: unexpected opcode %d", sender_uid, pmsg->hdr.opcode);
		goto failed;
	}

	if (payload)
		buf_free(payload);

	return pmsg;

failed:
	wormhole_message_free_parsed(pmsg);
	if (payload)
		buf_free(payload);
	return NULL;
}

void
wormhole_message_free_parsed(struct wormhole_message_parsed *pmsg)
{
	switch (pmsg->hdr.opcode) {
	case WORMHOLE_OPCODE_NAMESPACE_REQUEST:
		wormhole_message_destroy_namespace_request(&pmsg->payload.namespace_request);
		break;

	case WORMHOLE_OPCODE_NAMESPACE_RESPONSE:
		wormhole_message_destroy_namespace_response(&pmsg->payload.namespace_response);
		break;
	}

	free(pmsg);
}

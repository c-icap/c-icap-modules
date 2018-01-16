/*
 *  Copyright (C) 2011 Christos Tsantilas
 *  email: christos@chtsanti.net
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "common.h"
#include "body.h"
#include "request.h"
#include "debug.h"
#include "srv_body.h"
#include "simple_api.h"
#include <assert.h>
#include <errno.h>


int membody_decode(char *inbuf, size_t inlen, ci_membuf_t *outbuf, ci_off_t max_size, int encodeMethod)
{
    if (encodeMethod == CI_ENCODE_NONE)
        return 0;

    if (!inbuf || inlen == 0)
        return 0;

    int ret = 0;
#if defined(HAVE_CICAP_DECOMPRESS_TO)
    ret = ci_decompress_to_membuf(encodeMethod, inbuf, inlen, outbuf, max_size);
#else
    if (encodeMethod == CI_ENCODE_GZIP || encodeMethod == CI_ENCODE_DEFLATE)
        ret = ci_inflate_to_membuf(inbuf, inlen, outbuf, max_size);
    else if (encodeMethod == CI_ENCODE_BZIP2)
        ret = ci_bzunzip_to_membuf(inbuf, inlen, outbuf, max_size);
#if defined(HAVE_CICAP_BROTLI)
    else if (encodeMethod == CI_ENCODE_BROTLI) 
        ret = ci_brinflate_to_membuf(inbuf, inlen, outbuf, max_size);
#endif
#endif
    if (ret != CI_UNCOMP_OK)
        return 0;

    return 1;
}


#if 0
int do_url_decode(char *input, size_t inlen, ci_membuf_t *outbuf, ci_off_t max_size)
{
    int i, k;
    char str[3];
    char output[512];

    i = 0;
    k = 0;
    while ((input[i] != '\0') && i < inlen) {
	if (input[i] == '%'){
	    str[0] = input[i+1];
	    str[1] = input[i+2];
	    str[2] = '\0';
	    out[k] = strtol(str, NULL, 16);
	    i = i + 3;
	}
	else if (input[i] == '+') {
	    out[k] = ' ';
	    i++;
	}
	else {
	    out[k] = input[i];
	    i++;
	}
	k++;
        if (k == 512) {
            ci_membuf_write(outbuf, out, k, 0);
            k = 0;
        }
    }
    // write the remaining amount of data:
    ci_membuf_write(outbuf, out, k, 0);
    return CI_OK;
}
#endif

void srv_cf_body_init(srv_cf_body_t *body)
{
    body->body = NULL;
    body->decoded = NULL;
    body->ring = NULL;
    body->eof = 0;
    body->size = 0;
}

int srv_cf_body_build(srv_cf_body_t *body, size_t size)
{
    body->body = ci_membuf_new_sized(size);
    body->decoded = NULL;
    body->ring = NULL;
    body->eof = 0;
    body->size = 0;
    return 1;
}

void srv_cf_body_free(srv_cf_body_t *body)
{
    if (!body)
        return;

    if (body->ring)
        free(body->ring);
    if(body->body)
	ci_membuf_free(body->body);
    if(body->decoded)
	ci_membuf_free(body->decoded);
}

int srv_cf_body_write(srv_cf_body_t *body, char *data, size_t data_size, int iseof)
{
    int wlen;
    if (!body->body)
        return 0;

    if (iseof)
        body->eof = 1;

    if (body->ring)
        wlen = ci_ring_buf_write(body->ring, data, data_size);
    else
        wlen =  ci_membuf_write(body->body, data, data_size, iseof);

    if (wlen > 0)
        body->size += wlen;
    return wlen;
}

int srv_cf_body_read(srv_cf_body_t *body, char *data, size_t size)
{
    if (!body->body)
        return 0;

    if (body->ring)
        return ci_ring_buf_read(body->ring, data, size);

    return ci_membuf_read(body->body, data, size);
}

size_t srv_cf_body_readpos(srv_cf_body_t *body)
{
    if (!body->body)
        return 0;
    return body->body->readpos;
}

ci_membuf_t *srv_cf_body_decoded_membuf(srv_cf_body_t *body,int encoding_method, size_t maxBodyData)
{
    if (encoding_method != CI_ENCODE_NONE) {
        char *body_data = body->body->buf;
        size_t body_data_len = body->body->endpos;
        ci_membuf_t *outbuf = ci_membuf_new_sized(maxBodyData);

        if (CI_OK == membody_decode(body_data, body_data_len, outbuf, maxBodyData, encoding_method)) {
            body->decoded = outbuf;
            return outbuf;
        }
        else {
            ci_debug_printf(1, "Failed to decode encoded data!\n");
            ci_membuf_free(outbuf);
        }
    }

    return body->body;
}

void srv_cf_body_replace_body(srv_cf_body_t *body, ci_membuf_t *new_body)
{
    if (body->decoded) {
        ci_membuf_free(body->decoded);
        body->decoded = NULL;
    }
    if (body->ring) {
        free(body->ring);
        body->ring = NULL;
    }
    ci_membuf_free(body->body);
    body->body = new_body;
}

int srv_cf_body_to_ring(srv_cf_body_t *body)
{
    if (body->ring)
        return 0;

    assert(body->body->readpos == 0);

    body->ring = malloc(sizeof(ci_ring_buf_t));
    body->ring->buf = body->body->buf;
    body->ring->end_buf = body->body->buf + body->body->bufsize - 1;
    body->ring->read_pos = body->body->buf;
    /*The next write will be at the begining*/
    if (body->body->endpos == body->body->bufsize)
        body->ring->write_pos = body->body->buf;
    else
        body->ring->write_pos = body->body->buf + body->body->endpos;

    /*If we have not read anything on membuf, then it is full*/
    if (body->ring->write_pos == body->ring->read_pos && body->body->endpos)
        body->ring->full = 1;
    else
        body->ring->full = 0;

    return 1;
}

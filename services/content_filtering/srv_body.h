/*
 *  Copyright (C) 2012 Christos Tsantilas
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

#ifndef  SRV_BODY_H
#define SRV_BODY_H
//c-icap
#include "c_icap/body.h"

typedef struct srv_cf_body {
    ci_membuf_t *body;
    ci_membuf_t *decoded;
    ci_ring_buf_t *ring;
    int eof;
    int64_t size;
} srv_cf_body_t;

void srv_cf_body_init(srv_cf_body_t *body);
int srv_cf_body_build(srv_cf_body_t *body, size_t size);
void srv_cf_body_free(srv_cf_body_t *body);
int srv_cf_body_write(srv_cf_body_t *body, char *data, size_t size, int iseof);
int srv_cf_body_read(srv_cf_body_t *body, char *data, size_t size);

size_t srv_cf_body_readpos(srv_cf_body_t *body);
ci_membuf_t *srv_cf_body_decoded_membuf(srv_cf_body_t *body, int encoding_method, size_t maxBodyData);
void srv_cf_body_replace_body(srv_cf_body_t *body, ci_membuf_t *new_body);
int srv_cf_body_to_ring(srv_cf_body_t *body);

int membody_decode(char *inbuf, size_t inlen, ci_membuf_t *outbuf, ci_off_t max_size, int encodeMethod);

#endif

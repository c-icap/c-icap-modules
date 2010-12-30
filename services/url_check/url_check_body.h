/*
 *  Copyright (C) 2010 Christos Tsantilas
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

#include "body.h"

enum body_type {NO_BODY_TYPE=0, CACHED, RING};

struct body_data {
    union {
        ci_cached_file_t *cached;
        ci_ring_buf_t *ring;
    } store;
    enum body_type type;
    int eof;
};

#define body_data_haseof(body) (body->type==RING?body->eof : ci_cached_file_haseof(body->store.cached))
int body_data_init(struct body_data *bd, enum body_type type,  int size);
void body_data_destroy(struct body_data *body);
int body_data_write(struct body_data *body, char *buf, int len, int iseof);
int body_data_read(struct body_data *body, char *buf, int len);

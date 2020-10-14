/*
 *  Copyright (C) 2012 Christos Tsantilas
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

#ifndef AV_BODY_DATA_H
#define AV_BODY_DATA_H

#include "body.h"

enum av_body_type {AV_BT_NONE=0, AV_BT_FILE, AV_BT_MEM};

struct av_body_data {
    union {
        ci_simple_file_t *file;
        ci_membuf_t *mem;
    } store;
    int buf_exceed;
    ci_simple_file_t *decoded;
    enum av_body_type type;
};

#define av_body_data_lock_all(bd) { if ((bd)->type == AV_BT_FILE) ci_simple_file_lock_all((bd)->store.file); }
#define av_body_data_unlock(bd, len) { if ((bd)->type == AV_BT_FILE) ci_simple_file_unlock((bd)->store.file, len); }
#define av_body_data_unlock_all(bd) { if ((bd)->type == AV_BT_FILE) ci_simple_file_unlock_all((bd)->store.file); }
#define av_body_data_size(bd) ((bd)->type == AV_BT_FILE ? (bd)->store.file->endpos : ((bd)->type == AV_BT_MEM ? (bd)->store.mem->endpos : 0))

void av_body_data_new(struct av_body_data *bd, enum av_body_type type,  int size);
void av_body_data_named(struct av_body_data *bd, const char *dir, const char *name);
void av_body_data_destroy(struct av_body_data *body);
void av_body_data_release(struct av_body_data *body);
int av_body_data_write(struct av_body_data *body, char *buf, int len, int iseof);
int av_body_data_read(struct av_body_data *body, char *buf, int len);

int av_decompress_to_simple_file(int encodingMethod, const char *inbuf, size_t inlen, struct ci_simple_file *outfile, ci_off_t max_size);
#endif

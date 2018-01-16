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

#include "av_body.h"
#include "c_icap/simple_api.h"
#include "../../common.h"
#include <assert.h>

void av_body_data_new(struct av_body_data *bd, enum av_body_type type,  int size)
{
    if (type == AV_BT_FILE) {
        bd->store.file = ci_simple_file_new(size);
        if (bd->store.file)
            bd->type = type;
    }
    else if (type == AV_BT_MEM) {
        bd->store.mem = ci_membuf_new_sized(size);
        if (bd->store.mem)
            bd->type = type;
    }
    else
        bd->type = AV_BT_NONE;
    bd->buf_exceed = 0;
    bd->decoded = NULL;
}

void av_body_data_named(struct av_body_data *bd, const char *dir, const char *name)
{
    bd->store.file = ci_simple_file_named_new((char *)dir, (char *)name, 0);
    if (bd->store.file)
        bd->type = AV_BT_FILE;
    else
        bd->type = AV_BT_NONE;

    bd->buf_exceed = 0;
}

void av_body_data_destroy(struct av_body_data *body)
{
    if (body->type == AV_BT_NONE)
        return; /*Nothing to do*/
    if (body->type == AV_BT_FILE) {
        ci_simple_file_destroy(body->store.file);
        body->store.file = NULL;
        body->type = AV_BT_NONE;
    }
    else if (body->type == AV_BT_MEM) {
        ci_membuf_free(body->store.mem);
        body->store.mem = NULL;
        body->type = AV_BT_NONE;
    }
    if (body->decoded) {
        ci_simple_file_destroy(body->decoded);
        body->decoded = NULL;
    }
}

void av_body_data_release(struct av_body_data *body)
{
    /*This is make sense only for ci_simple_file_t objects.
      Means that the file will be closed but not removed from disk
      It is used only in vir_mode.
     */
    assert(body->type == AV_BT_FILE);
    ci_simple_file_release(body->store.file);
    body->store.file = NULL;
    body->type = AV_BT_NONE;
    if (body->decoded) {
        ci_simple_file_destroy(body->decoded);
        body->decoded = NULL;
    }
}

int av_body_data_write(struct av_body_data *body, char *buf, int len, int iseof)
{
    int memsize;
    if (body->type == AV_BT_FILE)
        return ci_simple_file_write(body->store.file, buf, len, iseof);
    else if (body->type == AV_BT_MEM) {
        if (body->buf_exceed)
            return 0; /*or just consume everything?*/
        memsize = body->store.mem->bufsize - body->store.mem->endpos;
        if (memsize < len) {
            body->buf_exceed = 1;
            return 0;
        }
        return ci_membuf_write(body->store.mem, buf, len, iseof);
    }
    return 0;
}

int av_body_data_read(struct av_body_data *body, char *buf, int len)
{
    if (body->type == AV_BT_FILE)
        return ci_simple_file_read(body->store.file, buf, len);
    else if (body->type == AV_BT_MEM)
        return ci_membuf_read(body->store.mem, buf, len);
    return 0;
}

int av_decompress_to_simple_file(int encodeMethod, const char *inbuf, size_t inlen, struct ci_simple_file *outfile, ci_off_t max_size)
{
#if defined(HAVE_CICAP_DECOMPRESS_TO)
    return ci_decompress_to_simple_file(encodeMethod, inbuf, inlen, outfile, max_size);
#else
    if (encodeMethod == CI_ENCODE_GZIP || encodeMethod == CI_ENCODE_DEFLATE)
        return ci_inflate_to_simple_file(inbuf, inlen, outfile, max_size);
    else if (encodeMethod == CI_ENCODE_BZIP2)
        return ci_bzunzip_to_simple_file(inbuf, inlen, outfile, max_size);
#if defined(HAVE_CICAP_BROTLI)
    else if (encodeMethod == CI_ENCODE_BROTLI)
        return ci_brinflate_to_simple_file(inbuf, inlen, outfile, max_size);
#endif
#endif
    return CI_UNCOMP_ERR_ERROR;
}

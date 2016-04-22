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
#include <assert.h>
#include <errno.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif
#ifdef HAVE_BZLIB
#include <bzlib.h>
#endif

#ifdef HAVE_BZLIB
static int do_mem_bzunzip(const char *buf, int inlen, ci_membuf_t *outbuf, ci_off_t max_size);
#endif
#ifdef HAVE_ZLIB
static int do_mem_inflate(char *inbuf, size_t inlen, ci_membuf_t *outbuf, ci_off_t max_size);
#endif
//static int do_url_decode(char *inbuf, size_t inlen, ci_membuf_t *outbuf, ci_off_t max_size);
int membody_decode(char *inbuf, size_t inlen, ci_membuf_t *outbuf, ci_off_t max_size, enum EncodeMethod encodeMethod)
{
    if (encodeMethod == emNone)
        return 0;

    if (!inbuf || inlen == 0)
        return 0;

    int ret = 0;
    if (encodeMethod == emZlib)
        ret = do_mem_inflate(inbuf, inlen, outbuf, 2*1024*1024);
#ifdef HAVE_BZLIB
    else if (encodeMethod == emBzlib)
        ret = do_mem_bzunzip(inbuf, inlen, outbuf, 2*1024*1024);
#endif

    if (ret <= 0)
        return 0;

    return 1;
}

#ifdef HAVE_ZLIB
static void *alloc_a_buffer(void *op, unsigned int items, unsigned int size)
{
    return ci_buffer_alloc(items*size);
}

static void free_a_buffer(void *op, void *ptr)
{
    ci_buffer_free(ptr);
}

enum {
    INFL_ERR_BOMB = -4,
    INFL_ERR_CORRUPT = -3,
    INFL_ERR_OUTPUT = -2,
    INFL_ERR_ERROR = -1,
    INFL_ERR_NONE = 0, 
    INFL_OK = 1, 
};

static const char *inflate_errors[] = {
    "zlib: No Error",
    "zlib: Inflate Failure",
    "zlib: Write Failed",
    "zlib: Corrupted",
    "zlib: Compression Bomb"
};

const char *do_mem_inflate_error(int err)
{
    ci_debug_printf (3, "Inflate error %d\n", err);
    if (err < INFL_ERR_NONE && err >= INFL_ERR_BOMB)
        return inflate_errors[-err];
    return "No Error";
}

#define CHUNK 8192
/*return:
  1 on success
  -1 on error
  0 if max_size reached.
 */
int do_mem_inflate(char *inbuf, size_t inlen, ci_membuf_t *outbuf, ci_off_t max_size) {
    int ret, retriable;
    unsigned have, written;
    ci_off_t outsize;
    z_stream strm;
    unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = alloc_a_buffer;
    strm.zfree = free_a_buffer;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit2(&strm, 32 + 15);
    if (ret != Z_OK)
        return INFL_ERR_ERROR;

    retriable = 1;
    outsize = 0;
    strm.next_in = (unsigned char*)inbuf;
    strm.avail_in = inlen;

    /* run inflate() on input until output buffer not full */
    do {
    do_mem_inflate_retry:
        strm.avail_out = CHUNK;
        strm.next_out = out;
        ret = inflate(&strm, Z_NO_FLUSH);
        assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
        switch (ret) {
        case Z_NEED_DICT:
        case Z_DATA_ERROR:
            if (retriable) {
                ret = inflateInit2(&strm, -15);
                retriable = 0;
                if (ret == Z_OK) {
                    strm.avail_in = inlen;
                    strm.next_in = (unsigned char *)inbuf;
                    goto do_mem_inflate_retry;
                }
                /*else let fail ...*/
            }
        case Z_MEM_ERROR:
            inflateEnd(&strm);
            return INFL_ERR_CORRUPT;
        }
        retriable = 0; // No more retries allowed
        have = CHUNK - strm.avail_out;
        if ((written = ci_membuf_write(outbuf, (char *)out, have, 0)) != have) {
            inflateEnd(&strm);
            return INFL_ERR_OUTPUT;
        }
        outsize += written;
        if (max_size > 0 && outsize > max_size) {
            inflateEnd(&strm);
            if ( (outsize/inlen) > 100) {
                ci_debug_printf(1, "Compression ratio UncompSize/CompSize = %" PRINTF_OFF_T "/%" PRINTF_OFF_T " = %" PRINTF_OFF_T "! Is it a zip bomb? aborting!\n", (CAST_OFF_T)outsize, (CAST_OFF_T)inlen, (CAST_OFF_T)(outsize/inlen));
                return INFL_ERR_BOMB;  /*Probably compression bomb object*/
            }
            else {
                ci_debug_printf(4, "Object is bigger than max allowed file\n");
                return INFL_ERR_NONE;
            }
        }
    } while (strm.avail_out == 0);
    
    /* done when inflate() says it's done */
    assert(ret == Z_STREAM_END);
    ci_membuf_write(outbuf, (char *)out, 0, 1);

    /* clean up and return */
    inflateEnd(&strm);
    return ret == Z_STREAM_END ? INFL_OK : INFL_ERR_CORRUPT;
}
#endif

#ifdef HAVE_BZLIB
static void *bzalloc_a_buffer(void *op, int items, int size)
{
    return ci_buffer_alloc(items*size);
}

static void bzfree_a_buffer(void *op, void *ptr)
{
    ci_buffer_free(ptr);
}

static int do_mem_bzunzip(const char *buf, int inlen, ci_membuf_t *outbuf, ci_off_t max_size)
{
    /*we can use  BZ2_bzBuffToBuffDecompress but we need to use our buffer_alloc interface...*/
     int ret;
     unsigned have, written;
     ci_off_t outsize;
     bz_stream strm;
     char out[CHUNK];

     strm.bzalloc = bzalloc_a_buffer;
     strm.bzfree = bzfree_a_buffer;
     strm.opaque = NULL;
     strm.avail_in = 0;
     strm.next_in = NULL;
     ret = BZ2_bzDecompressInit(&strm, 0, 0);
     if (ret != BZ_OK) {
          ci_debug_printf(1,
                          "Error initializing  bzlib (BZ2_bzDeompressInit return:%d)\n",
                          ret);
          return CI_ERROR;
     }

     strm.next_in = (char *)buf;
     strm.avail_in = inlen;

     outsize = 0;

     do {
         strm.avail_out = CHUNK;
         strm.next_out = out;
         ret = BZ2_bzDecompress(&strm);
         switch (ret) {
         case BZ_PARAM_ERROR:
         case BZ_DATA_ERROR:
         case BZ_DATA_ERROR_MAGIC:
         case BZ_MEM_ERROR:
             BZ2_bzDecompressEnd(&strm);
             return CI_ERROR;
         }

         have = CHUNK - strm.avail_out;
         if (!have || (written = ci_membuf_write(outbuf, (char *)out, have, 0)) != have) {
             BZ2_bzDecompressEnd(&strm);
             return INFL_ERR_OUTPUT;
         }
         outsize += written;
         if (max_size > 0 && outsize > max_size) {
             BZ2_bzDecompressEnd(&strm);
             if ( (outsize/inlen) > 100) {
                 ci_debug_printf(1, "Compression ratio UncompSize/CompSize = %" PRINTF_OFF_T "/%" PRINTF_OFF_T " = %" PRINTF_OFF_T "! Is it a zip bomb? aborting!\n", (CAST_OFF_T)outsize, (CAST_OFF_T)inlen, (CAST_OFF_T)(outsize/inlen));
                 return INFL_ERR_BOMB;  /*Probably compression bomb object*/
             }
             else {
                 ci_debug_printf(4, "Object is bigger than max allowed file\n");
                 return INFL_ERR_NONE;
             }
         }
     } while (strm.avail_out == 0);
     

     BZ2_bzDecompressEnd(&strm);
     return CI_OK;
}
#endif

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
    if (encoding_method != emNone) {
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

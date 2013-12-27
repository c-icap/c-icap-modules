/*
 *  Copyright (C) 2011 Christos Tsantilas
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

#include "c_icap/c-icap.h"
#include "c_icap/body.h"
#include "c_icap/mem.h"
#include "c_icap/debug.h"
#include "../../common.h"
#include <errno.h>
#include <assert.h>
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef HAVE_ZLIB
static void *alloc_a_buffer(void *op, unsigned int items, unsigned int size){
    return ci_buffer_alloc(items*size);
}

static void free_a_buffer(void *op, void *ptr){
    ci_buffer_free(ptr);
}

static int do_file_write(ci_simple_file_t *fout, const void *buf, size_t count) {
    int bytes, to_write;
    errno = 0;
    to_write = (int)count;
    do {
        bytes = ci_simple_file_write(fout, buf, to_write, 0);
        if (bytes > 0) {
            buf += bytes;
            to_write -= bytes;
        } else /* will result to decoding error */
            return 0;
    } while (to_write > 0);

    return count;
}

static int do_file_read(int fd, void *buf, size_t count) {
    int bytes;
    errno = 0;
    do {
        bytes = read(fd, buf, count);
    }while ( bytes < 0 && errno == EINTR);

    return bytes;
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

const char *virus_scan_inflate_error(int err)
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
int virus_scan_inflate(int fin, ci_simple_file_t *fout, ci_off_t max_size) {
    int ret, retriable;
    unsigned have, written;
    ci_off_t insize, outsize;
    z_stream strm;
    unsigned char in[CHUNK];
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
    insize = 0;
    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = do_file_read(fin, in, CHUNK);
        if (strm.avail_in < 0) {
            (void)inflateEnd(&strm);
            return INFL_ERR_ERROR;
        }
        if (strm.avail_in == 0) {
            break;
        }
        strm.next_in = in;
        insize += strm.avail_in;

        /* run inflate() on input until output buffer not full */
        do {
virus_scan_inflate_retry:
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
                       strm.avail_in = insize;
                       strm.next_in = in;
                       goto virus_scan_inflate_retry;
                    }
                    /*else let fail ...*/
                }
            case Z_MEM_ERROR:
                inflateEnd(&strm);
                return INFL_ERR_CORRUPT;
            }
            retriable = 0; // No more retries allowed
            have = CHUNK - strm.avail_out;
            if ((written = do_file_write(fout, out, have)) != have) {
                inflateEnd(&strm);
                return INFL_ERR_OUTPUT;
            }
            outsize += written;
            if (max_size > 0 && outsize > max_size) {
                inflateEnd(&strm);
                if ( (outsize/insize) > 100) {
                    ci_debug_printf(1, "Compression ratio UncompSize/CompSize = %" PRINTF_OFF_T "/%" PRINTF_OFF_T " = %" PRINTF_OFF_T "! Is it a zip bomb? aborting!\n", (CAST_OFF_T)outsize, (CAST_OFF_T)insize, (CAST_OFF_T)(outsize/insize));
                    return INFL_ERR_BOMB;  /*Probably compression bomb object*/
                }
                else {
                    ci_debug_printf(4, "Object is bigger than max scannable file\n");
                    return INFL_ERR_NONE;
                }
            }
        } while (strm.avail_out == 0);

        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    ci_simple_file_write(fout, NULL, 0, 1);
    /* clean up and return */
    inflateEnd(&strm);
    return ret == Z_STREAM_END ? INFL_OK : INFL_ERR_CORRUPT;
}

int virus_scan_inflate_mem(void *mem, size_t mem_size, ci_simple_file_t *fout, ci_off_t max_size){
    int ret;
    unsigned have, written;
    ci_off_t insize, outsize;
    z_stream strm;
      unsigned char out[CHUNK];

    /* allocate inflate state */
    strm.zalloc = alloc_a_buffer;
    strm.zfree = free_a_buffer;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
        return INFL_ERR_ERROR;

    outsize = 0;
    insize = 0;
    /* decompress until deflate stream ends or end of file */
    strm.next_in = mem;
    strm.avail_in = mem_size;
    insize += strm.avail_in;

    /* run inflate() on input until output buffer not full */
    do {
        strm.avail_out = CHUNK;
        strm.next_out = out;
        ret = inflate(&strm, Z_NO_FLUSH);
        assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
        switch (ret) {
        case Z_NEED_DICT:
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
            inflateEnd(&strm);
            return INFL_ERR_CORRUPT;
        }
        have = CHUNK - strm.avail_out;
        if ((written = do_file_write(fout, out, have)) != have) {
            inflateEnd(&strm);
            return INFL_ERR_OUTPUT;
        }
        outsize += written;
        if (max_size > 0 && outsize > max_size) {
            inflateEnd(&strm);
            if ( (outsize/insize) > 100) {
                ci_debug_printf(1, "Compression ratio UncompSize/CompSize = %" PRINTF_OFF_T "/%" PRINTF_OFF_T " = %" PRINTF_OFF_T "! Is it a zip bomb? aborting!\n", (CAST_OFF_T)outsize, (CAST_OFF_T)insize, (CAST_OFF_T)(outsize/insize));
                return INFL_ERR_BOMB;  /*Probably compression bomb object*/
            }
            else {
                ci_debug_printf(4, "Object is bigger than max scannable file\n");
                return INFL_ERR_NONE;
            }
        }
    } while (strm.avail_out == 0);

    ci_simple_file_write(fout, NULL, 0, 1);
    /* clean up and return */
    inflateEnd(&strm);
    return ret == Z_STREAM_END ? INFL_OK : INFL_ERR_CORRUPT;
}

#endif

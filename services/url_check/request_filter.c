/*
 *  Copyright (C) 2015 Christos Tsantilas
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
#include "c_icap/header.h"
#include "c_icap/simple_api.h"
#include "c_icap/debug.h"
#include "c_icap/array.h"
#include "c_icap/txt_format.h"

#include "request_filter.h"
#include "../../common.h"

static int SRV_UC_FILTERS_REGISTRY_ID = -1;

void url_check_free_request_filters(ci_list_t *request_filters)
{
    struct cfg_request_filter flt;
    if (!request_filters)
        return;

    memset(&flt, 0, sizeof(struct cfg_request_filter));
    while(ci_list_pop(request_filters, &flt) != NULL) {
         if (flt.filter && flt.filter->free)
              flt.filter->free(flt.data);
    }
    ci_list_destroy(request_filters);
}


/************************/
/*  HttpHeaderAddIfNone */
/************************/

struct http_header_data {
     char *head;
     char *value;
};

extern struct ci_fmt_entry srv_urlcheck_format_table [];
int http_header_addIfNone_cb(const struct cfg_request_filter *flt, ci_request_t *req)
{
     char buf[1024];
     int bytes;
     ci_headers_list_t *heads;
     struct http_header_data *data = (struct http_header_data *) flt->data;

     heads = ci_http_request_headers(req);
     if (!heads || ci_headers_search(heads, data->head))
          return 0;
     bytes = snprintf(buf, sizeof(buf), "%s: ", data->head);
     if (bytes >= sizeof(buf))
          return 0;
     if (ci_format_text(req, data->value, buf + bytes, sizeof(buf) - bytes, srv_urlcheck_format_table))
          ci_headers_add(heads, buf);
     return 1;
}

void *http_header_cfg(const char **argv)
{
     if (!argv[0] || !argv[1] || !argv[2])
          return NULL;

     struct http_header_data *data = malloc(sizeof(struct http_header_data));
     data->head = strdup(argv[1]);
     data->value = strdup(argv[2]);
     return data;
}

void http_header_free(void *d)
{
     struct http_header_data *data = (struct http_header_data *)d;
     free(data->head);
     free(data->value);
     free(data);
}

/************************/
/*  HttpHeaderRemove    */

int http_header_remove_cb(const struct cfg_request_filter *flt, ci_request_t *req)
{
     ci_headers_list_t *heads;
     const char *head = (const char *)flt->data;
     heads = ci_http_request_headers(req);
     if (heads && ci_headers_remove(heads, head))
          return 1;
     return 0;
}

void *http_header_remove_cfg(const char **argv)
{
     if (!argv[0] || !argv[1])
          return NULL;
     return strdup(argv[1]);
}

void http_header_remove_free(void *data)
{
     free(data);
}

int http_header_listadd_cb(const struct cfg_request_filter *flt, ci_request_t *req)
{
     char buf[65536];
     int bytes;
     ci_headers_list_t *heads;
     struct http_header_data *data = (struct http_header_data *) flt->data;

     heads = ci_http_request_headers(req);
     if (!heads)
          return 0;
     const char *val = ci_headers_search(heads, data->head);
     bytes = snprintf(buf, sizeof(buf), "%s: %s%s", data->head, val ? val : "", val && *val != '\0' ? ", " : "");
     if (bytes >= sizeof(buf))
          return 0;
     if (ci_format_text(req, data->value, buf + bytes, sizeof(buf) - bytes, srv_urlcheck_format_table))
          ci_headers_add(heads, buf);
     return 1;
}

int http_header_replace_cb(const struct cfg_request_filter *flt, ci_request_t *req)
{
     char buf[1024];
     int bytes;
     ci_headers_list_t *heads;
     struct http_header_data *data = (struct http_header_data *) flt->data;

     if (!(heads = ci_http_response_headers(req)))
          heads = ci_http_request_headers(req);
     if (!heads)
          return 0;

     bytes = snprintf(buf, sizeof(buf), "%s: ", data->head);
     if (bytes >= sizeof(buf))
          return 0;

     if (ci_headers_search(heads, data->head))
          ci_headers_remove(heads, data->head);

     if (ci_format_text(req, data->value, buf + bytes, sizeof(buf) - bytes, srv_urlcheck_format_table))
          ci_headers_add(heads, buf);
     return 1;
}

struct request_filter_cb_data{
    ci_request_t *req;
    int error;
    int modified;
};

static int request_filter_cb(void *data, const void *item)
{
     int ret;
     const struct cfg_request_filter *flt = (const struct cfg_request_filter *) item;
     struct request_filter_cb_data *d = (struct request_filter_cb_data *)data;
     ci_request_t *req = d->req;
     if (flt && flt->filter && flt->filter->filter_cb) {
          ret = flt->filter->filter_cb(flt, req);
          if (ret < 0) {
               d->error = 1;
               return  1;
          } else if (ret != 0)
               d->modified = 1;
     }
     return 0;
}

unsigned int url_check_request_filters_apply(ci_request_t *req, ci_list_t *request_filters)
{
    struct request_filter_cb_data data;
    if (!request_filters)
        return SRV_UC_ACT_NONE;
    data.req = req;
    data.error = 0;
    data.modified = 0;
    ci_list_iterate(request_filters, (void *)&data, request_filter_cb);
    return data.modified ? SRV_UC_ACT_HEADMOD : SRV_UC_ACT_NONE;
}

int url_check_request_filters_cfg_parse(ci_list_t **request_filters, const char **argv)
{
     struct cfg_request_filter req_filter;
     void *data;

     if (!request_filters)
          return 0;

     const url_check_req_filter_t *fdef= ci_registry_id_get_item(SRV_UC_FILTERS_REGISTRY_ID, argv[0]);

     if (fdef) {
         ci_debug_printf(8, "Request filter %s matched configure it\n", argv[0]);
         data = fdef->cfg(argv);
         if (!data) {
             ci_debug_printf(1, "ERROR: wrong arguments after: %s\n", argv[0]);
             return 0;
         }
         if (!*request_filters)
             *request_filters = ci_list_create(128*sizeof(struct cfg_request_filter), sizeof(struct cfg_request_filter));
         req_filter.filter = fdef;
         req_filter.data = data;
         ci_list_push_back(*request_filters, &req_filter);
         return 1;
     }

     return 0;
}

url_check_req_filter_t headerAddIfNone = {
    "HttpHeaderAddIfNone",
     http_header_addIfNone_cb,
     http_header_cfg,
     http_header_free
};

url_check_req_filter_t headerListAdd = {
    "HttpHeaderListAdd",
    http_header_listadd_cb,
    http_header_cfg,
    http_header_free
};

url_check_req_filter_t headerRemove = {
    "HttpHeaderRemove",
    http_header_remove_cb,
    http_header_remove_cfg,
    http_header_remove_free
};

url_check_req_filter_t headerReplace = {
    "HttpHeaderReplace",
    http_header_replace_cb,
    http_header_cfg,
    http_header_free
};


int url_check_request_filters_init()
{
    SRV_UC_FILTERS_REGISTRY_ID = ci_registry_create(SRV_UC_FILTERS_REGISTRY);
    srv_uc_register_req_filter(&headerAddIfNone);
    srv_uc_register_req_filter(&headerListAdd);
    srv_uc_register_req_filter(&headerRemove);
    srv_uc_register_req_filter(&headerReplace);
    return 1;
}

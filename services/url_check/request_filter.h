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

#ifndef __REQUEST_FILTER_H
#define __REQUEST_FILTER_H

#include "c_icap/registry.h"

enum url_check_http_methods {
    UC_METHOD_UNKNOWN = 0,
    UC_HTTP_GET,
    UC_HTTP_POST,
    UC_HTTP_PUT,
    UC_HTTP_HEAD,
    UC_HTTP_CONNECT,
    UC_HTTP_TRACE,
    UC_HTTP_OPTIONS,
    UC_HTTP_DELETE,
    UC_METHOD_END
};

enum url_check_proto {UC_PROTO_UNKNOWN=0, UC_PROTO_HTTP, UC_PROTO_HTTPS, UC_PROTO_FTP};

#define MAX_URL_SIZE  65536

struct url_check_http_info {
    int http_major;
    int http_minor;
    int method;
    unsigned int port;
    int proto;
    int transparent;   /*If it is a transparent request or not*/
    char host[CI_MAXHOSTNAMELEN + 1];
    char server_ip[64];                   /*I think ipv6 address needs about 32 bytes*/
    char site[CI_MAXHOSTNAMELEN + 1];
    char raw_url[MAX_URL_SIZE]; /*The url*/
    size_t raw_url_size;
    char *url; /*pointer to the part of the url after the protocol specification (after "://")*/
    char *args; /*pointer to the arguments part of the urls (after the '?') */
};

#define SRV_UC_ACT_ERROR      0xFFFFFFFF
#define SRV_UC_ACT_NONE       0x00
#define SRV_UC_ACT_ABORT      0x01
#define SRV_UC_ACT_ERRORPAGE  0x02
#define SRV_UC_ACT_HEADMOD    0x04
#define SRV_UC_ACT_REQMOD     0x08

#define SRV_UC_ACT_MODIFIED (SRV_UC_ACT_ERRORPAGE | SRV_UC_ACT_HEADMOD | SRV_UC_ACT_REQMOD)

struct url_check_action {
    const char *name;
    const char *action_str;
    unsigned int (*action)(ci_request_t *req, const struct url_check_action *act, const void *data, struct url_check_http_info *http_info);
    void* (*cfg)(const char **argv);
    void (*free)(void *data);
};
#define SRV_UC_ACTIONS_REGISTRY "srv_url_check::req_actions"
#define srv_uc_register_req_action(action) ci_registry_add_item(SRV_UC_ACTIONS_REGISTRY, (action)->name, action)

struct url_check_req_filter;
struct cfg_request_filter {
     const struct url_check_req_filter *filter;
     void *data;
};

struct url_check_req_filter {
     const char *name;
     int (*filter_cb)(const struct cfg_request_filter *flt, ci_request_t *req);
     void * (*cfg)(const char **argv);
     void (*free)(void *);
};
typedef struct url_check_req_filter url_check_req_filter_t;

void url_check_free_request_filters(ci_list_t *request_filters);
/*Return SRV_UC_ACT_HEADMOD|SRV_UC_ACT_HEADMOD|SRV_UC_ACT_NONE*/
unsigned int url_check_request_filters_apply(ci_request_t *req, ci_list_t *request_filters);
int url_check_request_filters_cfg_parse(ci_list_t **request_filters, const char **argv);
int url_check_request_filters_init();

#define SRV_UC_FILTERS_REGISTRY "srv_url_check::req_filters"
#define srv_uc_register_req_filter(filter) ci_registry_add_item(SRV_UC_FILTERS_REGISTRY, (filter)->name, filter)

#endif

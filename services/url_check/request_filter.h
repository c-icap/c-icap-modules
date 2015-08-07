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
int url_check_request_filters_apply(ci_request_t *req, ci_list_t *request_filters);
int url_check_request_filters_cfg_parse(ci_list_t **request_filters, const char **argv);
int url_check_request_filters_init();

#define SRV_UC_FILTERS_REGISTRY "srv_url_check::req_filters"
#define srv_uc_register_req_filter(filter) ci_registry_add_item(SRV_UC_FILTERS_REGISTRY, (filter)->name, filter)

#endif

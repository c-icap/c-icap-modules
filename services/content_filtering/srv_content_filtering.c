/*
 *  Copyright (C) 2012 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA.
 */

#ifdef HAVE_CONFIG_H
#include "common.h"
#else
#include "common-static.h"
#endif
#include "c_icap/c-icap.h"
#include "c_icap/cfg_param.h"
#include "c_icap/service.h"
#include "c_icap/header.h"
#include "c_icap/body.h"
#include "c_icap/simple_api.h"
#include "c_icap/txtTemplate.h"
#include "c_icap/lookup_table.h"
#include "c_icap/net_io.h"
#include "c_icap/debug.h"
#include "srv_body.h"
#include "filters.h"
#include <assert.h>
#include <ctype.h>

static int srv_content_filtering_init_service(ci_service_xdata_t * srv_xdata,
                                              struct ci_server_conf *server_conf);
static int srv_content_filtering_post_init_service(ci_service_xdata_t * srv_xdata,
                                                   struct ci_server_conf *server_conf);
static int srv_content_filtering_check_preview_handler(char *preview_data, int preview_data_len,
                                                       ci_request_t *);
static int srv_content_filtering_end_of_data_handler(ci_request_t * req);
static void *srv_content_filtering_init_request_data(ci_request_t * req);
static void srv_content_filtering_close_service();
static void srv_content_filtering_release_request_data(void *data);
static int srv_content_filtering_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                                    ci_request_t * req);

/*
  The srv_content_filtering_req_data structure will store the data required to serve an ICAP request.
*/
struct srv_content_filtering_req_data {
    const srv_cf_profile_t *profile;
    /*the body data*/
    srv_cf_body_t body;
    int enMethod;
    int64_t maxBodyData;
    int64_t expectedData;
    /*flag for marking the eof*/
    int eof;
    int isText;
    int abort;
    int isReqmod;
    srv_cf_results_t result;
};

static void generate_error_page(struct srv_content_filtering_req_data * data, ci_request_t * req, const char *tmpl);
static void add_xheaders(struct srv_content_filtering_req_data * data, ci_request_t * req);
static int encoding_method(const char *content_encoding);

/*srv_content_filtering module text formating codes table*/
static int fmt_srv_cf_action(ci_request_t *req, char *buf, int len, const char *param);
static int fmt_srv_cf_action_score(ci_request_t *req, char *buf, int len, const char *param);
static int fmt_srv_cf_action_reason(ci_request_t *req, char *buf, int len, const char *param);
static int fmt_srv_cf_scores_list(ci_request_t *req, char *buf, int len, const char *param);
static int fmt_srv_cf_filter(ci_request_t *req, char *buf, int len, const char *param);
static int fmt_srv_cf_filter_matches(ci_request_t *req, char *buf, int len, const char *param);

static struct ci_fmt_entry srv_content_filtering_format_table[] = {
    {"%CFA", "The Action", fmt_srv_cf_action},
    {"%CFC", "The ActionScore", fmt_srv_cf_action_score},
    {"%CFR", "The action reason: [>|<|=]ConfiguredScore", fmt_srv_cf_action_reason},
    {"%CFS", "The list of scores", fmt_srv_cf_scores_list},
    {"%CFF", "The filter caused the action", fmt_srv_cf_filter},
    {"%CFM", "The matches of filter caused the action", fmt_srv_cf_filter_matches},
    { NULL, NULL, NULL}
};

static ci_off_t MaxBodyData = 4*1024*1024; //131072; /*128k*/
static int RequireContentLength = 1;

static struct ci_conf_entry srv_content_filtering_conf_variables[] = {
    {"MaxBodyData", &MaxBodyData, ci_cfg_size_off, NULL},
    {"RequireContentLength", &RequireContentLength, ci_cfg_onoff, NULL},
    {"Match", NULL, srv_cf_cfg_match, NULL},
    {"MatchingFilter", NULL, srv_cf_cfg_match, NULL},
    {"Action", NULL, srv_cf_cfg_action, NULL},
    {"Profile", NULL, srv_cf_cfg_profile, NULL},
    {"ProfileOption", NULL, srv_cf_cfg_profile_option, NULL},
    {"ProfileAccess", NULL, srv_cf_cfg_profile_access, NULL},
    {NULL, NULL, NULL, NULL}
};

CI_DECLARE_MOD_DATA ci_service_module_t service = {
    "srv_content_filtering",                         /* mod_name, The module name */
    "srv_content_filtering service",            /* mod_short_descr,  Module short description */
    ICAP_RESPMOD|ICAP_REQMOD,     /* mod_type, The service type is responce or request modification */
    srv_content_filtering_init_service,              /* mod_init_service. Service initialization */
    srv_content_filtering_post_init_service,         /* post_init_service. Service initialization after c-icap
					configured. Not used here */
    srv_content_filtering_close_service,           /* mod_close_service. Called when service shutdowns. */
    srv_content_filtering_init_request_data,         /* mod_init_request_data */
    srv_content_filtering_release_request_data,      /* mod_release_request_data */
    srv_content_filtering_check_preview_handler,     /* mod_check_preview_handler */
    srv_content_filtering_end_of_data_handler,       /* mod_end_of_data_handler */
    srv_content_filtering_io,                        /* mod_service_io */
    srv_content_filtering_conf_variables,            /*configration variables table*/
    NULL
};


/* This function will be called when the service loaded  */
int srv_content_filtering_init_service(ci_service_xdata_t * srv_xdata,
                      struct ci_server_conf *server_conf)
{
     ci_debug_printf(5, "Initialization of srv_content_filtering module......\n");

     /*Tell to the icap clients that we can support up to 1024 size of preview data*/
     ci_service_set_preview(srv_xdata, 1024);

     /*Tell to the icap clients to send preview data for all files*/
     ci_service_set_transfer_preview(srv_xdata, "*");

     return CI_OK;
}

int srv_content_filtering_post_init_service(ci_service_xdata_t * srv_xdata,
                                struct ci_server_conf *server_conf)
{
    ci_debug_printf(5, "Post initialization of srv_content_filtering module......\n");
    srv_cf_filters_debug_print(1);
    return CI_OK;
}

/* This function will be called when the service shutdown */
void srv_content_filtering_close_service()
{
    srv_cf_filters_reset();
    srv_srv_cf_profiles_reset();
    ci_debug_printf(5,"Service shutdown!\n");
}

/*This function will be executed when a new request for srv_content_filtering service
  arrives. This function will initialize the required structures and data
  to serve the request.
 */
void *srv_content_filtering_init_request_data(ci_request_t * req)
{
    struct srv_content_filtering_req_data *srv_content_filtering_data;

    /*Allocate memory for the srv_content_filtering_data*/
    srv_content_filtering_data = malloc(sizeof(struct srv_content_filtering_req_data));
    if (!srv_content_filtering_data) {
        ci_debug_printf(1, "Memory allocation failed inside srv_content_filtering_init_request_data!\n");
        return NULL;
    }

    /*If the ICAP request encuspulates a HTTP objects which contains body data
      and not only headers allocate a ci_cached_file_t object to store the body data.
    */
    srv_cf_body_init(&srv_content_filtering_data->body);
    srv_content_filtering_data->eof = 0;
    srv_content_filtering_data->enMethod = CI_ENCODE_NONE;
    srv_content_filtering_data->isText = 0;
    srv_content_filtering_data->abort = 0;
    srv_content_filtering_data->isReqmod = 0;
    srv_content_filtering_data->maxBodyData = 0;
    srv_content_filtering_data->expectedData = 0;
    srv_content_filtering_data->result.action = NULL;
    srv_content_filtering_data->result.action_score = 0;
    srv_content_filtering_data->result.scores = NULL;
    srv_content_filtering_data->result.replaceBody = NULL;
    srv_content_filtering_data->result.addHeaders = NULL;

    /*Return to the c-icap server the allocated data*/
    return srv_content_filtering_data;
}

/*This function will be executed after the request served to release allocated data*/
void srv_content_filtering_release_request_data(void *data)
{
    /*The data points to the srv_content_filtering_req_data struct we allocated in function srv_content_filtering_init_service */
    struct srv_content_filtering_req_data *srv_content_filtering_data = (struct srv_content_filtering_req_data *)data;

    /*if we had body data, release the related allocated data*/
    srv_cf_body_free(&srv_content_filtering_data->body);

    if (srv_content_filtering_data->result.replaceBody)
        ci_membuf_free(srv_content_filtering_data->result.replaceBody);

    if (srv_content_filtering_data->result.scores)
        ci_list_destroy(srv_content_filtering_data->result.scores);
    free(srv_content_filtering_data);
}


int srv_content_filtering_check_preview_handler(char *preview_data, int preview_data_len,
                               ci_request_t * req)
{
     ci_off_t content_len;

     /*Get the srv_content_filtering_req_data we allocated using the  srv_content_filtering_init_service  function*/
     struct srv_content_filtering_req_data *srv_content_filtering_data = ci_service_data(req);

     /*If there are not body data in HTTP encapsulated object but only headers
       respond with Allow204 (no modification required) and terminate here the
       ICAP transaction */
     if(!ci_req_hasbody(req)) {
         ci_debug_printf(4, "Srv_Content_Filtering no body data will not process\n");
	 return CI_MOD_ALLOW204;
     }

     if (!(srv_content_filtering_data->profile = srv_srv_cf_profile_select(req))) {
         ci_debug_printf(4, "srv_content_filtering: no profile selected, will not process\n");
         return CI_MOD_ALLOW204;
     }
     ci_debug_printf(4, "srv_content_filtering: Will use profile '%s'\n", srv_content_filtering_data->profile->name);

     srv_content_filtering_data->maxBodyData = srv_content_filtering_data->profile->maxBodyData? srv_content_filtering_data->profile->maxBodyData : MaxBodyData;

     /*If the content type is not html do not process */
     const char *content_type = ci_http_response_get_header(req, "Content-Type");
     if (!content_type && req->type == ICAP_REQMOD)
         content_type = ci_http_request_get_header(req, "Content-Type");

     if (content_type && (strstr(content_type, "text/") != NULL || strstr(content_type, "application/javascript") != NULL))
         srv_content_filtering_data->isText = 1;
     else if (!srv_content_filtering_data->profile->anyContentType){
         ci_debug_printf(4, "Srv_Content_Filtering content type %s will not process\n", content_type);
         return CI_MOD_ALLOW204;
     }

     /*If there are is a Content-Length header, check it we do not want to
      process body data with more than MaxBodyData size*/
     content_len = ci_http_content_length(req);
     ci_debug_printf(4, "Srv_Content_Filtering expected length: %"PRINTF_OFF_T"\n", (CAST_OFF_T) content_len);
     srv_content_filtering_data->expectedData = content_len;

     if (content_len > srv_content_filtering_data->maxBodyData) {
         ci_debug_printf(4, "Srv_Content_Filtering  content-length=%"PRINTF_OFF_T" > %ld will not process\n", (CAST_OFF_T)content_len, srv_content_filtering_data->maxBodyData);
         return CI_MOD_ALLOW204;
     }

     /*If we do not have content len, for simplicity do not proccess it*/
     if (RequireContentLength && content_len <= 0) {
         ci_debug_printf(4, "Srv_Content_Filtering not Content-Length will not process\n");
         return CI_MOD_ALLOW204;
     }

     if (srv_content_filtering_data->isText) {

     }

     ci_debug_printf(8, "Srv_Content_Filtering service will process the request\n");

     const char *contentEncoding = NULL;
     if (req->type == ICAP_RESPMOD)
         contentEncoding = ci_http_response_get_header(req, "Content-Encoding");
     else
         contentEncoding = ci_http_request_get_header(req, "Content-Encoding");

     if (!contentEncoding)
         srv_content_filtering_data->enMethod = CI_ENCODE_NONE;
     else 
         srv_content_filtering_data->enMethod = encoding_method(contentEncoding);

     srv_cf_body_build(&srv_content_filtering_data->body, content_len > 0 ? content_len + 1 : srv_content_filtering_data->maxBodyData);

     /*if we have preview data and we want to proceed with the request processing
       we should store the preview data. There are cases where all the body
       data of the encapsulated HTTP object included in preview data. Someone can use
       the ci_req_hasalldata macro to  identify these cases
     */
     if (preview_data_len) {
         srv_cf_body_write(&srv_content_filtering_data->body, preview_data, preview_data_len, ci_req_hasalldata(req));
         srv_content_filtering_data->eof = ci_req_hasalldata(req);
     }

     srv_content_filtering_data->isReqmod = (req->type == ICAP_REQMOD ? 1 : 0);
     return CI_MOD_CONTINUE;
}

/* This function will called if we returned CI_MOD_CONTINUE in
   srv_content_filtering_check_preview_handler function, after we read all the data from
   the ICAP client
*/
int srv_content_filtering_end_of_data_handler(ci_request_t * req)
{
    char tmpBuf[1024];
    ci_headers_list_t *heads = NULL;
    struct srv_content_filtering_req_data *srv_content_filtering_data = ci_service_data(req);
    srv_cf_results_t *result = &(srv_content_filtering_data->result);

    if (srv_content_filtering_data->abort) {
        /*We had already start sending data....*/
        srv_content_filtering_data->eof = 1;
        return CI_MOD_DONE;
    }

    ci_debug_printf(2, "All data received, going to process!\n");

    /*Assure that we do not sent any data to the client yet*/
    assert(srv_cf_body_readpos(&srv_content_filtering_data->body) == 0);

    ci_membuf_t *decoded_data = srv_cf_body_decoded_membuf(&srv_content_filtering_data->body, srv_content_filtering_data->enMethod,  srv_content_filtering_data->maxBodyData);
    if (decoded_data) {
        /*
          Process data.....
          Assume the new data stored in body_data and they are of size body_data_len
        */
        srv_cf_apply_actions(req, srv_content_filtering_data->profile, decoded_data, result, srv_content_filtering_format_table);
    }

    add_xheaders(srv_content_filtering_data, req);

    if (result->replaceBody && !ci_req_sent_data(req)) {
        srv_cf_body_replace_body(&srv_content_filtering_data->body, result->replaceBody);
        snprintf(tmpBuf, sizeof(tmpBuf), "Content-Length: %lld", (long long int)ci_membuf_size(result->replaceBody));
        if (srv_content_filtering_data->isReqmod) {
            ci_http_request_remove_header(req, "Content-Encoding");
            ci_http_request_remove_header(req, "Content-Length");
            ci_http_request_add_header(req, tmpBuf);
        } else {
            ci_http_response_remove_header(req, "Content-Encoding");
            ci_http_response_remove_header(req, "Content-Length");
            ci_http_response_add_header(req, tmpBuf);
        }
        result->replaceBody = NULL; /*Now srv_content_filtering_data->body points to this.
                                     set it to NULL to avoid release twice later...*/
    }

    if (result->action) {
        switch (result->action->action) {
        case CF_AC_BLOCK:
            if (!ci_req_sent_data(req)) {
                generate_error_page(srv_content_filtering_data, req, result->action->template);
            }
            break;
        case CF_AC_ALLOW:
            break;
        default:
            ci_debug_printf(1, "Unknown action id: '%d'\n", result->action->action);
            break;
        }
        if (result->addHeaders) {
            heads = ci_http_response_headers(req);
            ci_headers_addheaders(heads, result->addHeaders);
        }
        ci_request_set_str_attribute(req,"srv_content_filtering:action", srv_cf_action_str(result->action->action));
    }

    /*mark the eof*/
    srv_content_filtering_data->eof = 1;
    /*Unlock the request body data so the c-icap server can send data*/
     ci_req_unlock_data(req);
     /*and return CI_MOD_DONE */
     return CI_MOD_DONE;
}

/* This function will called if we returned CI_MOD_CONTINUE in  srv_content_filtering_check_preview_handler
   function, when new data arrived from the ICAP client and when the ICAP client is
   ready to get data.
*/
int srv_content_filtering_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
            ci_request_t * req)
{
     int ret;
     struct srv_content_filtering_req_data *srv_content_filtering_data = ci_service_data(req);
     ret = CI_OK;

     /*write the data read from icap_client to the srv_content_filtering_data->body*/
     if(rlen && rbuf) {
         if (srv_content_filtering_data->body.ring == NULL &&
             (srv_content_filtering_data->body.size + *rlen) > srv_content_filtering_data->maxBodyData) {
             ci_debug_printf(4, "Srv_Content_Filtering content-length:%" PRIu64 " bigger than maxBodyData:%" PRId64 "\n",
                             (srv_content_filtering_data->body.size + *rlen),
                             srv_content_filtering_data->maxBodyData);
             if (!srv_cf_body_to_ring(&srv_content_filtering_data->body))
                 return CI_ERROR;
             ci_debug_printf(5, "Srv_Content_Filtering Stop buffering data, reverted to ring mode, and sent early response\n");
             /*We will not process body data. More data size than expected.*/
             srv_content_filtering_data->abort = 1;
             ci_req_unlock_data(req);
         }

         *rlen = srv_cf_body_write(&srv_content_filtering_data->body, rbuf, *rlen, iseof);
         if (*rlen < 0)
	    ret = CI_ERROR;
     }

     /*Do not send any data if we do not receive all of the data*/
     if (!srv_content_filtering_data->eof && !srv_content_filtering_data->abort)
         return ret;

     /*read some data from the srv_content_filtering_data->body and put them to the write buffer to be send
      to the ICAP client*/
     if (wbuf && wlen) {
          *wlen = srv_cf_body_read(&srv_content_filtering_data->body, wbuf, *wlen);
     }
     if(wlen && *wlen == 0 && srv_content_filtering_data->eof == 1)
	 *wlen = CI_EOF;

     return ret;
}

void generate_error_page(struct srv_content_filtering_req_data * data, ci_request_t * req, const char *tmpl)
{
     ci_membuf_t *error_page;
     char buf[1024];
     const char *lang;

     if ( ci_http_response_headers(req))
          ci_http_response_reset_headers(req);
     else
          ci_http_response_create(req, 1, 1);
     ci_http_response_add_header(req, "HTTP/1.0 403 Forbidden");
     ci_http_response_add_header(req, "Server: C-ICAP");
     ci_http_response_add_header(req, "Connection: close");
     ci_http_response_add_header(req, "Content-Type: text/html");

     error_page = ci_txt_template_build_content(req, "srv_content_filtering", tmpl ? tmpl : "BLOCK",
                                                srv_content_filtering_format_table);

     lang = ci_membuf_attr_get(error_page, "lang");
     if (lang) {
         snprintf(buf, sizeof(buf), "Content-Language: %s", lang);
         buf[sizeof(buf)-1] = '\0';
         ci_http_response_add_header(req, buf);
     }
     else
         ci_http_response_add_header(req, "Content-Language: en");

     srv_cf_body_replace_body(&data->body, error_page);
}

void add_xheaders(struct srv_content_filtering_req_data * data, ci_request_t * req)
{
    char buf[1024];
    char buf2[1024];
    if (data->profile) {
        snprintf(buf, sizeof(buf), "X-ICAP-Profile: %s", data->profile->name);
        buf[sizeof(buf)-1] = '\0';
        ci_icap_add_xheader(req, buf);
    }

    if (data->result.scores) {
        srv_cf_print_scores_list(data->result.scores, buf2, sizeof(buf2));
        ci_request_set_str_attribute(req,"srv_content_filtering:scores", buf2);

        snprintf(buf, sizeof(buf), "X-Attribute: %s", buf2);
        buf[sizeof(buf)-1] = '\0';
        ci_icap_add_xheader(req, buf);
    }

    if (data->result.action) {
        ci_request_set_str_attribute(req,"srv_content_filtering:action", srv_cf_action_str(data->result.action->action));
        snprintf(buf, sizeof(buf), "X-Response-Info: %s", srv_cf_action_str(data->result.action->action));
        buf[sizeof(buf)-1] = '\0';
        ci_icap_add_xheader(req, buf);

        ci_request_set_str_attribute(req, "srv_content_filtering:action_filter", data->result.action->matchingFilter->name);
        snprintf(buf, sizeof(buf), "%d", data->result.action_matchesCount);
        ci_request_set_str_attribute(req, "srv_content_filtering:action_filter_matches", buf);
        snprintf(buf, sizeof(buf), "%d", data->result.action_score);
        ci_request_set_str_attribute(req, "srv_content_filtering:action_filter_score", buf);

        snprintf(buf, sizeof(buf), "X-Response-Desc: %s score=%d%c%d",
                 data->result.action->matchingFilter->name,
                 data->result.action_score,
                 (data->result.action->scoreOperator == CF_OP_LESS ?  '<' :
                  (data->result.action->scoreOperator == CF_OP_GREATER ?  '>' : '=')),
                 data->result.action->score
            );
        ci_icap_add_xheader(req, buf);
    }
}


int encoding_method(const char *content_encoding)
{
#if defined(HAVE_CICAP_ENCODING_METHOD)
    return ci_encoding_method(content_encoding);
#else
    if (!content_encoding)
        return CI_ENCODE_NONE;

    if (strcasestr(content_encoding, "gzip") != NULL) {
        return CI_ENCODE_GZIP;
    }

    if (strcasestr(content_encoding, "deflate") != NULL) {
        return CI_ENCODE_DEFLATE;
    }
#if defined(HAVE_CICAP_BROTLI)
    if (strcasestr(content_encoding, "br") != NULL) {
        return CI_ENCODE_BROTLI;
    }
#endif

    if (strcasestr(content_encoding, "bzip2") != NULL) {
        return CI_ENCODE_BZIP2;
    }

    return CI_ENCODE_UNKNOWN;
#endif
}

int fmt_srv_cf_action(ci_request_t *req, char *buf, int len, const char *param)
{
    struct srv_content_filtering_req_data *srv_cf_data = ci_service_data(req);
    /*Do notwrite more than 512 bytes*/
    if (srv_cf_data && srv_cf_data->result.action)
        return snprintf(buf, len, "%s", srv_cf_action_str(srv_cf_data->result.action->action));
    else
        return snprintf(buf, len, "-");
}

int fmt_srv_cf_action_score(ci_request_t *req, char *buf, int len, const char *param)
{
    struct srv_content_filtering_req_data *srv_cf_data = ci_service_data(req);
    /*Do notwrite more than 512 bytes*/
    if (srv_cf_data  && srv_cf_data->result.action)
        return snprintf(buf, len, "%d", srv_cf_data->result.action_score);
    else
        return snprintf(buf, len, "-");
}

int fmt_srv_cf_action_reason(ci_request_t *req, char *buf, int len, const char *param)
{
    struct srv_content_filtering_req_data *srv_cf_data = ci_service_data(req);
    /*Do notwrite more than 512 bytes*/
    if (srv_cf_data  && srv_cf_data->result.action)
        return snprintf(buf, len, "%c%d",
                        (srv_cf_data->result.action->scoreOperator == CF_OP_LESS ?  '<' :
                         (srv_cf_data->result.action->scoreOperator == CF_OP_GREATER ?  '>' : '=')),
                        srv_cf_data->result.action->score);
    else
        return snprintf(buf, len, "-");
}

int fmt_srv_cf_scores_list(ci_request_t *req, char *buf, int len, const char *param)
{
    struct srv_content_filtering_req_data *srv_cf_data = ci_service_data(req);
    /*Do notwrite more than 512 bytes*/
    if (srv_cf_data  && srv_cf_data->result.scores)
        return srv_cf_print_scores_list(srv_cf_data->result.scores, buf, len);
    else
        return snprintf(buf, len, "-");
}

int fmt_srv_cf_filter(ci_request_t *req, char *buf, int len, const char *param)
{
    struct srv_content_filtering_req_data *srv_cf_data = ci_service_data(req);
    /*Do notwrite more than 512 bytes*/
    if (srv_cf_data  && srv_cf_data->result.action)
        return snprintf(buf, len, "%s", srv_cf_data->result.action->matchingFilter->name);
    else
        return snprintf(buf, len, "-");
}

int fmt_srv_cf_filter_matches(ci_request_t *req, char *buf, int len, const char *param)
{
    struct srv_content_filtering_req_data *srv_cf_data = ci_service_data(req);
    /*Do notwrite more than 512 bytes*/
    if (srv_cf_data  && srv_cf_data->result.action)
        return snprintf(buf, len, "%d", srv_cf_data->result.action_matchesCount);
    else
        return snprintf(buf, len, "-");
}

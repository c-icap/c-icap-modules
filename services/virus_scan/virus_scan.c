/*
 *  Copyright (C) 2004-2012 Christos Tsantilas
 *
 *  Other contributors/sponsors:
 *      - Multiple av engines support funded by Endian (http://www.endian.com)
 *	  and Panda Security (http://www.pandasecurity.com/)
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
#include "c_icap/service.h"
#include "c_icap/header.h"
#include "c_icap/simple_api.h"
#include "c_icap/debug.h"
#include "c_icap/cfg_param.h"
#include "virus_scan.h"
#include "c_icap/filetype.h"
#include "c_icap/ci_threads.h"
#include "c_icap/mem.h"
#include "c_icap/commands.h"
#include "c_icap/txt_format.h"
#include "c_icap/txtTemplate.h"
#include "c_icap/stats.h"
#include "../../common.h"
#include "md5.h"
#include <errno.h>
#include <assert.h>

int must_scanned(ci_request_t *req, char *preview_data, int preview_data_len);

static ci_str_vector_t *DEFAULT_ENGINE_NAMES = NULL;
static const av_engine_t *DEFAULT_ENGINES[AV_MAX_ENGINES];

static void build_reply_headers(ci_request_t *req, av_virus_info_t *vinfo);
void generate_error_page(av_req_data_t *data, ci_request_t *req);
char *virus_scan_compute_name(ci_request_t *req);
static void rebuild_content_length(ci_request_t *req, struct av_body_data *body);
/***********************************************************************************/
/* Module definitions                                                              */

static int SEND_PERCENT_DATA = 0;      /* By default will not send any bytes without check them before */
static int ALLOW204 = 1;
static ci_off_t MAX_OBJECT_SIZE = 5*1024*1024;
static ci_off_t START_SEND_AFTER = 0;
static int PASSONERROR = 0;

static struct ci_magics_db *magic_db = NULL;
static struct av_file_types SCAN_FILE_TYPES = {NULL, NULL};

/*char *VIR_SAVE_DIR="/srv/www/htdocs/downloads/";
  char *VIR_HTTP_SERVER="http://fortune/cgi-bin/get_file.pl?usename=%f&file="; */

char *VIR_SAVE_DIR = NULL;
char *VIR_HTTP_SERVER = NULL;
int VIR_UPDATE_TIME = 15;

/*Statistic  Ids*/
static int AV_SCAN_REQS = -1;
static int AV_VIRMODE_REQS = -1;
static int AV_SCAN_BYTES = -1;
static int AV_VIRUSES_FOUND = -1;
static int AV_SCAN_FAILURES = -1;

/*********************/
/* Formating table   */
static int fmt_virus_scan_virusname(ci_request_t *req, char *buf, int len, const char *param);
static int fmt_virus_scan_av_version(ci_request_t *req, char *buf, int len, const char *param);
static int fmt_virus_scan_http_url(ci_request_t *req, char *buf, int len, const char *param);
#ifdef VIRALATOR_MODE
int fmt_virus_scan_expect_size(ci_request_t *req, char *buf, int len, const char *param);
int fmt_virus_scan_filename(ci_request_t *req, char *buf, int len, const char *param);
int fmt_virus_scan_filename_requested(ci_request_t *req, char *buf, int len, const char *param);
int fmt_virus_scan_httpurl(ci_request_t *req, char *buf, int len, const char *param);
#endif
#ifdef USE_VSCAN_PROFILES
int fmt_virus_scan_profile(ci_request_t *req, char *buf, int len, const char *param);
#endif

struct ci_fmt_entry virus_scan_format_table [] = {
    {"%VVN", "Virus name", fmt_virus_scan_virusname},
    {"%VVV", "Antivirus Engine", fmt_virus_scan_av_version},
    {"%VU", "The HTTP url", fmt_virus_scan_http_url},
#ifdef VIRALATOR_MODE
    {"%VFR", "downloaded file requested name", fmt_virus_scan_filename_requested},
    {"%VFS", "Expected http body data size (Content-Length header)", fmt_virus_scan_expect_size},
    {"%VF", "local filename", fmt_virus_scan_filename},
    {"%VHS", "HTTP URL", fmt_virus_scan_httpurl},
#endif
#ifdef USE_VSCAN_PROFILES
    {"%VPR", "Profile name", fmt_virus_scan_profile},
#endif
    { NULL, NULL, NULL}
};


/*virus_scan service extra data ... */
static ci_service_xdata_t *virus_scan_xdata = NULL;

static int AVREQDATA_POOL = -1;

static int virus_scan_init_service(ci_service_xdata_t *srv_xdata,
                           struct ci_server_conf *server_conf);
static int virus_scan_post_init_service(ci_service_xdata_t *srv_xdata,
                           struct ci_server_conf *server_conf);
static void virus_scan_close_service();
static int virus_scan_check_preview_handler(char *preview_data, int preview_data_len,
                                    ci_request_t *);
static int virus_scan_end_of_data_handler(ci_request_t *);
static void *virus_scan_init_request_data(ci_request_t *req);
static void virus_scan_release_request_data(void *data);
static int virus_scan_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                 ci_request_t *req);

/*Arguments parse*/
static void virus_scan_parse_args(av_req_data_t *data, char *args);
/*Configuration Functions*/
int cfg_ScanFileTypes(const char *directive, const char **argv, void *setdata);
int cfg_SendPercentData(const char *directive, const char **argv, void *setdata);
int cfg_av_set_str_vector(const char *directive, const char **argv, void *setdata);
#ifdef USE_VSCAN_PROFILES
int cfg_av_req_profile(const char *directive, const char **argv, void *setdata);
int cfg_av_req_profile_access(const char *directive, const char **argv, void *setdata);
#endif
/*General functions*/
static int get_filetype(ci_request_t *req, int *encoding);
static void set_istag(ci_service_xdata_t *srv_xdata);
static void cmd_reload_istag(const char *name, int type, void *data);
static int init_body_data(ci_request_t *req);

/*It is dangerous to pass directly fields of the limits structure in conf_variables,
  becouse in the feature some of this fields will change type (from int to unsigned int
  or from long to long long etc)
  I must use global variables and use the post_init_service function to fill the
  limits structure.
  But, OK let it go for the time ....
*/

/*Configuration Table .....*/
static struct ci_conf_entry conf_variables[] = {
     {"SendPercentData",  &SEND_PERCENT_DATA, cfg_SendPercentData, NULL},
     {"ScanFileTypes", &SCAN_FILE_TYPES, cfg_ScanFileTypes, NULL},
     {"MaxObjectSize", &MAX_OBJECT_SIZE, ci_cfg_size_off, NULL},
     {"StartSendingDataAfter", &START_SEND_AFTER, ci_cfg_size_off, NULL},
     {"StartSendPercentDataAfter", &START_SEND_AFTER, ci_cfg_size_off, NULL},
     {"Allow204Responces", &ALLOW204, ci_cfg_onoff, NULL},
     {"PassOnError", &PASSONERROR, ci_cfg_onoff, NULL},
     {"DefaultEngine", &DEFAULT_ENGINE_NAMES, cfg_av_set_str_vector, NULL},
#ifdef USE_VSCAN_PROFILES
     {"Profile", NULL, cfg_av_req_profile, NULL},
     {"ProfileAccess", NULL, cfg_av_req_profile_access, NULL},
#endif
#ifdef VIRALATOR_MODE
     {"VirSaveDir", &VIR_SAVE_DIR, ci_cfg_set_str, NULL},
     {"VirHTTPServer", &VIR_HTTP_SERVER, ci_cfg_set_str, NULL}, /*Deprecated*/
     {"VirHTTPUrl", &VIR_HTTP_SERVER, ci_cfg_set_str, NULL},
     {"VirUpdateTime", &VIR_UPDATE_TIME, ci_cfg_set_int, NULL},
     {"VirScanFileTypes", &SCAN_FILE_TYPES, cfg_ScanFileTypes, NULL},
#endif
};


CI_DECLARE_MOD_DATA ci_service_module_t service = {
     "virus_scan",              /*Module name */
     "Antivirus service",        /*Module short description */
     ICAP_RESPMOD | ICAP_REQMOD,        /*Service type responce or request modification */
     virus_scan_init_service,    /*init_service. */
     virus_scan_post_init_service,   /*post_init_service. */
     virus_scan_close_service,   /*close_service */
     virus_scan_init_request_data,       /*init_request_data. */
     virus_scan_release_request_data,    /*release request data */
     virus_scan_check_preview_handler,
     virus_scan_end_of_data_handler,
     virus_scan_io,
     conf_variables,
     NULL
};



int virus_scan_init_service(ci_service_xdata_t *srv_xdata,
                           struct ci_server_conf *server_conf)
{
     magic_db = server_conf->MAGIC_DB;
     av_file_types_init(&SCAN_FILE_TYPES);
#ifdef USE_VSCAN_PROFILES
     av_req_profile_init_profiles();
#endif

     ci_debug_printf(10, "Going to initialize virus_scan\n");
     virus_scan_xdata = srv_xdata;      /*Needed by db_reload command */
     ci_service_set_preview(srv_xdata, 1024);
     ci_service_enable_204(srv_xdata);
     ci_service_set_transfer_preview(srv_xdata, "*");

     /*Initialize object pools*/
     AVREQDATA_POOL = ci_object_pool_register("av_req_data_t", sizeof(av_req_data_t));

     if(AVREQDATA_POOL < 0) {
	 ci_debug_printf(1, " virus_scan_init_service: error registering object_pool av_req_data_t\n");
	 return CI_ERROR;
     }

     /*initialize statistic counters*/
     /* TODO:convert to const after fix ci_stat_* api*/
     char *stats_label = "Service virus_scan";
     AV_SCAN_REQS = ci_stat_entry_register("Requests scanned", STAT_INT64_T, stats_label);
     AV_VIRMODE_REQS = ci_stat_entry_register("Virmode requests", STAT_INT64_T, stats_label);
     AV_SCAN_BYTES = ci_stat_entry_register("Body bytes scanned", STAT_KBS_T, stats_label);
     AV_VIRUSES_FOUND = ci_stat_entry_register("Viruses found", STAT_INT64_T, stats_label);
     AV_SCAN_FAILURES = ci_stat_entry_register("Scan failures", STAT_INT64_T, stats_label);

     memset(DEFAULT_ENGINES, 0, AV_MAX_ENGINES * sizeof(av_engine_t *));
     return CI_OK;
}

int virus_scan_post_init_service(ci_service_xdata_t *srv_xdata,
                           struct ci_server_conf *server_conf)
{
    set_istag(virus_scan_xdata);
    register_command_extend(AV_RELOAD_ISTAG, ONDEMAND_CMD, NULL, cmd_reload_istag);
    return CI_OK;
}

void virus_scan_close_service()
{
     av_file_types_destroy(&SCAN_FILE_TYPES);
     ci_object_pool_unregister(AVREQDATA_POOL);

#ifdef USE_VSCAN_PROFILES
     av_req_profile_release_profiles();
#endif
     if (DEFAULT_ENGINE_NAMES) {
         ci_str_vector_destroy(DEFAULT_ENGINE_NAMES);
         DEFAULT_ENGINE_NAMES = NULL;
     }
     memset(DEFAULT_ENGINES, 0, AV_MAX_ENGINES * sizeof(av_engine_t *));
}

static int get_first_engine(void *data, const char *label, const void *obj)
{
    const void **eng = (const void **)data;
    *eng = obj;
    ci_debug_printf(1, "Setting antivirus default engine: %s\n", label);
    return 1;
}

void select_default_engine()
{
    int i, k;
    const char *eng_name;
    if (DEFAULT_ENGINE_NAMES) {
        for(k = 0, i = 0; i < AV_MAX_ENGINES - 1 && (eng_name = ci_str_vector_get(DEFAULT_ENGINE_NAMES, i)); i++) {
            DEFAULT_ENGINES[k] = ci_registry_get_item(AV_ENGINES_REGISTRY, eng_name);
            if (DEFAULT_ENGINES[k]) k++;
            else {
                ci_debug_printf(1, "WARNING! Wrong antivirus engine name: %s\n", eng_name);
            }
        }
        DEFAULT_ENGINES[k] = NULL;
    }

    if (!DEFAULT_ENGINES[0]) {
        ci_registry_iterate(AV_ENGINES_REGISTRY, &(DEFAULT_ENGINES[0]), get_first_engine);
        DEFAULT_ENGINES[1] = NULL;
    }
}

void *virus_scan_init_request_data(ci_request_t *req)
{
    int preview_size;
     av_req_data_t *data;

     if (! DEFAULT_ENGINES[0])
         select_default_engine();

     preview_size = ci_req_preview_size(req);

     if (req->args[0] != '\0') {
          ci_debug_printf(5, "service arguments:%s\n", req->args);
     }
     if (ci_req_hasbody(req)) {
          ci_debug_printf(5, "Request type: %d. Preview size:%d\n", req->type,
                          preview_size);
          if (!(data = ci_object_pool_alloc(AVREQDATA_POOL))) {
               ci_debug_printf(1,
                               "Error allocation memory for service data!!!!!!!\n");
               return NULL;
          }
          memset(&data->body,0, sizeof(struct av_body_data));
          data->error_page = NULL;
          data->url_log[0] = '\0';
          data->virus_info.virus_name[0] = '\0';
          data->virus_info.virus_found = 0;
          data->virus_info.disinfected = 0;
          data->virus_info.viruses = NULL;
          data->must_scanned = SCAN;
          data->virus_check_done = 0;
          if (ALLOW204)
               data->args.enable204 = 1;
          else
               data->args.enable204 = 0;
          data->args.forcescan = 0;
          data->args.sizelimit = 1;
          data->args.mode = 0;

          memcpy(data->engine, DEFAULT_ENGINES, AV_MAX_ENGINES * sizeof(av_engine_t *));

          if (req->args[0] != '\0') {
               ci_debug_printf(5, "service arguments:%s\n", req->args);
               virus_scan_parse_args(data, req->args);
          }
          if (data->args.enable204 && ci_req_allow204(req))
               data->allow204 = 1;
          else
               data->allow204 = 0;
          data->req = req;
#ifdef USE_VSCAN_PROFILES
          data->profile = NULL;
#endif
#ifdef VIRALATOR_MODE
          data->last_update = 0;
          data->requested_filename = NULL;
          data->vir_mode_state = VIR_ZERO;
          data->expected_size = 0;
#endif
          return data;
     }
     return NULL;
}


void virus_scan_release_request_data(void *data)
{
     if (data) {
          ci_debug_printf(5, "Releasing virus_scan data.....\n");
#ifdef VIRALATOR_MODE
          if (((av_req_data_t *) data)->must_scanned == VIR_SCAN) {
               av_body_data_release(&(((av_req_data_t *) data)->body));
               if (((av_req_data_t *) data)->requested_filename)
                    ci_buffer_free(((av_req_data_t *) data)->requested_filename);
          }
          else
#endif
               av_body_data_destroy(&(((av_req_data_t *) data)->body));

          if (((av_req_data_t *) data)->error_page)
               ci_membuf_free(((av_req_data_t *) data)->error_page);

          if (((av_req_data_t *) data)->virus_info.viruses)
              ci_vector_destroy(((av_req_data_t *) data)->virus_info.viruses);
          ci_object_pool_free(data);
     }
}


int virus_scan_check_preview_handler(char *preview_data, int preview_data_len,
                                    ci_request_t *req)
{
     ci_off_t content_size = 0;
#ifdef USE_VSCAN_PROFILES
     struct av_req_profile *prof = NULL;
     char buf[256];
#endif
     av_req_data_t *data = ci_service_data(req);

     ci_debug_printf(6, "OK; the preview data size is %d\n", preview_data_len);

     if (!data || !ci_req_hasbody(req)){
	 ci_debug_printf(6, "No body data, allow 204\n");
          return CI_MOD_ALLOW204;
     }

#ifdef USE_VSCAN_PROFILES
     /*Select correct if any profile*/
     prof = av_req_profile_select(req);
     if (prof) {
         ci_debug_printf(6, "Selected profile is: %s\n", prof->name);
         data->profile = prof;
         if (prof->max_object_size && MAX_OBJECT_SIZE > prof->max_object_size)
             data->max_object_size = prof->max_object_size;
         else
             data->max_object_size = MAX_OBJECT_SIZE;

         data->send_percent_bytes = prof->send_percent_data >= 0 ? prof->send_percent_data : SEND_PERCENT_DATA;
         data->start_send_after = prof->start_send_after >= 0 ? prof->start_send_after : START_SEND_AFTER;

         if (prof->engines[0] != NULL)
             memcpy(data->engine, prof->engines, AV_MAX_ENGINES * sizeof(av_engine_t *));
         snprintf(buf, sizeof(buf), "X-ICAP-Profile: %s", prof->name);
         buf[sizeof(buf)-1] = '\0';
         ci_icap_add_xheader(req, buf);
     }
     else {
#else
    {
#endif
         data->max_object_size = MAX_OBJECT_SIZE;
         data->send_percent_bytes = SEND_PERCENT_DATA;
         data->start_send_after = START_SEND_AFTER;
     }

     if (!data->engine[0]) {
         ci_debug_printf(1, "Antivirus engine is not available, allow 204\n");
         return CI_MOD_ALLOW204;
     }

     /*Compute the expected size, will be used by must_scanned*/
     content_size = ci_http_content_length(req);
     data->expected_size = content_size;

     /*log objects url*/
     if (!ci_http_request_url(req, data->url_log, LOG_URL_SIZE)) {
         ci_debug_printf(2, "Failed to retrieve HTTP request URL\n");
     }

     if (preview_data_len == 0) {
         data->must_scanned = NO_DECISION;
         return CI_MOD_CONTINUE;
     }

     /*must_scanned will fill the data->must_scanned field*/
     if (must_scanned(req, preview_data, preview_data_len) == NO_SCAN) {
          ci_debug_printf(6, "Not in scan list. Allow it...... \n");
          return CI_MOD_ALLOW204;
     }

     if (init_body_data(req) == CI_ERROR)
         return CI_ERROR;

     if (preview_data_len) {
         if (av_body_data_write(&data->body, preview_data, preview_data_len,
                                ci_req_hasalldata(req)) == CI_ERROR)
	     return CI_ERROR;
     }

     return CI_MOD_CONTINUE;
}

int virus_scan_read_from_net(char *buf, int len, int iseof, ci_request_t *req)
{
     /*We can put here scanning hor jscripts and html and raw data ...... */
     int ret;
     int allow_transfer;
     av_req_data_t *data = ci_service_data(req);
     if (!data)
          return CI_ERROR;

     if (data->must_scanned == NO_DECISION) {
         /*Build preview data
           TODO: move to c-icap/request.c ....
          */
         if (len) {
             ret = ci_buf_reset_size(&(req->preview_data), len > 1024? 1024 : len);
             assert(ret > 0);
             ci_buf_write(&(req->preview_data), buf, len > 1024 ? 1024 : len);
         }
         if (must_scanned(req, buf, len) == NO_SCAN) {
             ci_debug_printf(6, "Outside preview check: Not in scan list. Allow it...... \n");
         }

         if (init_body_data(req) == CI_ERROR)
             return CI_ERROR;

         if (data->must_scanned == NO_SCAN) {
             ci_req_unlock_data(req);
             av_body_data_unlock_all(&(data->body));
         }
     }
     assert(data->must_scanned != NO_DECISION);

     if (data->body.type == AV_BT_NONE) /*No body data? consume all content*/
	 return len;

     if (data->must_scanned == NO_SCAN
#ifdef VIRALATOR_MODE
         || data->must_scanned == VIR_SCAN
#endif
         ) {                    /*if must not scanned then simply write the data and exit..... */
          return av_body_data_write(&data->body, buf, len, iseof);
     }

     if (data->args.sizelimit
         && av_body_data_size(&data->body) >= data->max_object_size) {
         ci_debug_printf(5, "Object bigger than max scanable file. \n");
          data->must_scanned = 0;

          if(data->args.mode == 1){
              /*We are in simple mode we can not send early ICAP responses. What?*/
              ci_debug_printf(1, "Object does not fit to max object size and early responses are not allowed! \n");
              return CI_ERROR;
          }
          else { /*Send early response.*/
              ci_req_unlock_data(req);      /*Allow ICAP to send data before receives the EOF....... */
              av_body_data_unlock_all(&data->body);        /*Unlock all body data to continue send them..... */
          }

     }                          /*else Allow transfer data->send_percent_bytes of the data */
     else if (data->args.mode != 1 &&   /*not in the simple mode */
              data->start_send_after < av_body_data_size(&data->body)) {
          ci_req_unlock_data(req);
#if 1
          assert(data->send_percent_bytes >= 0 && data->send_percent_bytes <= 100);
#endif
          allow_transfer =
              (data->send_percent_bytes * (av_body_data_size(&data->body) + len)) / 100;
          av_body_data_unlock(&data->body, allow_transfer);
     }
     return av_body_data_write(&data->body, buf, len, iseof);
}



int virus_scan_write_to_net(char *buf, int len, ci_request_t *req)
{
     int bytes;
     av_req_data_t *data = ci_service_data(req);
     if (!data)
          return CI_ERROR;

#ifdef VIRALATOR_MODE
     if (data->must_scanned == VIR_SCAN) {
          return send_vir_mode_page(data, buf, len, req);
     }
#endif

     if (data->virus_info.virus_found && data->error_page == 0 &&
         !(data->virus_info.disinfected)) {
          /*Inform user. Q:How? Maybe with a mail...... */
          return CI_EOF;        /* Do not send more data if a virus found and data has sent (readpos!=0) */
     }
     /*if a virus found and no data sent, an inform page has already generated */

     if (data->error_page)
          return ci_membuf_read(data->error_page, buf, len);

     if(data->body.type != AV_BT_NONE)
	 bytes = av_body_data_read(&data->body, buf, len);
     else
	 bytes =0;
     return bytes;
}

int virus_scan_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                 ci_request_t *req)
{
     if (rbuf && rlen) {
          *rlen = virus_scan_read_from_net(rbuf, *rlen, iseof, req);
	  if (*rlen == CI_ERROR)
	       return CI_ERROR;
          /*else if (*rlen < 0) ignore*/
     }
     else if (iseof) {
	 if (virus_scan_read_from_net(NULL, 0, iseof, req) == CI_ERROR)
	     return CI_ERROR;
     }

     if (wbuf && wlen) {
          *wlen = virus_scan_write_to_net(wbuf, *wlen, req);
     }
     return CI_OK;
}

static int virus_scan(ci_request_t *req, av_req_data_t *data);
int virus_scan_end_of_data_handler(ci_request_t *req)
{
     av_req_data_t *data = ci_service_data(req);
     const char *http_client_ip;
     if (!data || data->body.type == AV_BT_NONE)
          return CI_MOD_DONE;

     data->virus_check_done = 1;
     ci_debug_printf(6, "Scan from file\n");
     if (virus_scan(req, data) == CI_ERROR) {
         ci_debug_printf(1, "Error while scanning for virus. Aborting....\n");
         return CI_ERROR;
     }
     if (data->virus_info.virus_found) {
         ci_request_set_str_attribute(req,"virus_scan:virus", data->virus_info.virus_name);
         ci_stat_uint64_inc(AV_VIRUSES_FOUND, 1);
	  http_client_ip = ci_headers_value(req->request_header, "X-Client-IP");
          ci_debug_printf(1, "VIRUS DETECTED: %s , http client ip: %s, http user: %s, http url: %s \n ",
                          data->virus_info.virus_name,
			  (http_client_ip != NULL? http_client_ip : "-"),
			  (req->user[0] != '\0'? req->user: "-"),
			  data->url_log
	      );
     }
     if ((data->virus_info.virus_found && data->virus_info.disinfected) &&
         (!ci_req_sent_data(req) || data->must_scanned == VIR_SCAN)) {
         rebuild_content_length(req, &data->body);
     }
     else if (data->virus_info.virus_found){
          if (!ci_req_sent_data(req)) {   /*If no data had sent we can send an error page  */
#ifdef VIRALATOR_MODE
              if (data->must_scanned == VIR_SCAN) {
                  /*For file types required the virelator mode then the error page with the
                    head data already exist. Release it first. */
                  if (data->error_page) {
                      ci_membuf_free(data->error_page);
                      data->error_page = NULL;
                  }
                  /* ... do other virmode releases if required ...*/
                  /* Go back to normal scan mode*/
                  data->must_scanned = SCAN;
              }
#endif /*VIRELATOR_MODE*/
               generate_error_page(data, req);
               ci_request_set_str_attribute(req,"virus_scan:action", "blocked");
          }
#ifdef VIRALATOR_MODE
          else if (data->must_scanned == VIR_SCAN) {
               endof_data_vir_mode(data, req);
               ci_request_set_str_attribute(req,"virus_scan:action", "blocked");
          }
#endif /*VIRELATOR_MODE*/
          else {
               ci_debug_printf(5, "Simply no other data sent\n");
               ci_request_set_str_attribute(req,"virus_scan:action", "partiallyblocked");
          }
          return CI_MOD_DONE;
     }

     if (data->virus_info.disinfected)
         ci_request_set_str_attribute(req,"virus_scan:action", "disinfected");
     else
         ci_request_set_str_attribute(req,"virus_scan:action", "passed");
#ifdef VIRALATOR_MODE
     if (data->must_scanned == VIR_SCAN) {
          endof_data_vir_mode(data, req);
     }
     else
#endif /* VIRELATOR_MODE */
         if (data->allow204 && !ci_req_sent_data(req) && !data->virus_info.disinfected) {
             ci_debug_printf(6, "virus_scan module: Respond with allow 204\n");
             return CI_MOD_ALLOW204;
         }
     ci_req_unlock_data(req);
     av_body_data_unlock_all(&data->body);   /*Unlock all data to continue send them..... */
//     ci_debug_printf(6,
//                     "file unlocked, flags: %d (unlocked:%" PRINTF_OFF_T ")\n",
//                     body->flags, (CAST_OFF_T) body->unlocked);
     return CI_MOD_DONE;
}

static int handle_deflated(av_req_data_t *data)
{
    const char *err = NULL;
    /*
      Normally antiviruses can not handle deflate encoding, because there is not
      any way to recognize them. So try to uncompress deflated files before pass them
      to the antivirus engine.
    */
    int ret = CI_UNCOMP_OK;

    if (data->encoded != CI_ENCODE_DEFLATE
#if defined(HAVE_CICAP_BROTLI)
        && data->encoded != CI_ENCODE_BROTLI
#endif
       )
        return 1;

    if ((data->body.decoded = ci_simple_file_new(0))) {
        const char *zippedData = NULL;
        size_t zippedDataLen = 0;
        if (data->body.type == AV_BT_FILE) {
            zippedData = ci_simple_file_to_const_string(data->body.store.file);
            zippedDataLen = data->body.store.file->endpos;
            /**/
        } else {
            assert(data->body.type == AV_BT_MEM);
            zippedData = data->body.store.mem->buf;
            zippedDataLen = data->body.store.mem->endpos;
        }
        if (zippedData) {
            ci_debug_printf(3, "Zipped data %p of size %ld, encoding method: %s\n", zippedData, (long int) zippedDataLen, (data->encoded == CI_ENCODE_DEFLATE ? "deflate" : "brotli"));
            ret = av_decompress_to_simple_file(data->encoded, zippedData, zippedDataLen, data->body.decoded, MAX_OBJECT_SIZE);
            ci_debug_printf(3, "Scan from unzipped file %s of size %lld\n", data->body.decoded->filename, (long long int)data->body.decoded->endpos);
        }
    } else {
        ci_debug_printf(1, "Enable to create temporary file to decode deflated file!\n");
        ret = CI_UNCOMP_ERR_ERROR;
    }


    if (ret ==CI_UNCOMP_OK)
        return 1;

    if (ret == CI_UNCOMP_ERR_NONE) /*Exceeds the maximum allowed size*/
        data->must_scanned = NO_SCAN;
    else {
        /*Probably corrupted object. Handle it as virus*/
#if defined(HAVE_CICAP_DECOMPRESS_ERROR)
        err = ci_decompress_error(ret);
#else
        err = ci_inflate_error(ret);
#endif
        ci_stat_uint64_inc(AV_SCAN_FAILURES, 1);
        if (PASSONERROR) {
            ci_debug_printf(1, "Unable to uncompress deflate encoded data: %s! Let it pass due to PassOnError\n", err);
            return 1;
        }

        /*virus_scan_inflate_error always return a no null description*/
        ci_debug_printf(1, "Unable to uncompress deflate encoded data: %s! Handle object as infected\n", err);
        strncpy(data->virus_info.virus_name, err, AV_NAME_SIZE);
        data->virus_info.virus_name[AV_NAME_SIZE - 1] = '\0';
        data->virus_info.virus_found = 1;
    }
    return 0;
}

static int virus_scan(ci_request_t *req, av_req_data_t *data)
{
    int scan_status, i;

    if (data->must_scanned == NO_SCAN) {       /*If exceeds the MAX_OBJECT_SIZE for example ......  */
        return CI_OK;
    }

    if (handle_deflated(data)) {
        /*TODO Must check for errors*/
        if (data->engine[0]) {
            for (i=0; data->engine[i] != NULL && !data->virus_info.virus_found; i++) {
                ci_debug_printf(4, "Use '%s' engine to scan data\n", data->engine[i]->name);
                if (data->body.decoded)
                    scan_status = data->engine[i]->scan_simple_file(data->body.decoded, &data->virus_info);
                else if (data->body.type == AV_BT_FILE)
                    scan_status = data->engine[i]->scan_simple_file(data->body.store.file, &data->virus_info);
                else // if (data->body.type == AV_BT_MEM)
                    scan_status = data->engine[i]->scan_membuf(data->body.store.mem, &data->virus_info);

                /* we can not disinfect encoded files yet
                   nor files which partialy sent back to client*/
                if (data->virus_info.disinfected && (data->body.decoded || ci_req_sent_data(req)))
                    data->virus_info.disinfected = 0;


                if (!scan_status) {
                    ci_stat_uint64_inc(AV_SCAN_FAILURES, 1);
                    ci_debug_printf(1, "Failed to scan web object\n");
                    /* We need to inform the caller proxy for the error,
                       to give the opportunity to stop using this broken
                       icap service.
                     */
                    if (!PASSONERROR)
                        return CI_ERROR;
                }
            }
            build_reply_headers(req, &data->virus_info);
        }
        ci_stat_uint64_inc(AV_SCAN_REQS, 1);
        ci_stat_kbs_inc(AV_SCAN_BYTES, (int)av_body_data_size(&data->body));
    }
    return CI_OK;
}

struct print_buf{
    char *buf;
    int size;
    int count;
    const char *sep;
};



static int print_violation(void *d, const void *item)
{
    /* We need to print :
      Filename                  = TEXT
      ThreadDescription         = TEXT
      ProblemID                 = 1*DIGIT
      ResolutionID              = 0 | 1 | 2
     */
    char buf[512];
    int bytes;
    struct print_buf *pb = (struct print_buf *) d;
    av_virus_t *sdata = (av_virus_t *) item;

    if (pb->size <=0)
        return 1; /*Stop iterating*/

    bytes = snprintf(buf, sizeof(buf), "\r\n\t-\r\n\t%s\r\n\t%d\r\n\t%d",
                     sdata->virus,
                     sdata->problemID,
                     sdata->action);
    buf[sizeof(buf) - 1] = '\0';
    bytes = (bytes < sizeof(buf) ? bytes : sizeof(buf));
    if (bytes > pb->size)
        return 1; /*Do not print, stop iterating*/
    strcpy(pb->buf, buf);
    pb->buf = pb->buf + bytes;
    pb->size -= bytes;
    ci_debug_printf(5, "Print violation: %s (next bytes: %d)\n", buf, pb->size);
    return 0;
}

static void print_xviolations(char *buf, size_t buf_size,  av_virus_info_t *vinfo)
{
    int i;
    struct print_buf pb;
    ci_vector_t *viruses = vinfo->viruses;
    if (buf_size < 128) return;  /*must have an enough big size*/

    if (viruses && viruses->count >0) {        
        i = snprintf(buf, buf_size, "%d", viruses->count);
        pb.buf = buf+i;
        pb.size = buf_size - i;
        ci_vector_iterate(viruses, &pb, print_violation);
    } else if (vinfo->virus_name[0] != '\0') {
        snprintf(buf, buf_size, "1\r\n\t-\r\n\t%s\r\n\t0\r\n\t0", vinfo->virus_name);
    } else
        snprintf(buf, buf_size, "-");

    ci_debug_printf(5, "Print viruses header %s\n", buf);
}

static struct actions {
    int act_code;
    const char *act_str;
} ACTIONS[] = {
    {AV_NONE, "NO_ACTION"},
    {AV_CLEAN, "DISINFECTED"},
    {AV_FILE_REMOVED, "DELETED"},
    {-1, NULL}
};

static const char *av_action(int code){
    int i=0;
    for(i=0; ACTIONS[i].act_str != NULL; i++) {
        if (ACTIONS[i].act_code == code)
            return ACTIONS[i].act_str;
    }
    return "-";
}

static int print_virus_item(void *d, const void *item)
{
    char buf[512];
    int bytes;
    struct print_buf *pb = (struct print_buf *) d;
    av_virus_t *sdata = ( av_virus_t *) item;

    if (pb->size <=0)
        return 1; /*Stop iterating*/

    bytes = snprintf(buf, sizeof(buf), "%s%s:%s:%s",
                     (pb->count > 0 ? pb->sep : ""),
                     sdata->virus,
                     sdata->type,
                     av_action(sdata->action));
    buf[sizeof(buf) - 1] = '\0';
    bytes = (bytes < sizeof(buf) ? bytes : sizeof(buf));
    if (bytes > pb->size)
        return 1; /*Do not print, stop iterating*/
    strcpy(pb->buf, buf);
    pb->buf = pb->buf + bytes;
    pb->size -= bytes;
    pb->count++;
    ci_debug_printf(5, "Print violation: %s (next bytes: %d)\n", buf, pb->size);
    return 0;
}

int print_viruses_list(char *buf, size_t buf_size,  av_virus_info_t *vinfo, const char *sep)
{
    struct print_buf pb;
    ci_vector_t *viruses = vinfo->viruses;
    if (viruses) {
        pb.buf = buf;
        pb.size = buf_size ;
        pb.count = 0;
        if (sep)
            pb.sep = sep;
        else
            pb.sep = ", ";
        ci_vector_iterate(viruses, &pb, print_virus_item);
        ci_debug_printf(5, "Print viruses list %s\n", buf);
        return (buf_size - pb.size);
    } else if (vinfo->virus_name[0] != '\0') {
        // If no viruses list provided try the virus_name
        // On errors only av_virus_info_t::virus_name  updated
        snprintf(buf, buf_size, "%s::%s", vinfo->virus_name, av_action(AV_NONE));
    } else {
        buf[0] = '-';
        buf[1] = '\0';
    }
    return 0;
}

void build_reply_headers(ci_request_t *req, av_virus_info_t *vinfo)
{
    char head[1024];

    if (!vinfo)
        return;

    if (vinfo->virus_found && !ci_req_sent_data(req)) {
        snprintf(head, sizeof(head), "X-Infection-Found: Type=0; Resolution=%d; Threat=%s;",
                 (vinfo->disinfected ? 1 : 2),
                 vinfo->virus_name[0] != '\0' ? vinfo->virus_name : "Unknown");
        head[sizeof(head)-1] = '\0';
        ci_icap_add_xheader(req, head);

        if (vinfo->viruses && vinfo->viruses->count >0) {
            strcpy(head, "X-Violations-Found: ");
            print_xviolations((head+20), sizeof(head) - 20,  vinfo);
            ci_icap_add_xheader(req, head);
        }
    }

    if (vinfo->virus_found) {
        print_viruses_list(head, sizeof(head), vinfo, ", ");
        ci_request_set_str_attribute(req, "virus_scan:viruses-list", head);
    }
}

/*******************************************************************************/
/* Other  functions                                                            */

static int istag_update_md5(void *ctx, const char *name, const void *engine_ptr)
{
    const char *sig;
    av_engine_t *eng = (av_engine_t *) engine_ptr;
    struct ci_MD5Context *mdctx = (struct ci_MD5Context *)ctx;
    ci_debug_printf(5, "ISTAG update %s\n", name);
    sig = eng->signature();
    ci_MD5Update(mdctx, (const unsigned char *)sig, (size_t)strlen(sig));
    return 0;
}

void set_istag(ci_service_xdata_t *srv_xdata)
{
     char istag[SERVICE_ISTAG_SIZE + 1];
     struct ci_MD5Context mdctx;
     unsigned char digest[16];
     assert(SERVICE_ISTAG_SIZE >= 25);
     ci_MD5Init(&mdctx);
     ci_registry_iterate(AV_ENGINES_REGISTRY, &mdctx, istag_update_md5);
     ci_MD5Final(digest, &mdctx);
     istag[0] = '-';
     ci_base64_encode(digest, 16, istag+1, SERVICE_ISTAG_SIZE);
     ci_service_set_istag(srv_xdata, istag);
}

int get_filetype(ci_request_t *req, int *iscompressed)
{
      int filetype;
      /*Use the ci_magic_req_data_type which caches the result*/
      filetype = ci_magic_req_data_type(req, iscompressed);
     return filetype;
}

static int init_body_data(ci_request_t *req)
{
    int scan_from_mem, i;
    av_req_data_t *data = ci_service_data(req);
    assert(data);
#ifdef VIRALATOR_MODE
     if (data->must_scanned == VIR_SCAN) {
          init_vir_mode_data(req, data);
          ci_stat_uint64_inc(AV_VIRMODE_REQS, 1);
     }
     else {
#endif
         scan_from_mem = 1;
         for (i=0; data->engine[i] != NULL; i++) {
             /*If one of the engines does not support scanning from mem scan from file*/
             if(!(data->engine[i]->options & AV_OPT_MEM_SCAN) || data->engine[i]->scan_membuf == NULL)
                 scan_from_mem = 0;
         }

         if (scan_from_mem &&
             data->expected_size > 0 && data->expected_size < CI_BODY_MAX_MEM)
             av_body_data_new(&(data->body), AV_BT_MEM, data->expected_size);
         else
             av_body_data_new(&(data->body), AV_BT_FILE, data->args.sizelimit==0 ? 0 : data->max_object_size);
          /*Icap server can not send data at the begining.
            The following call does not needed because the c-icap
            does not send any data if the ci_req_unlock_data is not called:*/
          /* ci_req_lock_data(req);*/

          /* Let ci_simple_file api to control the percentage of data.
             For now no data can send */
          av_body_data_lock_all(&(data->body));
#ifdef VIRALATOR_MODE
     }
#endif
     if (data->body.type == AV_BT_NONE)           /*Memory allocation or something else ..... */
         return CI_ERROR;

     return CI_OK;
}

int must_scanned(ci_request_t *req, char *preview_data, int preview_data_len)
{
/* We are assuming that file_type is a valid file type.
   The caller is responsible to pass a valid file_type value
*/
     int type, i;
     int *file_groups;
     int file_type;
     const struct av_file_types *configured_file_types = NULL;
     av_req_data_t *data  = ci_service_data(req);;

     /*By default do not scan*/
     type = NO_SCAN;

#ifdef USE_VSCAN_PROFILES
     if (data->profile) {
         if (data->profile->disable_scan)
             return (data->must_scanned = NO_SCAN);
         configured_file_types = &data->profile->scan_file_types;
     }
     else
#endif
         configured_file_types = &SCAN_FILE_TYPES;
     /*Going to determine the file type,get_filetype can take preview_data as null ....... */
     file_type = get_filetype(req, &data->encoded);

     if (preview_data_len == 0 || file_type < 0) {
	 if (ci_http_request_url(req, data->url_log, LOG_URL_SIZE) <= 0)
             strcpy(data->url_log, "-");

	 ci_debug_printf(1, "WARNING! %s, can not get required info to scan url: %s\n",
			 (preview_data_len == 0? "No preview data" : "Error computing file type"),
			 data->url_log);
         /*
           By default do not scan when you are not able to retrieve filetype.
           TODO: Define configuration parameters to allow user decide if such
                      objects must scanned or not.
          */
     }
     else { /*We have a valid filetype*/
         file_groups = ci_data_type_groups(magic_db, file_type);
         i = 0;
         if (file_groups) {
             while ( i < MAX_GROUPS && file_groups[i] >= 0) {
                 assert(file_groups[i] < ci_magic_groups_num(magic_db));
                 if ((type = configured_file_types->scangroups[file_groups[i]]) > 0)
                     break;
                 i++;
             }
         }

         if (type == NO_SCAN) {
             assert(file_type < ci_magic_types_num(magic_db));
             type = configured_file_types->scantypes[file_type];
         }
     }

     if (type == NO_SCAN && data->args.forcescan)
          type = SCAN;
     else if (type == VIR_SCAN && data->args.mode == 1) /*in simple mode */
          type = SCAN;
     else if(data->args.mode == 4 && type == VIR_SCAN)
         type = SCAN; // We are in stream mode, there is no VIR_SCAN
     else if (type == VIR_SCAN && ci_req_type(req) != ICAP_RESPMOD)
          type = SCAN; /*Vir mode will not work in REQMOD requests*/
     else if (type == VIR_SCAN && (VIR_SAVE_DIR == NULL || VIR_HTTP_SERVER == NULL)) {
	  ci_debug_printf(1, "Vir mode requested for this file type but \"VirSaveDir\" or/and \"VirHTTPServer\" is not set!");
 	  type = SCAN;
     }

     if (type == SCAN && data->args.sizelimit && data->max_object_size &&
         data->expected_size > data->max_object_size) {
         ci_debug_printf(1,
                         "Object size is %" PRINTF_OFF_T " ."
                         " Bigger than max scannable file size (%"
                         PRINTF_OFF_T "). Allow it.... \n",
                         (CAST_OFF_T) data->expected_size,
                         (CAST_OFF_T) data->max_object_size);
         type = NO_SCAN;
     }

     data->must_scanned = type;
     return type;
}

void generate_error_page(av_req_data_t *data, ci_request_t *req)
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

     error_page = ci_txt_template_build_content(req, "virus_scan", "VIRUS_FOUND",
                           virus_scan_format_table);

     lang = ci_membuf_attr_get(error_page, "lang");
     if (lang) {
         snprintf(buf, sizeof(buf), "Content-Language: %s", lang);
         buf[sizeof(buf)-1] = '\0';
         ci_http_response_add_header(req, buf);
     }
     else
         ci_http_response_add_header(req, "Content-Language: en");

     data->error_page = error_page;
}

int av_file_types_init( struct av_file_types *ftypes)
{
    int i;
    ftypes->scantypes = (int *) malloc(ci_magic_types_num(magic_db) * sizeof(int));
    ftypes->scangroups = (int *) malloc(ci_magic_groups_num(magic_db) * sizeof(int));

    if (!ftypes->scantypes || !ftypes->scangroups)
        return 0;

    for (i = 0; i < ci_magic_types_num(magic_db); i++)
        ftypes->scantypes[i] = 0;
    for (i = 0; i < ci_magic_groups_num(magic_db); i++)
        ftypes->scangroups[i] = 0;
    return 1;
}

void av_file_types_destroy( struct av_file_types *ftypes)
{
    free(ftypes->scantypes);
    ftypes->scantypes = NULL;
    free(ftypes->scangroups);
    ftypes->scangroups = NULL;
}

static void cmd_reload_istag(const char *name, int type, void *data)
{
    ci_debug_printf(1, "recomputing istag ...\n");
    if (virus_scan_xdata)
        set_istag(virus_scan_xdata);
}

/***************************************************************************************/
/* Parse arguments function -
   Current arguments: allow204=on|off, force=on, sizelimit=off, mode=simple|vir|mixed
*/
void virus_scan_parse_args(av_req_data_t *data, char *args)
{
     char *str;
     size_t s;
     char buf[512];
     if ((str = strstr(args, "allow204="))) {
          if (strncmp(str + 9, "on", 2) == 0)
               data->args.enable204 = 1;
          else if (strncmp(str + 9, "off", 3) == 0)
               data->args.enable204 = 0;
     }
     if ((str = strstr(args, "force="))) {
          if (strncmp(str + 6, "on", 2) == 0)
               data->args.forcescan = 1;
     }
     if ((str = strstr(args, "sizelimit="))) {
          if (strncmp(str + 10, "off", 3) == 0)
               data->args.sizelimit = 0;
     }
     if ((str = strstr(args, "mode="))) {
          if (strncmp(str + 5, "simple", 6) == 0)
               data->args.mode = 1;
          else if (strncmp(str + 5, "vir", 3) == 0)
               data->args.mode = 2;
          else if (strncmp(str + 5, "mixed", 5) == 0)
               data->args.mode = 3;
          else if (strncmp(str + 5, "streamed", 8) == 0)
               data->args.mode = 4;
     }
     if ((str = strstr(args, "engine="))) {
         str += 7;
         s = strcspn(str, "&,");
         s = (s < (sizeof(buf) - 1) ? s : (sizeof(buf) - 1) );
         strncpy(buf, str, s);
         buf[s] = '\0';
         const av_engine_t *engine = ci_registry_get_item(AV_ENGINES_REGISTRY, buf);
         if (engine) {
             data->engine[0] = engine;
             data->engine[1] = NULL;
         } else {
             ci_debug_printf(2, "Requested engine '%s' is not available, using defaults\n", buf);
         }
     }
}

void rebuild_content_length(ci_request_t *req, struct av_body_data *bd)
{
    ci_off_t new_file_size = 0;
    char buf[256];
    ci_simple_file_t *body = NULL;
    ci_membuf_t *memBuf = NULL;

    if (bd->type == AV_BT_FILE) {
        body = bd->store.file;
        assert(body->readpos == 0);
        new_file_size = body->endpos;
    }
    else if (bd->type == AV_BT_MEM) {
        memBuf = bd->store.mem;
        new_file_size = memBuf->endpos;
    }
    else /*do nothing....*/
        return;

    ci_debug_printf(5, "Body data size changed to new size %"  PRINTF_OFF_T "\n",
                    (CAST_OFF_T)new_file_size);

    snprintf(buf, sizeof(buf), "Content-Length: %" PRINTF_OFF_T, (CAST_OFF_T)new_file_size);
    ci_http_response_remove_header(req, "Content-Length");
    ci_http_response_add_header(req, buf);
}

/****************************************************************************************/
/*Configuration Functions                                                               */

int cfg_ScanFileTypes(const char *directive, const char **argv, void *setdata)
{
     int i, id;
     int type = NO_SCAN;
     struct av_file_types *ftypes = (struct av_file_types *)setdata;
     if (!ftypes)
         return 0;

     if (strcmp(directive, "ScanFileTypes") == 0)
          type = SCAN;
     else if (strcmp(directive, "VirScanFileTypes") == 0)
          type = VIR_SCAN;
     else
          return 0;

     for (i = 0; argv[i] != NULL; i++) {
          if ((id = ci_get_data_type_id(magic_db, argv[i])) >= 0)
               ftypes->scantypes[id] = type;
          else if ((id = ci_get_data_group_id(magic_db, argv[i])) >= 0)
               ftypes->scangroups[id] = type;
          else
               ci_debug_printf(1, "Unknown data type %s \n", argv[i]);

     }

     ci_debug_printf(2, "I am going to scan data for %s scanning of type: ",
                     (type == 1 ? "simple" : "vir_mode"));
     for (i = 0; i < ci_magic_types_num(magic_db); i++) {
          if (ftypes->scantypes[i] == type)
               ci_debug_printf(2, ",%s", ci_data_type_name(magic_db, i));
     }
     for (i = 0; i < ci_magic_groups_num(magic_db); i++) {
          if (ftypes->scangroups[i] == type)
               ci_debug_printf(2, ",%s", ci_data_group_name(magic_db, i));
     }
     ci_debug_printf(1, "\n");
     return 1;
}


int cfg_SendPercentData(const char *directive, const char **argv, void *setdata)
{
     int val = 0;
     char *end;
     if (argv == NULL || argv[0] == NULL) {
          ci_debug_printf(1, "Missing arguments in directive %s \n", directive);
          return 0;
     }
     errno = 0;
     val = strtoll(argv[0], &end, 10);
     if (errno != 0 || val < 0 || val > 100) {
          ci_debug_printf(1, "Invalid argument in directive %s \n", directive);
          return 0;
     }

     *((int *) setdata) = val;
     ci_debug_printf(2, "Setting parameter: %s=%d\n", directive, val);
     return 1;
}

int cfg_av_set_str_vector(const char *directive, const char **argv, void *setdata)
{
    int i;
    ci_str_vector_t **v = (ci_str_vector_t **) setdata;
    if (*v == NULL)
        *v = ci_str_vector_create(4096);
    for (i = 0; argv[i] != NULL; i++)
        (void)ci_str_vector_add(*v, argv[i]);

    if (i > 0)
        return 1;

    return 0;
}

/**************************************************************/
/* virus_scan templates  formating table                      */

int fmt_virus_scan_virusname(ci_request_t *req, char *buf, int len, const char *param)
{
    av_req_data_t *data = ci_service_data(req);
    if (strcasecmp(param, "FullList") == 0)
        return print_viruses_list(buf, (len > 1024 ? 1024 : len), &data->virus_info, "\n");
    if (! data->virus_info.virus_found)
        return 0;

    return snprintf(buf, len, "%s", data->virus_info.virus_name);
}


int fmt_virus_scan_av_version(ci_request_t *req, char *buf, int len, const char *param)
{
    int i, bytes, ret;
    av_req_data_t *data = ci_service_data(req);
    for (i = 0, bytes = 0, ret = 0; data->engine[i] != NULL && len > 0; i++, len -= ret) {
        ret = snprintf(buf + bytes, len, "%s%s-%s", (i > 0 ? ", " : ""), data->engine[i]->name, data->engine[i]->version_str());
        bytes += ret; /*bytes may exceeds the input len but the caller will handle it*/
    }
    return bytes;
}

int fmt_virus_scan_http_url(ci_request_t *req, char *buf, int len, const char *param)
{
    av_req_data_t *data = ci_service_data(req);
    return snprintf(buf, len, "%s", data->url_log);
}

#ifdef USE_VSCAN_PROFILES
int fmt_virus_scan_profile(ci_request_t *req, char *buf, int len, const char *param)
{
    av_req_data_t *data = ci_service_data(req);
    if (data->profile)
        return snprintf(buf, len, "%s", data->profile->name);

    return snprintf(buf, len, "-");
}
#endif

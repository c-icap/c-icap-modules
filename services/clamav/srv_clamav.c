/*
 *  Copyright (C) 2004 Christos Tsantilas
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


#include "c-icap.h"
#include "service.h"
#include "header.h"
#include "simple_api.h"
#include "debug.h"
#include "cfg_param.h"
#include "srv_clamav.h"
#include "filetype.h"
#include "ci_threads.h"
#include "mem.h"
#include "commands.h"
#include "../../common.h"
#include "txt_format.h"
#include "txtTemplate.h"
#include <errno.h>


int must_scanned(ci_request_t *req, char *preview_data, int preview_data_len);

long int CLAMAV_MAXRECLEVEL = 5;
long int CLAMAV_MAX_FILES = 0;
ci_off_t CLAMAV_MAXFILESIZE = 100 * 1048576; /* maximal archived file size == 100 Mb */
char *CLAMAV_TMP = NULL;
#define CLAMAV_VERSION_SIZE 64
char CLAMAV_VERSION[CLAMAV_VERSION_SIZE];

void generate_error_page(av_req_data_t * data, ci_request_t * req);
char *srvclamav_compute_name(ci_request_t * req);
/***********************************************************************************/
/* Module definitions                                                              */

static int SEND_PERCENT_BYTES = 0;      /* Can send all bytes that has received without checked */
static int ALLOW204 = 1;
static ci_off_t MAX_OBJECT_SIZE = 5*1024*1024;
static ci_off_t START_SEND_AFTER = 0;

static struct ci_magics_db *magic_db = NULL;
static int *scantypes = NULL;
static int *scangroups = NULL;

/*char *VIR_SAVE_DIR="/srv/www/htdocs/downloads/";
  char *VIR_HTTP_SERVER="http://fortune/cgi-bin/get_file.pl?usename=%f&file="; */

char *VIR_SAVE_DIR = NULL;
char *VIR_HTTP_SERVER = NULL;
int VIR_UPDATE_TIME = 15;

/*********************/
/* Formating table   */
int fmt_srv_clamav_virusname(ci_request_t *req, char *buf, int len, char *param);
int fmt_srv_clamav_clamversion(ci_request_t *req, char *buf, int len, char *param);
int fmt_srv_clamav_http_url(ci_request_t *req, char *buf, int len, char *param);
#ifdef VIRALATOR_MODE
int fmt_srv_clamav_expect_size(ci_request_t *req, char *buf, int len, char *param);
int fmt_srv_clamav_filename(ci_request_t *req, char *buf, int len, char *param);
int fmt_srv_clamav_filename_requested(ci_request_t *req, char *buf, int len, char *param);
int fmt_srv_clamav_httpurl(ci_request_t *req, char *buf, int len, char *param);
#endif
struct ci_fmt_entry srv_clamav_format_table [] = {
    {"%VVN", "Virus name", fmt_srv_clamav_virusname},
    {"%VVV", "Clamav Antivirus name", fmt_srv_clamav_clamversion},
    {"%VU", "The HTTP url", fmt_srv_clamav_http_url},
#ifdef VIRALATOR_MODE
    {"%VFR", "downloaded file requested name", fmt_srv_clamav_filename_requested},
    {"%VFS", "Expected http body data size (Content-Length header)", fmt_srv_clamav_expect_size},
    {"%VF", "local filename", fmt_srv_clamav_filename},
    {"%VHS", "HTTP URL", fmt_srv_clamav_httpurl},
#endif
    { NULL, NULL, NULL}
};


/*srv_clamav service extra data ... */
ci_service_xdata_t *srv_clamav_xdata = NULL;

int AVREQDATA_POOL = -1;

int srvclamav_init_service(ci_service_xdata_t * srv_xdata,
                           struct ci_server_conf *server_conf);
int srvclamav_post_init_service(ci_service_xdata_t * srv_xdata,
                           struct ci_server_conf *server_conf);
void srvclamav_close_service();
int srvclamav_check_preview_handler(char *preview_data, int preview_data_len,
                                    ci_request_t *);
int srvclamav_end_of_data_handler(ci_request_t *);
void *srvclamav_init_request_data(ci_request_t * req);
void srvclamav_release_request_data(void *data);
int srvclamav_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                 ci_request_t * req);

/*Arguments parse*/
void srvclamav_parse_args(av_req_data_t * data, char *args);
/*Configuration Functions*/
int cfg_ScanFileTypes(char *directive, char **argv, void *setdata);
int cfg_SendPercentBytes(char *directive, char **argv, void *setdata);
int cfg_ClamAvTmpDir(char *directive, char **argv, void *setdata);
/*Commands functions*/
void dbreload_command(char *name, int type, char **argv);
/*General functions*/
int get_filetype(ci_request_t * req);
void set_istag(ci_service_xdata_t * srv_xdata);

/*It is dangerous to pass directly fields of the limits structure in conf_variables,
  becouse in the feature some of this fields will change type (from int to unsigned int 
  or from long to long long etc)
  I must use global variables and use the post_init_service function to fill the 
  limits structure.
  But, OK let it go for the time ....
*/

/*Configuration Table .....*/
static struct ci_conf_entry conf_variables[] = {
     {"SendPercentData", NULL, cfg_SendPercentBytes, NULL},
     {"ScanFileTypes", NULL, cfg_ScanFileTypes, NULL},
     {"MaxObjectSize", &MAX_OBJECT_SIZE, ci_cfg_size_off, NULL},
     {"StartSendPercentDataAfter", &START_SEND_AFTER, ci_cfg_size_off, NULL},
     {"Allow204Responces", &ALLOW204, ci_cfg_onoff, NULL},
     {"ClamAvMaxRecLevel", &CLAMAV_MAXRECLEVEL, ci_cfg_size_long, NULL},
     {"ClamAvMaxFilesInArchive", &CLAMAV_MAX_FILES, ci_cfg_size_long, NULL},
/*     {"ClamAvBzipMemLimit",NULL,setBoolean,NULL},*/
     {"ClamAvMaxFileSizeInArchive", &CLAMAV_MAXFILESIZE, ci_cfg_size_off,
      NULL},
     {"ClamAvTmpDir", NULL, cfg_ClamAvTmpDir, NULL},
#ifdef VIRALATOR_MODE
     {"VirSaveDir", &VIR_SAVE_DIR, ci_cfg_set_str, NULL},
     {"VirHTTPUrl", &VIR_HTTP_SERVER, ci_cfg_set_str, NULL},
     {"VirUpdateTime", &VIR_UPDATE_TIME, ci_cfg_set_int, NULL},
     {"VirScanFileTypes", NULL, cfg_ScanFileTypes, NULL},
#endif
     {NULL, NULL, NULL, NULL}
};


CI_DECLARE_MOD_DATA ci_service_module_t service = {
     "srv_clamav",              /*Module name */
     "Clamav/Antivirus service",        /*Module short description */
     ICAP_RESPMOD | ICAP_REQMOD,        /*Service type responce or request modification */
     srvclamav_init_service,    /*init_service. */
     srvclamav_post_init_service,   /*post_init_service. */
     srvclamav_close_service,   /*close_service */
     srvclamav_init_request_data,       /*init_request_data. */
     srvclamav_release_request_data,    /*release request data */
     srvclamav_check_preview_handler,
     srvclamav_end_of_data_handler,
     srvclamav_io,
     conf_variables,
     NULL
};



int srvclamav_init_service(ci_service_xdata_t * srv_xdata,
                           struct ci_server_conf *server_conf)
{
     int ret, i;
     magic_db = server_conf->MAGIC_DB;
     scantypes = (int *) malloc(ci_magic_types_num(magic_db) * sizeof(int));
     scangroups = (int *) malloc(ci_magic_groups_num(magic_db) * sizeof(int));

     for (i = 0; i < ci_magic_types_num(magic_db); i++)
          scantypes[i] = 0;
     for (i = 0; i < ci_magic_groups_num(magic_db); i++)
          scangroups[i] = 0;


     ci_debug_printf(10, "Going to initialize srvclamav\n");
     ret = clamav_init_virusdb();
     if (!ret)
          return 0;
     srv_clamav_xdata = srv_xdata;      /*Needed by db_reload command */
     set_istag(srv_clamav_xdata);
     ci_service_set_preview(srv_xdata, 1024);
     ci_service_enable_204(srv_xdata);
     ci_service_set_transfer_preview(srv_xdata, "*");
 

     /*Initialize object pools*/
     AVREQDATA_POOL = ci_object_pool_register("av_req_data_t", sizeof(av_req_data_t));

     if(AVREQDATA_POOL < 0) {
	 ci_debug_printf(1, " srvclamav_init_service: error registering object_pool av_req_data_t\n");
	 return 0;
     }
     /*initialize service commands */
     register_command("srv_clamav:dbreload", MONITOR_PROC_CMD | CHILDS_PROC_CMD,
                      dbreload_command);

     return 1;
}

int srvclamav_post_init_service(ci_service_xdata_t * srv_xdata,
                           struct ci_server_conf *server_conf)
{
    return clamav_init();
}

void srvclamav_close_service()
{
     free(scantypes);
     scantypes = NULL;
     free(scangroups);
     scangroups = NULL;
     ci_object_pool_unregister(AVREQDATA_POOL);
     clamav_destroy_virusdb();
     if (CLAMAV_TMP)
         free(CLAMAV_TMP);
}

void *srvclamav_init_request_data(ci_request_t * req)
{
     int preview_size;
     av_req_data_t *data;

     preview_size = ci_req_preview_size(req);

     if (req->args) {
          ci_debug_printf(5, "service arguments:%s\n", req->args);
     }
     if (ci_req_hasbody(req)) {
          ci_debug_printf(5, "Request type: %d. Preview size:%d\n", req->type,
                          preview_size);
          if (!(data = ci_object_pool_alloc(AVREQDATA_POOL))) {
               ci_debug_printf(1,
                               "Error allocation memory for service data!!!!!!!");
               return NULL;
          }
          data->body = NULL;
          data->error_page = NULL;
          data->virus_name = NULL;
          data->must_scanned = SCAN;
          data->virus_check_done = 0;
          if (ALLOW204)
               data->args.enable204 = 1;
          else
               data->args.enable204 = 0;
          data->args.forcescan = 0;
          data->args.sizelimit = 1;
          data->args.mode = 0;

          if (req->args) {
               ci_debug_printf(5, "service arguments:%s\n", req->args);
               srvclamav_parse_args(data, req->args);
          }
          if (data->args.enable204 && ci_allow204(req))
               data->allow204 = 1;
          else
               data->allow204 = 0;
          data->req = req;

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


void srvclamav_release_request_data(void *data)
{
     if (data) {
          ci_debug_printf(5, "Releasing srv_clamav data.....\n");
#ifdef VIRALATOR_MODE
          if (((av_req_data_t *) data)->must_scanned == VIR_SCAN) {
               ci_simple_file_release(((av_req_data_t *) data)->body);
               if (((av_req_data_t *) data)->requested_filename)
                    ci_buffer_free(((av_req_data_t *) data)->requested_filename);
          }
          else
#endif
          if (((av_req_data_t *) data)->body)
               ci_simple_file_destroy(((av_req_data_t *) data)->body);

          if (((av_req_data_t *) data)->error_page)
               ci_membuf_free(((av_req_data_t *) data)->error_page);

          if (((av_req_data_t *) data)->virus_name)
               ci_buffer_free(((av_req_data_t *) data)->virus_name);
          ci_object_pool_free(data);
     }
}


int srvclamav_check_preview_handler(char *preview_data, int preview_data_len,
                                    ci_request_t * req)
{
     ci_off_t content_size = 0;
     av_req_data_t *data = ci_service_data(req);

     ci_debug_printf(6, "OK; the preview data size is %d\n", preview_data_len);

     if (!data || !ci_req_hasbody(req)){
	 ci_debug_printf(6, "No body data, allow 204\n");
          return CI_MOD_ALLOW204;
     }

     /*Compute the expected size, will be used by must_scanned*/
     content_size = ci_http_content_length(req);
     data->expected_size = content_size;

     /*must_scanned will fill the data->must_scanned field*/
     if (must_scanned(req, preview_data, preview_data_len) == NO_SCAN) {
          ci_debug_printf(6, "Not in scan list. Allow it...... \n");
          return CI_MOD_ALLOW204;
     }

#ifdef VIRALATOR_MODE
     if (data->must_scanned == VIR_SCAN) {
          init_vir_mode_data(req, data);
     }
     else {
#endif
          data->body = ci_simple_file_new(data->args.sizelimit==0 ? 0 : MAX_OBJECT_SIZE);

          if (SEND_PERCENT_BYTES >= 0 && START_SEND_AFTER == 0) {
               ci_req_unlock_data(req); /*Icap server can send data before all body has received */
               /*Let ci_simple_file api to control the percentage of data.For the beggining no data can send.. */
               ci_simple_file_lock_all(data->body);
          }
#ifdef VIRALATOR_MODE
     }
#endif
     if (!data->body)           /*Memory allocation or something else ..... */
          return CI_ERROR;

     if (preview_data_len) {
	 if (ci_simple_file_write(data->body, preview_data, preview_data_len,
				  ci_req_hasalldata(req)) == CI_ERROR)
	     return CI_ERROR;
     }

     /*We are going to proceed scanning this object log its url*/
     ci_http_request_url(req, data->url_log, LOG_URL_SIZE);
     return CI_MOD_CONTINUE;
}



int srvclamav_read_from_net(char *buf, int len, int iseof, ci_request_t * req)
{
     /*We can put here scanning hor jscripts and html and raw data ...... */
     int allow_transfer;
     av_req_data_t *data = ci_service_data(req);
     if (!data)
          return CI_ERROR;

     if (!data->body) /*No body data? consume all content*/
	 return len;

     if (data->must_scanned == NO_SCAN
#ifdef VIRALATOR_MODE
         || data->must_scanned == VIR_SCAN
#endif
         ) {                    /*if must not scanned then simply write the data and exit..... */
          return ci_simple_file_write(data->body, buf, len, iseof);
     }

     if (data->args.sizelimit
         && ci_simple_file_size(data->body) >= MAX_OBJECT_SIZE) {
         ci_debug_printf(5, "Object bigger than max scanable file. \n");
          data->must_scanned = 0;

          if(data->args.mode == 1){ 
              /*We are in simple mode we can not send early ICAP responses. What?*/
              ci_debug_printf(1, "Object does not fit to max object size and early responses are not allowed! \n");
              return CI_ERROR;
          }
          else { /*Send early response.*/
              ci_req_unlock_data(req);      /*Allow ICAP to send data before receives the EOF....... */
              ci_simple_file_unlock_all(data->body);        /*Unlock all body data to continue send them..... */
          }

     }                          /*else Allow transfer SEND_PERCENT_BYTES of the data */
     else if (data->args.mode != 1 &&   /*not in the simple mode */
              SEND_PERCENT_BYTES
              && START_SEND_AFTER < ci_simple_file_size(data->body)) {
          ci_req_unlock_data(req);
          allow_transfer =
              (SEND_PERCENT_BYTES * (data->body->endpos + len)) / 100;
          ci_simple_file_unlock(data->body, allow_transfer);
     }
     return ci_simple_file_write(data->body, buf, len, iseof);
}



int srvclamav_write_to_net(char *buf, int len, ci_request_t * req)
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

     if (data->virus_name != NULL && data->error_page == 0) {
          /*Inform user. Q:How? Maybe with a mail...... */
          return CI_EOF;        /* Do not send more data if a virus found and data has sent (readpos!=0) */
     }
     /*if a virus found and no data sent, an inform page has already generated */

     if (data->error_page)
          return ci_membuf_read(data->error_page, buf, len);

     if(data->body)
	 bytes = ci_simple_file_read(data->body, buf, len);
     else
	 bytes =0;
     return bytes;
}

int srvclamav_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                 ci_request_t * req)
{
     int ret = CI_OK;
     if (rbuf && rlen) {
          *rlen = srvclamav_read_from_net(rbuf, *rlen, iseof, req);
	  if (*rlen == CI_ERROR)
	       return CI_ERROR;
          else if (*rlen < 0)
	       ret = CI_OK;
     }
     else if (iseof) {
	 if (srvclamav_read_from_net(NULL, 0, iseof, req) == CI_ERROR)
	     return CI_ERROR;
     }

     if (wbuf && wlen) {
          *wlen = srvclamav_write_to_net(wbuf, *wlen, req);
     }
     return CI_OK;
}

int srvclamav_end_of_data_handler(ci_request_t * req)
{
     av_req_data_t *data = ci_service_data(req);
     ci_simple_file_t *body;
     char *http_client_ip;
     unsigned long scanned_data = 0;

     if (!data || !data->body)
          return CI_MOD_DONE;

     body = data->body;
     data->virus_check_done = 1;
     if (data->must_scanned == NO_SCAN) {       /*If exceeds the MAX_OBJECT_SIZE for example ......  */
          ci_simple_file_unlock_all(body);      /*Unlock all data to continue send them . Not really needed here.... */
          return CI_MOD_DONE;
     }


     ci_debug_printf(6, "Scan from file\n");
     lseek(body->fd, 0, SEEK_SET);

     data->virus_name = clamav_scan(body->fd, &scanned_data);

     ci_debug_printf(6,
                     "Clamav engine scanned %lu blocks of  data. Data size: %"
                     PRINTF_OFF_T "...\n", 
		     scanned_data, (CAST_OFF_T) body->endpos);

     if (data->virus_name) { /*A virus found*/
	  http_client_ip = ci_headers_value(req->request_header, "X-Client-IP");
          ci_debug_printf(1, "VIRUS DETECTED: %s , http client ip: %s, http user: %s, http url: %s \n ",
                          data->virus_name,
			  (http_client_ip != NULL? http_client_ip : "-"),
			  (req->user[0] != '\0'? req->user: "-"),
			  data->url_log
	      );
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
          }
#ifdef VIRALATOR_MODE
          else if (data->must_scanned == VIR_SCAN) {
               endof_data_vir_mode(data, req);
          }
#endif /*VIRELATOR_MODE*/
          else
               ci_debug_printf(5, "Simply no other data sent\n");
          return CI_MOD_DONE;
     }

#ifdef VIRALATOR_MODE
     if (data->must_scanned == VIR_SCAN) {
          endof_data_vir_mode(data, req);
     }
     else 
#endif /* VIRELATOR_MODE */
         if (data->allow204 && !ci_req_sent_data(req)) {
             ci_debug_printf(6, "srvClamAv module: Respond with allow 204\n");
             return CI_MOD_ALLOW204;
         }

     ci_simple_file_unlock_all(body);   /*Unlock all data to continue send them..... */
     ci_debug_printf(6,
                     "file unlocked, flags :%d (unlocked:%" PRINTF_OFF_T ")\n",
                     body->flags, (CAST_OFF_T) body->unlocked);
     return CI_MOD_DONE;
}



/*******************************************************************************/
/* Other  functions                                                            */

void set_istag(ci_service_xdata_t * srv_xdata)
{
     char istag[SERVICE_ISTAG_SIZE + 1];
     char str_version[64];
     int cfg_version = 0;
     unsigned int version, level;

     clamav_get_versions(&level, &version, str_version, sizeof(str_version));
     /*cfg_version maybe must set by user when he is changing 
        the srv_clamav configuration.... */
     snprintf(istag, SERVICE_ISTAG_SIZE, "-%.3d-%s-%u%u",
              cfg_version, str_version, level, version);
     istag[SERVICE_ISTAG_SIZE] = '\0';
     ci_service_set_istag(srv_xdata, istag);

     /*Also set the CLAMAV_VERSION*/
     snprintf(CLAMAV_VERSION, CLAMAV_VERSION_SIZE-1, "%s/%d", str_version, version);
     CLAMAV_VERSION[CLAMAV_VERSION_SIZE-1] = '\0';
}

int get_filetype(ci_request_t * req)
{
     int iscompressed, filetype;
      /*Use the ci_magic_req_data_type which caches the result*/
      filetype = ci_magic_req_data_type(req, &iscompressed);


/*     if iscompressed we do not care becouse clamav can understand zipped objects*/

/*     Yes but what about deflate compression as encoding ??????
       I don't know, maybe we can modify web-client requests to not send
       deflate method to Accept-Encoding header  :( .
       Or decompress internally the file and pass to the 
       clamav the decompressed data....
*/
     return filetype;
}

int must_scanned(ci_request_t * req, char *preview_data, int preview_data_len)
{
/* We are assuming that file_type is a valid file type.
   The caller is responsible to pass a valid file_type value
*/
     int type, i;
     int *file_groups;
     int file_type;
     av_req_data_t * data  = ci_service_data(req);;

     /*By default do not scan*/
     type = NO_SCAN;
     /*Going to determine the file type,get_filetype can take preview_data as null ....... */
     file_type = get_filetype(req);
     
     if (preview_data_len == 0 || file_type < 0) {
	 ci_http_request_url(req, data->url_log, LOG_URL_SIZE);
	 ci_debug_printf(1, "WARNING! %s, can not get required info to scan url :%s\n", 
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
             while (file_groups[i] >= 0 && i < MAX_GROUPS) {
                 if ((type = scangroups[file_groups[i]]) > 0)
                     break;
                 i++;
             }
         }

         if (type == NO_SCAN)
             type = scantypes[file_type];
     }

     if (type == NO_SCAN && data->args.forcescan)
          type = SCAN;
     else if (type == VIR_SCAN && data->args.mode == 1) /*in simple mode */
          type = SCAN;
     else if (type == VIR_SCAN && ci_req_type(req) != ICAP_RESPMOD)
          type = SCAN; /*Vir mode will not work in REQMOD requests*/
     else if (type == VIR_SCAN && (VIR_SAVE_DIR == NULL || VIR_HTTP_SERVER == NULL)) {
	  ci_debug_printf(1, "Vir mode requested for this file type but \"VirSaveDir\" or/and \"VirHTTPServer\" is not set!");
 	  type = SCAN;
     }
     
     if (type == SCAN && data->args.sizelimit && MAX_OBJECT_SIZE &&
         data->expected_size > MAX_OBJECT_SIZE) {
         ci_debug_printf(1,
                         "Object size is %" PRINTF_OFF_T " ."
                         " Bigger than max scannable file size (%"
                         PRINTF_OFF_T "). Allow it.... \n", 
                         (CAST_OFF_T) data->expected_size,
                         (CAST_OFF_T) MAX_OBJECT_SIZE);
         type = NO_SCAN;
     }
     
     data->must_scanned = type;
     return type;
}

void generate_error_page(av_req_data_t * data, ci_request_t * req)
{
     ci_membuf_t *error_page;
     char buf[128];

     snprintf(buf, 128, "X-Infection-Found: Type=0; Resolution=2; Threat=%s;",
              data->virus_name);
     buf[127] = '\0';
     ci_icap_add_xheader(req, buf);

     if ( ci_http_response_headers(req))
          ci_http_response_reset_headers(req);
     else
          ci_http_response_create(req, 1, 1);
     ci_http_response_add_header(req, "HTTP/1.0 403 Forbidden");
     ci_http_response_add_header(req, "Server: C-ICAP");
     ci_http_response_add_header(req, "Connection: close");
     ci_http_response_add_header(req, "Content-Type: text/html");
     ci_http_response_add_header(req, "Content-Language: en");

     error_page = ci_txt_template_build_content(req, "srv_clamav", "VIRUS_FOUND",
                           srv_clamav_format_table);
     data->error_page = error_page;
}

/***************************************************************************************/
/* Parse arguments function - 
   Current arguments: allow204=on|off, force=on, sizelimit=off, mode=simple|vir|mixed          
*/
void srvclamav_parse_args(av_req_data_t * data, char *args)
{
     char *str;
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
     }
}

/****************************************************************************************/
/*Commands functions                                                                    */
void dbreload_command(char *name, int type, char **argv)
{
     ci_debug_printf(1, "Clamav virus database reload command received\n");
     if (!clamav_reload_virusdb())
          ci_debug_printf(1, "Clamav virus database reload command failed!\n");
     if (srv_clamav_xdata)
          set_istag(srv_clamav_xdata);
}

/****************************************************************************************/
/*Configuration Functions                                                               */

int cfg_ScanFileTypes(char *directive, char **argv, void *setdata)
{
     int i, id;
     int type = NO_SCAN;
     if (strcmp(directive, "ScanFileTypes") == 0)
          type = SCAN;
     else if (strcmp(directive, "VirScanFileTypes") == 0)
          type = VIR_SCAN;
     else
          return 0;

     for (i = 0; argv[i] != NULL; i++) {
          if ((id = ci_get_data_type_id(magic_db, argv[i])) >= 0)
               scantypes[id] = type;
          else if ((id = ci_get_data_group_id(magic_db, argv[i])) >= 0)
               scangroups[id] = type;
          else
               ci_debug_printf(1, "Unknown data type %s \n", argv[i]);

     }

     ci_debug_printf(2, "I am going to scan data for %s scanning of type:",
                     (type == 1 ? "simple" : "vir_mode"));
     for (i = 0; i < ci_magic_types_num(magic_db); i++) {
          if (scantypes[i] == type)
               ci_debug_printf(2, ",%s", ci_data_type_name(magic_db, i));
     }
     for (i = 0; i < ci_magic_groups_num(magic_db); i++) {
          if (scangroups[i] == type)
               ci_debug_printf(2, ",%s", ci_data_group_name(magic_db, i));
     }
     ci_debug_printf(1, "\n");
     return 1;
}


int cfg_SendPercentBytes(char *directive, char **argv, void *setdata)
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

     SEND_PERCENT_BYTES = val;
     ci_debug_printf(2, "Setting parameter :%s=%d\n", directive, val);
     return val;
}



int cfg_ClamAvTmpDir(char *directive, char **argv, void *setdata)
{
     struct stat stat_buf;
     if (argv == NULL || argv[0] == NULL) {
          ci_debug_printf(1, "Missing arguments in directive:%s\n", directive);
          return 0;
     }
     if (stat(argv[0], &stat_buf) != 0 || !S_ISDIR(stat_buf.st_mode)) {
          ci_debug_printf(1,
                          "The directory %s (%s=%s) does not exist or is not a directory !!!\n",
                          argv[0], directive, argv[0]);
          return 0;
     }

     /*TODO:Try to write to the directory to see if it is writable ........

      */
     CLAMAV_TMP = strdup(argv[0]);
     ci_debug_printf(2, "Setting parameter :%s=%s\n", directive, argv[0]);
     return 1;
}


/**************************************************************/
/* srv_clamav templates  formating table                      */

int fmt_srv_clamav_virusname(ci_request_t *req, char *buf, int len, char *param)
{
    av_req_data_t *data = ci_service_data(req);
    if (! data->virus_name)
        return 0;

    return snprintf(buf, len, "%s", data->virus_name);
}

int fmt_srv_clamav_clamversion(ci_request_t *req, char *buf, int len, char *param)
{
    return snprintf(buf, len, "%s", CLAMAV_VERSION);
}

int fmt_srv_clamav_http_url(ci_request_t *req, char *buf, int len, char *param)
{
    av_req_data_t *data = ci_service_data(req);
    return snprintf(buf, len, "%s", data->url_log);
}

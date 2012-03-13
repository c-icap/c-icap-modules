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
#include "mem.h"
#include "body.h"
#include "simple_api.h"
#include "debug.h"
#include "cfg_param.h"
#include "txtTemplate.h"

#include <clamav.h>
#include <time.h>
#include <errno.h>
#include "srv_clamav.h"
#include "../../common.h"
#include <assert.h>

extern char *VIR_SAVE_DIR;
extern char *VIR_HTTP_SERVER;
extern int VIR_UPDATE_TIME;
extern struct ci_fmt_entry srv_clamav_format_table [];

char *srvclamav_compute_name(ci_request_t * req);
/*char *construct_url(char *strformat, char *filename, char *user);*/


void init_vir_mode_data(ci_request_t * req, av_req_data_t * data)
{
     ci_membuf_t *error_page;
     char buf[512];
     const char *lang;
     ci_http_response_reset_headers(req);
     ci_http_response_add_header(req, "HTTP/1.1 200 OK");
     ci_http_response_add_header(req, "Server: C-ICAP/srvclamav");
     ci_http_response_add_header(req, "Connection: close");
     ci_http_response_add_header(req, "Content-Type: text/html");

     data->last_update = time(NULL);
     data->requested_filename = NULL;
     data->vir_mode_state = VIR_ZERO;


     if ((data->requested_filename = srvclamav_compute_name(req)) != NULL) {
          if (NULL ==
              (data->body =
               ci_simple_file_named_new(VIR_SAVE_DIR,
                                        data->requested_filename, 0)))
	      data->body = ci_simple_file_named_new(VIR_SAVE_DIR, NULL, 0);
     }
     else {
	 data->body = ci_simple_file_named_new(VIR_SAVE_DIR, NULL, 0);
     }


     error_page = ci_txt_template_build_content(req, "srv_clamav", "VIR_MODE_HEAD",
						srv_clamav_format_table);

     lang = ci_membuf_attr_get(error_page, "lang");
     if (lang) {
         snprintf(buf, sizeof(buf), "Content-Language: %s", lang);
         buf[sizeof(buf)-1] = '\0';
         ci_http_response_add_header(req, buf);
     }
     else
         ci_http_response_add_header(req, "Content-Language: en");

     assert( data->error_page==NULL);
     data->error_page = error_page;
     data->vir_mode_state = VIR_HEAD;
     ci_req_unlock_data(req);
}


int send_vir_mode_page(av_req_data_t * data, char *buf, int len,
                       ci_request_t * req)
{
     int ret;
     ci_membuf_t *error_page;

     if (data->vir_mode_state == VIR_END) {
         data->vir_mode_state = VIR_END;
         ci_debug_printf(3, "viralator:EOF already received, nothing to do (why am I called?)\n");
         return CI_EOF;
     }

     if (data->error_page) {
         ret = ci_membuf_read(data->error_page, buf, len);
         if (ret != CI_EOF)
             return ret;
         else {
             ci_membuf_free(data->error_page);
             data->error_page = NULL;
         }
     }
     
     if (data->vir_mode_state == VIR_TAIL) {
         data->vir_mode_state = VIR_END;
	 ci_debug_printf(6, "viralator:EOF received, and vir mode HTML page sent....\n");
	 return CI_EOF;
     }
     else if (data->vir_mode_state == VIR_HEAD) {
       ci_debug_printf(6, "vir mode HTML HEAD data sent ....\n");
       data->vir_mode_state = VIR_MAIN;
     }
     
     /*HERE we should always are in VIR_MAIN state */

     if ((((av_req_data_t *) data)->last_update + VIR_UPDATE_TIME) > time(NULL)) {
          return 0;
     }
     time(&(((av_req_data_t *) data)->last_update));

     ci_debug_printf(6,
                     "Downloaded %" PRINTF_OFF_T " bytes from %" PRINTF_OFF_T
                     " of data<br>",
                     (CAST_OFF_T) ci_simple_file_size(((av_req_data_t *) data)->body),
                     (CAST_OFF_T) ((av_req_data_t *) data)->expected_size);
     
     error_page = ci_txt_template_build_content(req, "srv_clamav", "VIR_MODE_PROGRESS",
						srv_clamav_format_table);
     if (!error_page) {
       ci_debug_printf(1, "Error createging Template file VIR_MODE_PROGRESS!. Stop processing...\n");
       return CI_EOF;
     }

     data->error_page = error_page;
     ret = ci_membuf_read(data->error_page, buf, len);
     return ret;
}




void endof_data_vir_mode(av_req_data_t * data, ci_request_t * req)
{
     ci_membuf_t *error_page;

     if (data->virus_name && data->body) {
	  error_page = ci_txt_template_build_content(req, "srv_clamav", 
						     "VIR_MODE_VIRUS_FOUND",
						     srv_clamav_format_table);
	  data->error_page = error_page;
          data->vir_mode_state = VIR_TAIL;
	  fchmod(data->body->fd, 0);
     }
     else if (data->body) {
	  error_page = ci_txt_template_build_content(req, "srv_clamav", "VIR_MODE_TAIL",
						     srv_clamav_format_table);
	  data->error_page = error_page;
	  data->vir_mode_state = VIR_TAIL;
          fchmod(data->body->fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
     }
}


char *srvclamav_compute_name(ci_request_t * req)
{
     char *abuf;
     const char *str, *filename, *last_delim;
     int namelen;
     if ((filename = ci_http_response_get_header(req, "Location")) != NULL) {
          if ((str = strrchr(filename, '/'))) {
               filename = str + 1;
               if ((str = strrchr(filename, '?')))
                    filename = str + 1;
          }
          if (filename != '\0') {
	      abuf = ci_buffer_alloc(strlen(filename) + 1);
	      strcpy(abuf, filename);
	      return abuf;
	       
          } else
               return NULL;
     }
     /*if we are here we are going to compute name from request headers if exists.... */
     if (!(str = ci_http_request(req)))
          return NULL;

     if (strncmp(str, "GET", 3) != 0)
          return NULL;

     if (!(str = strchr(str, ' ')))
          return NULL;

     str = str + 1;
     filename = str;
     last_delim = NULL;
     while (*str != '\0' && *str != ' ') {
          if (*str == '/' || *str == '?')
               last_delim = str;
          str += 1;
     }
     if (last_delim != NULL)
          filename = last_delim + 1;

     if (filename == str)       /*for example the requested position is http:// */
          return NULL;

     last_delim = str;
     namelen = last_delim - filename;
     if (namelen >= CI_FILENAME_LEN)
          namelen = CI_FILENAME_LEN - 1;

     abuf = ci_buffer_alloc(namelen * sizeof(char) + 1);
     strncpy(abuf, filename, namelen);
     abuf[namelen] = '\0';
     return abuf;
}


/*
char *construct_url(char *strformat, char *filename, char *user)
{
     char *url, *str;
     int i, format_len, filename_len = 0, user_len = 0;
     if (!strformat)
          return NULL;

     format_len = strlen(strformat);
     if (filename)
          filename_len = strlen(filename);
     if (user)
          user_len = strlen(user);

     url = malloc(format_len + filename_len + user_len + 2);
     str = url;

     for (i = 0; i < format_len; i++) {
          if (strformat[i] == '%') {
               switch (strformat[i + 1]) {
               case 'f':
                    if (filename)
                         memcpy(str, filename, filename_len);
                    str += filename_len;
                    i++;
                    break;
               case 'u':
                    if (user)
                         memcpy(str, user, user_len);
                    str += user_len;
                    i++;
                    break;
               default:
                    *str = strformat[i];
                    str += 1;
                    break;
               }
          }
          else {
               *str = strformat[i];
               str += 1;
          }
     }
     *str = '\0';
     return url;
}
*/

int fmt_srv_clamav_filename(ci_request_t *req, char *buf, int len, const char *param)
{
    av_req_data_t *data = ci_service_data(req);

    if (! data->body || ! data->body->filename)
        return 0;
    
    return snprintf(buf, len, "%s", data->body->filename);
}

int fmt_srv_clamav_filename_requested(ci_request_t *req, char *buf, int len, const char *param)
{
    av_req_data_t *data = ci_service_data(req);
    if (! data->requested_filename)
        return 0;
    
    return snprintf(buf, len, "%s", data->requested_filename);
}

int fmt_srv_clamav_expect_size(ci_request_t *req, char *buf, int len, const char *param)
{
    av_req_data_t *data = ci_service_data(req);

    if (data->expected_size == 0)
        return snprintf(buf, len, "-");

    return snprintf(buf, len, "%" PRINTF_OFF_T, (CAST_OFF_T)data->expected_size);
}

extern struct ci_fmt_entry srv_clamav_format_table [];
int fmt_srv_clamav_httpurl(ci_request_t *req, char *buf, int len, const char *param)
{
    char url[1024];
    ci_format_text(req, VIR_HTTP_SERVER , url, 1024, srv_clamav_format_table);
    url[1023] = '\0';
    return snprintf(buf, len, "%s", url);
}

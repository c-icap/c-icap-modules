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


#include "c_icap/c-icap.h"
#include "c_icap/service.h"
#include "c_icap/header.h"
#include "c_icap/mem.h"
#include "c_icap/body.h"
#include "c_icap/simple_api.h"
#include "c_icap/debug.h"
#include "c_icap/cfg_param.h"
#include "c_icap/txtTemplate.h"

#include <time.h>
#include <errno.h>
#include "virus_scan.h"
#include "../../common.h"
#include <assert.h>

extern char *VIR_SAVE_DIR;
extern char *VIR_HTTP_SERVER;
extern int VIR_UPDATE_TIME;
extern struct ci_fmt_entry virus_scan_format_table [];

char *virus_scan_compute_name(ci_request_t * req);
/*char *construct_url(char *strformat, char *filename, char *user);*/

/*Declare the undocumented c-icap library function url_decoder*/
int url_decoder(const char *input,char *output, int output_len);

void init_vir_mode_data(ci_request_t * req, av_req_data_t * data)
{
     ci_membuf_t *error_page;
     char buf[512];
     const char *lang;
     void *temp_file_name;

     /*Initilize the viralator mode*/
     data->last_update = time(NULL);
     data->vir_mode_state = VIR_ZERO;
     /*Try to find out the name of downloaded object.
       The HTTP response headers used, so virus_scan_compute_name should
       called before destroy the HTTP response headers.
      */
     if ((data->requested_filename = virus_scan_compute_name(req)) != NULL) {
          /* data->requested_filename may contain escaped characters, if so we must
             remove them in the file name, but not requested file name.
          */
          temp_file_name = ci_buffer_alloc(strlen(data->requested_filename) + 1);
          if(url_decoder(data->requested_filename, temp_file_name, strlen(data->requested_filename) + 1))
          {
               av_body_data_named(&data->body, VIR_SAVE_DIR, temp_file_name);
               if (data->body.type == AV_BT_NONE)
                    av_body_data_named(&data->body, VIR_SAVE_DIR, NULL);
          }
          else { /* This should NEVER happen */
               av_body_data_named(&data->body, VIR_SAVE_DIR, data->requested_filename);
               if (data->body.type == AV_BT_NONE)
                    av_body_data_named(&data->body, VIR_SAVE_DIR, NULL);
          }
          ci_buffer_free(temp_file_name);
     }
     else {
         av_body_data_named(&data->body, VIR_SAVE_DIR, NULL);
     }

     /*Remove old HTTP response headers and replace with our*/
     ci_http_response_reset_headers(req);
     ci_http_response_add_header(req, "HTTP/1.1 200 OK");
     ci_http_response_add_header(req, "Server: C-ICAP/virus_scan");
     ci_http_response_add_header(req, "Connection: close");
     ci_http_response_add_header(req, "Content-Type: text/html");

     error_page = ci_txt_template_build_content(req, "virus_scan", "VIR_MODE_HEAD",
						virus_scan_format_table);

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
                     (CAST_OFF_T) av_body_data_size(&(((av_req_data_t *) data)->body)),
                     (CAST_OFF_T) ((av_req_data_t *) data)->expected_size);

     error_page = ci_txt_template_build_content(req, "virus_scan", "VIR_MODE_PROGRESS",
						virus_scan_format_table);
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
     if (data->body.type == AV_BT_NONE)
         return;
     assert(data->body.type == AV_BT_FILE);
     if (data->virus_info.virus_found && !data->virus_info.disinfected) {
	  error_page = ci_txt_template_build_content(req, "virus_scan",
						     "VIR_MODE_VIRUS_FOUND",
						     virus_scan_format_table);
	  data->error_page = error_page;
          data->vir_mode_state = VIR_TAIL;
	  fchmod(data->body.store.file->fd, 0);
     }
     else {
	  error_page = ci_txt_template_build_content(req, "virus_scan", "VIR_MODE_TAIL",
						     virus_scan_format_table);
	  data->error_page = error_page;
	  data->vir_mode_state = VIR_TAIL;
          fchmod(data->body.store.file->fd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
     }
}


char *virus_scan_compute_name(ci_request_t * req)
{
     char *abuf;
     const char *str, *filename, *args, *content_disposition;
     int namelen;

     content_disposition = ci_http_response_get_header(req, "Content-Disposition");
     if (content_disposition && (filename = ci_strcasestr(content_disposition, "filename="))) {
          filename = filename + 9;
          if ((str = strrchr(filename, '/'))) {
               filename = str + 1;
          }
          if ((str = strrchr(filename, ';'))) {
               namelen = str - filename;
          }
          else namelen = strlen(filename);
          /* Strip quotes as they can cause problems */
          if (filename[0] == '\"' && filename[namelen - 1] == '\"') {
               filename++;
               namelen -= 2;
          }
          if (filename[0] != '\0') {
               abuf = ci_buffer_alloc((namelen + 1) * sizeof(char));
               strncpy(abuf, filename, namelen);
               abuf[namelen] = '\0';
               return abuf;
          }
          /* If we do not have a valid content-disposition with a filename section, we should fall through and do our best to have a file name */
     }

     /*if we are here we are going to compute name from request headers if exists.... */
     if (!(str = ci_http_request(req)))
          return NULL;

     if (strncmp(str, "GET", 3) != 0)
          return NULL;

     if (!(str = strchr(str, ' ')))
          return NULL;

     while (*str == ' ') str++;
     filename = str;

     if(NULL == (args = strchr(filename, '?')))
          args = strchr(filename, ' ');

     for (str = args; *str != '/' && str != filename; --str);
     if(*str == '/') str++;

     if (filename == str)       /*for example the requested position is http:// */
          return NULL;

     namelen = args - str;
     if (namelen >= CI_FILENAME_LEN)
          namelen = CI_FILENAME_LEN - 1;

     abuf = ci_buffer_alloc((namelen + 1) * sizeof(char));
     strncpy(abuf, str, namelen);
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

int fmt_virus_scan_filename(ci_request_t *req, char *buf, int len, const char *param)
{
    char *filename, *str;
    av_req_data_t *data = ci_service_data(req);

    if (data->body.type == AV_BT_NONE)
         return 0;
    assert(data->body.type == AV_BT_FILE);

    if (! data->body.store.file->filename)
        return 0;

    filename = data->body.store.file->filename;
    if((str = strrchr(filename, '/')) != NULL)
        filename = str + 1;

    return snprintf(buf, len, "%s", filename);
}

int fmt_virus_scan_filename_requested(ci_request_t *req, char *buf, int len, const char *param)
{
    av_req_data_t *data = ci_service_data(req);

    if (! data->requested_filename)
        return 0;

    return snprintf(buf, len, "%s", data->requested_filename);
}

int fmt_virus_scan_expect_size(ci_request_t *req, char *buf, int len, const char *param)
{
    av_req_data_t *data = ci_service_data(req);

    if (data->expected_size == 0)
        return snprintf(buf, len, "-");

    return snprintf(buf, len, "%" PRINTF_OFF_T, (CAST_OFF_T)data->expected_size);
}

extern struct ci_fmt_entry virus_scan_format_table [];
int fmt_virus_scan_httpurl(ci_request_t *req, char *buf, int len, const char *param)
{
    char url[1024];
    ci_format_text(req, VIR_HTTP_SERVER , url, 1024, virus_scan_format_table);
    url[1023] = '\0';
    return snprintf(buf, len, "%s", url);
}

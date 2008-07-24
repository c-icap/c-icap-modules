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
#include "body.h"
#include "simple_api.h"
#include "debug.h"
#include "sguardDB.h"

/*Structs for this module */
enum http_methods { HTTP_UNKNOWN = 0, HTTP_GET, HTTP_POST };

struct http_info {
  int http_major;
  int http_minor;
  int method;
  char site[CI_MAXHOSTNAMELEN + 1];
  char page[1024];              /* I think it is enough, does not 
				   include page arguments */
};

enum lookupdb_types {DB_INTERNAL,DB_SG};

struct lookup_db {
  char *name;
  int type;
  void *db_data;
  void * (*load_db)(struct lookup_db *db, char *path);
  int    (*lookup_db)(void *db_data, struct http_info *http_info);
  void   (*release_db)(void *db_data);
  struct lookup_db *next;
};

struct lookup_db *LOOKUP_DBS = NULL;

int add_lookup_db(struct lookup_db *ldb);
struct lookup_db *new_lookup_db(char *name, int type,
				void *(load_db)(struct lookup_db *ldb, char *path),
				int (lookup_db)(void *db_data, 
						struct http_info *http_info),
				void (release_db)(void *db_data)
				);
/* ALL lookup_db functions*/
int all_lookup_db(void *db_data, struct http_info *http_info);


#define DB_ERROR -1
#define DB_DENY   0
#define DB_ALLOW  1

struct access_db {
  struct lookup_db *db;
  int allow;
  struct access_db *next;
};

struct profile {
  char *name;
  struct access_db *dbs;
  struct profile *next;
};

struct profile *PROFILES = NULL;

int url_check_init_service(ci_service_xdata_t * srv_xdata,
                           struct ci_server_conf *server_conf);
void *url_check_init_request_data(ci_request_t * req);
void url_check_release_data(void *data);
int url_check_process(ci_request_t *);
int url_check_check_preview(char *preview_data, int preview_data_len,
                            ci_request_t *);
int url_check_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                 ci_request_t * req);
//int    url_check_write(char *buf,int len ,int iseof,ci_request_t *req);
//int    url_check_read(char *buf,int len,ci_request_t *req);

/*Profile functions */
struct profile *profile_search(char *name);

/*Config functions*/
int cfg_load_sg_db(char *directive, char **argv, void *setdata);
int cfg_profile(char *directive, char **argv, void *setdata);
/*Configuration Table .....*/
static struct ci_conf_entry conf_variables[] = {
  {"LoadSquidGuardDB", NULL, cfg_load_sg_db, NULL},
  {"Profile", NULL, cfg_profile, NULL},
  {NULL, NULL, NULL, NULL}
};

CI_DECLARE_MOD_DATA ci_service_module_t service = {
     "url_check",
     "Url_Check demo service",
     ICAP_REQMOD,
     url_check_init_service,    /* init_service */
     NULL,                      /*post_init_service */
     NULL,                      /*close_Service */
     url_check_init_request_data,       /* init_request_data */
     url_check_release_data,    /*Release request data */
     url_check_check_preview,
     url_check_process,
     url_check_io,
     conf_variables,
     NULL
};

struct url_check_data {
     ci_cached_file_t *body;
     int denied;
};


int url_check_init_service(ci_service_xdata_t * srv_xdata,
                           struct ci_server_conf *server_conf)
{
     unsigned int xops;
     struct lookup_db *int_db;
     printf("Initialization of url_check module......\n");
     ci_service_set_preview(srv_xdata, 0);
     xops = CI_XCLIENTIP | CI_XSERVERIP;
     xops |= CI_XAUTHENTICATEDUSER | CI_XAUTHENTICATEDGROUPS;
     ci_service_set_xopts(srv_xdata, xops);

     /*Add internal database lookups*/
     int_db = new_lookup_db("ALL", DB_INTERNAL, NULL,
			    all_lookup_db,
			    NULL);
     if(int_db)
       return add_lookup_db(int_db);

     return CI_OK;
}


void *url_check_init_request_data(ci_request_t * req)
{
     struct url_check_data *uc = malloc(sizeof(struct url_check_data));
     uc->body = NULL;
     uc->denied = 0;
     return uc;      /*Get from a pool of pre-allocated structs better...... */
}


void url_check_release_data(void *data)
{
     struct url_check_data *uc = data;
     if (uc->body)
          ci_cached_file_destroy(uc->body);
     free(uc);                  /*Return object to pool..... */
}


int get_http_info(ci_request_t * req, ci_headers_list_t * req_header,
                  struct http_info *httpinf)
{
     char *str;
     int i;

     /*Now get the site name */
     str = ci_headers_value(req_header, "Host");
     if (str) {
          strncpy(httpinf->site, str, CI_MAXHOSTNAMELEN);
          httpinf->site[CI_MAXHOSTNAMELEN] = '\0';
     }
     else
          httpinf->site[0] = '\0';

     str = req_header->headers[0];
     if (str[0] == 'g' || str[0] == 'G')        /*Get request.... */
          httpinf->method = HTTP_GET;
     else if (str[0] == 'p' || str[0] == 'P')   /*post request.... */
          httpinf->method = HTTP_POST;
     else {
          httpinf->method = HTTP_UNKNOWN;
          return 0;
     }
     if ((str = strchr(str, ' ')) == NULL) {    /*The request must have the form:GETPOST page HTTP/X.X */
          return 0;
     }
     while (*str == ' ')
          str++;
     i = 0;
     while (*str != ' ' && *str != '\0' && i < 1022)    /*copy page to the struct. */
          httpinf->page[i++] = *str++;
     httpinf->page[i] = '\0';

     if (*str != ' ') {         /*Where is the protocol info????? */
          return 0;
     }
     while (*str == ' ')
          str++;
     if (*str != 'H' || *(str + 4) != '/') {    /*Not in HTTP/X.X form */
          return 0;
     }
     str += 5;
     httpinf->http_major = strtol(str, &str, 10);
     if (*str != '.') {
          return 0;
     }
     str++;
     httpinf->http_minor = strtol(str, &str, 10);


     return 1;
}

int check_destination(struct http_info *httpinf)
{
  struct profile *profile;
  int ret;
  ci_debug_printf(9, "URL  to host %s\n", httpinf->site);
  ci_debug_printf(9, "URL  page %s\n", httpinf->page);
  
  profile = profile_search("default");
  
  if(!profile) {
    ci_debug_printf(1,"Profile default is not configured! Allow the request...\n");
    return DB_ALLOW;
  }

  if((ret=profile_access(profile, httpinf)) == DB_ERROR) {
    ci_debug_printf(1,"Error searching in profile! Allow the request\n");
    return DB_ALLOW;
  }

  return ret;
}

static char *error_message = "<H1>Permition deny!<H1>";

int url_check_check_preview(char *preview_data, int preview_data_len,
                            ci_request_t * req)
{
     ci_headers_list_t *req_header;
     struct url_check_data *uc = ci_service_data(req);
     struct http_info httpinf;
     int allow = 1;

     if ((req_header = ci_http_request_headers(req)) == NULL) /*It is not possible but who knows ..... */
          return CI_ERROR;

     get_http_info(req, req_header, &httpinf);

     ci_debug_printf(9, "URL  to host %s\n", httpinf.site);
     ci_debug_printf(9, "URL  page %s\n", httpinf.page);

     allow = check_destination(&httpinf);


     if (!allow) {
          /*The URL is not a good one so.... */
          ci_debug_printf(9, "Oh!!! we are going to deny this site.....\n");

          uc->denied = 1;
          uc->body = ci_cached_file_new(strlen(error_message) + 10);
          ci_http_response_create(req, 1, 1); /*Build the responce headers */

          ci_http_response_add_header(req, "HTTP/1.0 403 Forbidden"); /*Send an 403 Forbidden http responce to web client */
          ci_http_response_add_header(req, "Server: C-ICAP");
          ci_http_response_add_header(req, "Content-Type: text/html");
          ci_http_response_add_header(req, "Content-Language: en");
          ci_http_response_add_header(req, "Connection: close");

          ci_cached_file_write(uc->body, error_message, strlen(error_message),
                               1);

     }
     else {
          /*if we are inside preview negotiation or client allow204 responces oudsite of preview then */
          if (preview_data || ci_req_allow204(req))
               return CI_MOD_ALLOW204;

          /*
             icap client does not support preview of data in reqmod requests neither 204 responces outside preview
             so we need to read all the body if exists and send it back to client.
             Allocate a new body for it 
           */
          if (ci_req_hasbody(req)) {
               int clen = ci_http_content_lenght(req) + 100;
               uc->body = ci_cached_file_new(clen);
          }

     }

     unlock_data(req);
     return CI_MOD_CONTINUE;
}


int url_check_process(ci_request_t * req)
{

/*
	  printf("Buffer size=%d, Data size=%d\n ",
		 ((struct membuf *)b)->bufsize,((struct membuf *)b)->endpos);
*/
     return CI_MOD_DONE;
}

int url_check_io(char *wbuf, int *wlen, char *rbuf, int *rlen, int iseof,
                 ci_request_t * req)
{
     int ret;
     struct url_check_data *uc = ci_service_data(req);
     if (!uc->body)
          return CI_ERROR;

     ret = CI_OK;
     if (uc->denied == 0) {
          if (rbuf && rlen) {
               *rlen = ci_cached_file_write(uc->body, rbuf, *rlen, iseof);
               if (*rlen == CI_ERROR)
                    ret = CI_ERROR;
          }
          else if (iseof)
               ci_cached_file_write(uc->body, NULL, 0, iseof);
     }

     if (wbuf && wlen) {
          *wlen = ci_cached_file_read(uc->body, wbuf, *wlen);
          if (*wlen == CI_ERROR)
               ret = CI_ERROR;
     }

     return ret;
}

/******************************************************************/
/* Lookup databases functions                                     */

struct lookup_db *new_lookup_db(char *name,
				int type,
				void *(load_db)(struct lookup_db *,char *path),
				int (lookup_db)(void *db_data, 
						struct http_info *http_info),
				void (release_db)(void *db_data)
				)
{
  struct lookup_db *ldb = malloc(sizeof(struct lookup_db));
  
  if(!ldb)
    return NULL;

  ldb->name = strdup(name);
  ldb->type = type;
  ldb->db_data = NULL;
  ldb->load_db = load_db;
  ldb->lookup_db = lookup_db;
  ldb->release_db = release_db;
  ldb->next = NULL;
  return ldb;
}

int add_lookup_db(struct lookup_db *ldb)
{
  struct lookup_db *tmp_ldb;

  if(!ldb)
    return 0;

  ldb->next=NULL;

  if(LOOKUP_DBS == NULL){
    LOOKUP_DBS=ldb;
    return 1;
  }
  
  tmp_ldb = LOOKUP_DBS;
  while(tmp_ldb->next != NULL) tmp_ldb = tmp_ldb->next;
  
  tmp_ldb->next=ldb;
  return 1;
}

struct lookup_db *search_lookup_db(char *name)
{
  struct lookup_db *tmp_ldb;
  if((tmp_ldb=LOOKUP_DBS) == NULL)
    return NULL;
  
  while((tmp_ldb != NULL) && (strcmp(tmp_ldb->name,name) != 0))
    tmp_ldb=tmp_ldb->next;
  
  return tmp_ldb;
}

void release_lookup_dbs()
{
  struct lookup_db *tmp_ldb;
  
  while((tmp_ldb = LOOKUP_DBS)){
    LOOKUP_DBS=LOOKUP_DBS->next;
    free(tmp_ldb->name);
    if(tmp_ldb->release_db)
      tmp_ldb->release_db(tmp_ldb->db_data);
    free(tmp_ldb);
  }
}

/*****************************************************************/
/* Profile definitions                                           */

struct profile *profile_search(char *name)
{
  struct profile *tmp_profile;
  tmp_profile = PROFILES;
  while(tmp_profile) {
    if(strcmp(tmp_profile->name,name)==0)
      return tmp_profile;
    tmp_profile = tmp_profile->next;
  }
  return NULL;
}

struct profile *profile_check_add(char *name)
{
  struct profile *tmp_profile;
  if((tmp_profile=profile_search(name)))
    return tmp_profile;

  /*Else create a new one and add it to the head of the list*/
  if(!(tmp_profile = malloc(sizeof(struct profile))))
    return NULL;
  tmp_profile->name=strdup(name);
  tmp_profile->dbs=NULL;
  tmp_profile->next=PROFILES;

  ci_debug_printf(1, "srv_url_check: Add profile :%s\n", name);

  return (PROFILES = tmp_profile);
}

struct access_db *profile_add_db(struct profile *prof, struct lookup_db *db, int type)
{
  struct access_db *new_adb,*tmp_adb;
  if(!prof || !db)
    return NULL;
  
  new_adb = malloc(sizeof(struct access_db));
  new_adb->db = db;
  new_adb->allow = type;
  new_adb->next = NULL;
  
  tmp_adb = prof->dbs;
  if (!tmp_adb)
    return (prof->dbs = new_adb);

  while(tmp_adb->next!= NULL) 
    tmp_adb = tmp_adb->next;
  
  tmp_adb->next = new_adb;
  
  return new_adb;
}

int profile_access(struct profile *prof, struct http_info *info)
{
  struct access_db *adb;
  struct lookup_db *db = NULL;
  adb=prof->dbs;
  while (adb) {
    db=adb->db;
    if(!db) {
      ci_debug_printf(1, "Empty access DB in profile %s! is this possible????\n",
		      prof->name);
      return DB_ERROR;
    }

    if(!db->lookup_db) {
      ci_debug_printf(1, "The db %s in profile %s has not an lookup_db method implemented!\n",
		      db->name,
		      prof->name);
      return DB_ERROR;
    }

    if(db->lookup_db(db->db_data, info))
      return adb->allow;
    adb=adb->next;
  }
  return DB_ALLOW;
}

int cfg_profile(char *directive, char **argv, void *setdata)
{
  int i,type=0;
  struct profile *prof;
  struct lookup_db *db;

  if(!argv[0] || !argv[1] || !argv[2])
    return 0;
  
  prof=profile_check_add(argv[0]);

  if(strcasecmp(argv[1],"allow")==0)
    type = DB_ALLOW;
  else if(strcasecmp(argv[1],"deny")==0)
    type = DB_DENY;
  else {
    ci_debug_printf(1, "srv_url_check: Configuration error, expecting allow/deny got %s\n", argv[1]);
    return 0;
  }

  ci_debug_printf(1, "srv_url_check: Add dbs to profile %s: ", argv[0]);

  for(i=2; argv[i] != NULL; i++) {
    db=search_lookup_db(argv[i]);
    if(!db) {
      ci_debug_printf(1,"srv_url_check: WARNING the lookup db %s does not exists!\n", argv[i]);
    }
    else {
      ci_debug_printf(1,"%s ",argv[i]);
      profile_add_db(prof, db, type);
    }
  }
  ci_debug_printf(1,"\n");
  return 1;
}


/*****************************************************************/
/* SguidGuard Databases                                          */


void *sg_load_db(struct lookup_db *db, char *path)
{
  sg_db_t *sg_db;
  sg_db = sg_init_db(path);
  return (db->db_data = (void *)sg_db);
}

int sg_lookup_db(void *db_data, struct http_info *http_info)
{
  char url[1024];
  sg_db_t *sg_db = (sg_db_t *)db_data;
  if( sg_domain_exists(sg_db, http_info->site) )
    return 1;

  snprintf(url,1023,"%s%s",http_info->site,http_info->page);
  return sg_url_exists(sg_db,url);
}

void sg_release_db(void *db_data)
{
  sg_db_t *sg_db = (sg_db_t *)db_data;
  sg_close_db(sg_db);
  free(sg_db);
}


int cfg_load_sg_db(char *directive, char **argv, void *setdata) 
{
  struct lookup_db *ldb;

  if (argv == NULL || argv[0] == NULL || argv[1] == NULL) {
    ci_debug_printf(1, "Missing arguments in directive:%s\n", directive);
    return 0;
  }


  ldb = new_lookup_db(argv[0], DB_SG, 
		      sg_load_db,
		      sg_lookup_db,
		      sg_release_db);
  if(ldb) {
    if(!ldb->load_db(ldb, argv[1])) {
      free(ldb);
      return 0;
    }
    return add_lookup_db(ldb);
  }
  
  return 0;
}

/**********************************************************************/
/* Other */
int all_lookup_db(void *db_data, struct http_info *http_info)
{
  return 1;
}

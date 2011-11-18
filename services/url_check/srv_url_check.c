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
#include "lookup_table.h"
#include "debug.h"
#include "access.h"
#include "acl.h"
#include "../../common.h"
#include "commands.h"
#if defined(HAVE_BDB)
#include "sguardDB.h"
#endif

/*Structs for this module */
enum http_methods { HTTP_UNKNOWN = 0, HTTP_GET, HTTP_POST };

#define CHECK_HOST     0x01
#define CHECK_URL      0x02
#define CHECK_FULL_URL 0x04
#define CHECK_DOMAIN   0x08
#define CHECK_SRV_IP   0x10
#define CHECK_SRV_NET  0x20

#define MAX_URL_SIZE  65536
#define MAX_PAGE_SIZE (MAX_URL_SIZE - CI_MAXHOSTNAMELEN)

const char *protos[] = {"", "http", "https", "ftp", NULL};
enum proto {UNKNOWN=0, HTTP, HTTPS, FTP};

struct http_info {
    int http_major;
    int http_minor;
    int method;
    unsigned int port;
    int proto;
    char host[CI_MAXHOSTNAMELEN + 1];
    char server_ip[64];                   /*I think ipv6 address needs about 32 bytes*/
    char site[CI_MAXHOSTNAMELEN + 1];
    char url[MAX_URL_SIZE];              /* I think it is enough */
    char *args;
};

enum lookupdb_types {DB_INTERNAL, DB_SG, DB_LOOKUP};

struct lookup_db {
  char *name;
  int type;
  unsigned int check;
  void *db_data;
  void * (*load_db)(struct lookup_db *db, char *path);
  int    (*lookup_db)(struct lookup_db *db, struct http_info *http_info);
  void   (*release_db)(struct lookup_db *db);
  struct lookup_db *next;
};

struct lookup_db *LOOKUP_DBS = NULL;

int add_lookup_db(struct lookup_db *ldb);
struct lookup_db *new_lookup_db(char *name, int type,
				unsigned int check,
				void *(*load_db)(struct lookup_db *ldb, char *path),
				int (*lookup_db)(struct lookup_db *ldb,
						struct http_info *http_info),
				void (*release_db)(struct lookup_db *ldb)
				);
/* ALL lookup_db functions*/
int all_lookup_db(struct lookup_db *ldb, struct http_info *http_info);
void release_lookup_dbs();

#define DB_ERROR -1
#define DB_BLOCK  0
#define DB_PASS   1

struct access_db {
  struct lookup_db *db;
  int pass;
  struct access_db *next;
};

struct profile {
  char *name;
  ci_access_entry_t *access_list;
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
void url_check_close_service();
//int    url_check_write(char *buf,int len ,int iseof,ci_request_t *req);
//int    url_check_read(char *buf,int len,ci_request_t *req);

/*Profile functions */
struct profile *profile_search(char *name);
struct profile *profile_select(ci_request_t *req);

/*Config functions*/
int cfg_load_sg_db(char *directive, char **argv, void *setdata);
int cfg_load_lt_db(char *directive, char **argv, void *setdata);
int cfg_profile(char *directive, char **argv, void *setdata);
int cfg_profile_access(char *directive, char **argv, void *setdata);
/*Configuration Table .....*/
static struct ci_conf_entry conf_variables[] = {
#if defined(HAVE_BDB)
  {"LoadSquidGuardDB", NULL, cfg_load_sg_db, NULL},
#endif
  {"LookupTableDB", NULL, cfg_load_lt_db, NULL},
  {"Profile", NULL, cfg_profile, NULL},
  {"ProfileAccess", NULL, cfg_profile_access, NULL},
  {NULL, NULL, NULL, NULL}
};

CI_DECLARE_MOD_DATA ci_service_module_t service = {
     "url_check",
     "Url_Check demo service",
     ICAP_REQMOD,
     url_check_init_service,    /* init_service */
     NULL,                      /*post_init_service */
     url_check_close_service,                      /*close_Service */
     url_check_init_request_data,       /* init_request_data */
     url_check_release_data,    /*Release request data */
     url_check_check_preview,
     url_check_process,
     url_check_io,
     conf_variables,
     NULL
};

int URL_CHECK_DATA_POOL = -1;
struct url_check_data {
     ci_cached_file_t *body;
     int denied;
};


int url_check_init_service(ci_service_xdata_t * srv_xdata,
                           struct ci_server_conf *server_conf)
{
     unsigned int xops;
     struct lookup_db *int_db;
     ci_debug_printf(2, "Initialization of url_check module......\n");
     ci_service_set_preview(srv_xdata, 0);
     xops = CI_XCLIENTIP | CI_XSERVERIP;
     xops |= CI_XAUTHENTICATEDUSER | CI_XAUTHENTICATEDGROUPS;
     ci_service_set_xopts(srv_xdata, xops);

     /*initialize mempools          */
     URL_CHECK_DATA_POOL = ci_object_pool_register("url_check_data", 
						   sizeof(struct url_check_data));

     if (URL_CHECK_DATA_POOL < 0)
	 return CI_ERROR;
     /*Add internal database lookups*/
     int_db = new_lookup_db("ALL", DB_INTERNAL, CHECK_HOST, NULL,
			    all_lookup_db,
			    NULL);
     if(int_db)
       return add_lookup_db(int_db);

     return CI_OK;
}

void url_check_close_service()
{
    ci_object_pool_unregister(URL_CHECK_DATA_POOL);
    release_lookup_dbs();
}


void *url_check_init_request_data(ci_request_t * req)
{
     struct url_check_data *uc = ci_object_pool_alloc(URL_CHECK_DATA_POOL);
     uc->body = NULL;
     uc->denied = 0;
     return uc;      /*Get from a pool of pre-allocated structs better...... */
}


void url_check_release_data(void *data)
{
     struct url_check_data *uc = data;
     if (uc->body)
          ci_cached_file_destroy(uc->body);
     ci_object_pool_free(uc);    /*Return object to pool..... */
}

int get_protocol(const char *str,int size) 
{
    int i;
    for(i=0; protos[i]!=NULL; i++) {
	if(strncmp(str,protos[i],size)==0)
	    return i;
    }
    return 0;
}

/*Macro to convert a char hex digit to numeric*/
#define ctox(h) (h >= 'A'? (toupper(h) - 'A' + 10) : toupper(h) - '0')

int get_http_info(ci_request_t * req, ci_headers_list_t * req_header,
                  struct http_info *httpinf)
{
     const char *str;
     char *tmp, c;
     int i, proxy_mode=0;

     /*Initialize htto_info struct*/
     httpinf->url[0]='\0';
     httpinf->args = NULL;
     httpinf->site[0] = '\0';
     httpinf->host[0] = '\0';
     httpinf->server_ip[0] = '\0';
     httpinf->method = HTTP_UNKNOWN;
     httpinf->port = 0;
     httpinf->proto = UNKNOWN;
     httpinf->http_major = -1;
     httpinf->http_minor = -1;

     /*Now get the site name */
     str = ci_headers_value(req_header, "Host");
     if (str) {
          tmp = httpinf->host;
          for (tmp = httpinf->host; *str != '\0' && (tmp - httpinf->host) < CI_MAXHOSTNAMELEN; tmp++,str++)
               *tmp = tolower(*str);
          httpinf->host[CI_MAXHOSTNAMELEN] = '\0';
     }

     /*
       When x-server-ip implemented in c-icap (and squid3)
       strcpy(http->inf,req->xserverip);
       else do a getipbyname
     */
     
     str = req_header->headers[0];
     if (str[0] == 'g' || str[0] == 'G')        /*Get request.... */
	 httpinf->method = HTTP_GET;
     else if (str[0] == 'p' || str[0] == 'P')   /*post request.... */
	 httpinf->method = HTTP_POST;
     /*else unknown*/

     if ((str = strchr(str, ' ')) == NULL) {    /*The request must have the form:GETPOST page HTTP/X.X */
          return 0;
     }
     while (*str == ' ')
          str++;


     /*here we are at the beggining of the URL. If we are in a reqmod request the
       URL propably has the form http://site[:port]/page or just /page 
       (where, in squid transparent mode?)
      */
     /*check if we are in the form proto://url
      */
     if ((tmp=strstr(str,"://"))) {	 
	 proxy_mode=1;
	 httpinf->proto = get_protocol(str,str-tmp);
	 str = tmp+3;
	 i=0;
	 while(*str != ':' && *str != '/'  && *str != ' ' && *str != '\0' && i < CI_MAXHOSTNAMELEN){
	     httpinf->site[i] = tolower(*str); /*Is it possible to give us hostname with uppercase letters?*/
	     httpinf->url[i] = httpinf->site[i];
	     i++;
	     str++;
	 }
	 httpinf->site[i] = '\0';
	 httpinf->url[i] = '\0';
	 if(*str==':'){
	     httpinf->port = strtol(str+1,&tmp,10);
	     if(!tmp || *tmp!='/') 
		 return 0;
	     /*Do we want the port contained into URL? if no:*/
	     /*str = tmp;*/
	 }
     }
     else {
	 strcpy(httpinf->url, httpinf->host);
	 strcpy(httpinf->site, httpinf->host);
	 httpinf->port = 80;
     }

     i = strlen(httpinf->url);
     while (*str != ' ' && *str != '\0' && i < MAX_PAGE_SIZE) {  /*copy page to the struct. */
         if (*str == '?' && ! httpinf->args) {
             httpinf->url[i++] = *str++;
             httpinf->args = &(httpinf->url[i]);             
         } else  if (*str == '%' && 
                     isxdigit(*(str+1)) && 
                     /* only printable ascii,  0x20 <= ascii  <= 0x7e :*/
                     *(str+1) <= '7' && *(str+1) >= '2' &&
                     isxdigit(*(str+2)) ) {
             
             c  = 16 * ctox(*(str+1)) + ctox(*(str+2));
             /*if it is not space, '+', '%' and it is not 7f=127*/
             if (strchr(" +%?", c) == NULL && c < 127) {
                 httpinf->url[i++] = c;
                 str += 3;
             }
             else
                 httpinf->url[i++] = *str++;
         }
         else //TODO: maybe convert to %xx any non asciii char
             httpinf->url[i++] = *str++;
     }

     httpinf->url[i] = '\0';

     if (*str != ' ') {         /*Where is the protocol info????? */
          return 0;
     }
     while (*str == ' ')
          str++;
     if (*str != 'H' || *(str + 4) != '/') {    /*Not in HTTP/X.X form */
          return 0;
     }
     str += 5;
     httpinf->http_major = strtol(str, &tmp, 10);
     if (!tmp || *tmp != '.') {
          return 0;
     }
     str = tmp + 1;
     httpinf->http_minor = strtol(str, NULL, 10);

     return 1;
}

int profile_access(struct profile *prof, struct http_info *info);

static char *error_message = "<H1>Access denied!<H1>";

int url_check_check_preview(char *preview_data, int preview_data_len,
                            ci_request_t * req)
{
     ci_headers_list_t *req_header;
     struct url_check_data *uc = ci_service_data(req);
     struct http_info httpinf;
     struct profile *profile;
     int pass = DB_PASS;

     if ((req_header = ci_http_request_headers(req)) == NULL) /*It is not possible but who knows ..... */
          return CI_ERROR;

     if (!get_http_info(req, req_header, &httpinf)) /*Unknown method or something else...*/
	 return CI_MOD_ALLOW204;

     ci_debug_printf(9, "URL  to host %s\n", httpinf.site);
     ci_debug_printf(9, "URL  page %s\n", httpinf.url);

     profile = profile_select(req);

     if (!profile) {
          ci_debug_printf(1, "No Profile configured! Allowing the request...\n");
	  return CI_MOD_ALLOW204;
     }

     if ((pass=profile_access(profile, &httpinf)) == DB_ERROR) {
          ci_debug_printf(1,"Error searching in profile! Allow the request\n");
	  return CI_MOD_ALLOW204;;
     }


     if (pass == DB_BLOCK) {
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
               int clen = ci_http_content_length(req) + 100;
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
				unsigned int check,
				void *(*load_db)(struct lookup_db *,char *path),
				int (*lookup_db)(struct lookup_db *ldb, 
						struct http_info *http_info),
				void (*release_db)(struct lookup_db *ldb)
				)
{
  struct lookup_db *ldb = malloc(sizeof(struct lookup_db));
  
  if(!ldb)
    return NULL;

  ldb->name = strdup(name);
  ldb->type = type;
  ldb->check = check;
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
      tmp_ldb->release_db(tmp_ldb);
    free(tmp_ldb);
  }
}

/*****************************************************************/
/* Profile definitions                                           */

struct profile *profile_select(ci_request_t *req)
{
  struct profile *tmp_profile, *default_profile;
  default_profile = NULL;
  tmp_profile = PROFILES;
  while(tmp_profile) {

    if (tmp_profile->access_list &&
	(ci_access_entry_match_request(tmp_profile->access_list, 
				       req) == CI_ACCESS_ALLOW)) {
        return tmp_profile;
    }
    
    if (strcmp(tmp_profile->name,"default")==0)
        default_profile = tmp_profile;

    tmp_profile = tmp_profile->next;
  }
  return default_profile;
}

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
  tmp_profile->name = strdup(name);
  tmp_profile->access_list = NULL;
  tmp_profile->dbs = NULL;
  tmp_profile->next = PROFILES;

  ci_debug_printf(2, "srv_url_check: Add profile :%s\n", name);

  return (PROFILES = tmp_profile);
}

struct access_db *profile_add_db(struct profile *prof, struct lookup_db *db, int type)
{
  struct access_db *new_adb,*tmp_adb;
  if(!prof || !db)
    return NULL;
  
  new_adb = malloc(sizeof(struct access_db));
  new_adb->db = db;
  new_adb->pass = type;
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
    ci_debug_printf(5, "Going to check the db %s for %s \n", db->name, (adb->pass==0?"PASS":"BLOCK"));

    if (db->lookup_db(db, info)) {
	ci_debug_printf(5, "The db :%s matches! \n", db->name);
	return adb->pass;
    }
    adb=adb->next;
  }
  return DB_PASS;
}

int cfg_profile(char *directive, char **argv, void *setdata)
{
  int i,type=0;
  struct profile *prof;
  struct lookup_db *db;

  if(!argv[0] || !argv[1] || !argv[2])
    return 0;
  
  prof=profile_check_add(argv[0]);

  if(strcasecmp(argv[1],"pass")==0)
    type = DB_PASS;
  else if(strcasecmp(argv[1],"block")==0)
    type = DB_BLOCK;
  else {
    ci_debug_printf(1, "srv_url_check: Configuration error, expecting pass/block got %s\n", argv[1]);
    return 0;
  }

  ci_debug_printf(2, "srv_url_check: Add dbs to profile %s: ", argv[0]);

  for(i=2; argv[i] != NULL; i++) {
    db=search_lookup_db(argv[i]);
    if(!db) {
      ci_debug_printf(1,"srv_url_check: WARNING the lookup db %s does not exists!\n", argv[i]);
    }
    else {
      ci_debug_printf(2,"%s ",argv[i]);
      profile_add_db(prof, db, type);
    }
  }
  ci_debug_printf(2,"\n");
  return 1;
}

int cfg_profile_access(char *directive, char **argv, void *setdata)
{
   struct profile *prof;
   ci_access_entry_t *access_entry;
   int argc, error;
   char *acl_spec_name;

   if(!argv[0] || !argv[1])
    return 0;

   if (!(prof = profile_search(argv[0]))) {
       ci_debug_printf(1, "Error: Unknown profile %s!", argv[0]);
       return 0;
   }
    
   if ((access_entry = ci_access_entry_new(&(prof->access_list), 
					   CI_ACCESS_ALLOW))  == NULL) {
         ci_debug_printf(1, "Error creating access list for cfg profiles!\n");
         return 0;
     }
   
   error = 0;
   for (argc = 1; argv[argc]!= NULL; argc++) {
       acl_spec_name = argv[argc];
          /*TODO: check return type.....*/
          if (!ci_access_entry_add_acl_by_name(access_entry, acl_spec_name)) {
	      ci_debug_printf(1,"Error adding acl spec: %s in profile %s."
			        " Probably does not exist!\n", 
			      acl_spec_name, prof->name);
              error = 1;
          }
          else
	    ci_debug_printf(2,"\tAdding acl spec: %s in profile %s\n", acl_spec_name, prof->name);
     }

     if (error)
         return 0;

     return 1;
}

/*****************************************************************/
/* SguidGuard Databases                                          */

#if defined(HAVE_BDB)
void *sg_load_db(struct lookup_db *db, char *path)
{
  sg_db_t *sg_db;
  sg_db = sg_init_db(path);
  return (db->db_data = (void *)sg_db);
}

int sg_lookup_db(struct lookup_db *ldb, struct http_info *http_info)
{
  sg_db_t *sg_db = (sg_db_t *)ldb->db_data;
  if (!sg_db) {
       ci_debug_printf(1, "sg_db %s is not open? \n", ldb->name);
       return 0;
  }
  ci_debug_printf(5, "sg_db: checking domain %s \n", http_info->site);
  if( sg_domain_exists(sg_db, http_info->site) )
    return 1;

  ci_debug_printf(5, "sg_db: checking url %s \n", http_info->url);
  return sg_url_exists(sg_db,http_info->url);
}

void sg_release_db(struct lookup_db *ldb)
{
  sg_db_t *sg_db = (sg_db_t *)ldb->db_data;
  if (!sg_db) {
       ci_debug_printf(9, "sg_release_db: sg_db is not open? \n");
       return;
  }
  sg_close_db(sg_db);
  ldb->db_data = NULL;
}

struct command_sg_db_data {
   char path[CI_MAX_PATH];
   struct lookup_db *ldb;
};

void command_open_sg_db(char *name, int type, void *data)
{
  struct command_sg_db_data *sg_data;
  struct lookup_db *ldb;
  sg_db_t *sg_db;
  sg_data = (struct command_sg_db_data *)data;
  ldb = (struct lookup_db *)sg_data->ldb;
  sg_db = sg_init_db(sg_data->path);
  ldb->db_data = (void *)sg_db;

  free(sg_data);
}


int cfg_load_sg_db(char *directive, char **argv, void *setdata) 
{
  struct lookup_db *ldb;
  struct command_sg_db_data *db_data;

  if (argv == NULL || argv[0] == NULL || argv[1] == NULL) {
    ci_debug_printf(1, "Missing arguments in directive:%s\n", directive);
    return 0;
  }

  ldb = new_lookup_db(argv[0], 
		      DB_SG, 
		      CHECK_HOST|CHECK_URL,
		      sg_load_db,
		      sg_lookup_db,
		      sg_release_db);


  if(ldb) {
    db_data = malloc(sizeof(struct command_sg_db_data));
    if (!db_data)
      return 0;
    strncpy(db_data->path, argv[1], CI_MAX_PATH);
    db_data->path[CI_MAX_PATH-1] = '\0';
    db_data->ldb = ldb;
    register_command_extend("open_sg_db", CHILD_START_CMD, db_data,
			    command_open_sg_db);
    return add_lookup_db(ldb);
  }
  
  return 0;
}
#endif

/*****************************************************************/
/* c-icap lookup table databases                                 */


void *lt_load_db(struct lookup_db *db, char *path)
{
  struct ci_lookup_table *lt_db;
  lt_db = ci_lookup_table_create(path);
  if(lt_db && !lt_db->open(lt_db)) {
    ci_lookup_table_destroy(lt_db);
    lt_db = NULL;
  }
  return (db->db_data = (void *)lt_db);
}

char *find_last(char *s,char *e,const char accept)
{
  char *p;
  p = e;
  while(p >= s) {
      if(accept == *p)
	  return p;
      p--;
  }
  return NULL;
}

int lt_lookup_db(struct lookup_db *ldb, struct http_info *http_info)
{
  void **vals=NULL;
  void *ret = NULL;
  char *s, *snext, *e, *end, store;
  int len, full_url =0;
  struct ci_lookup_table *lt_db = (struct ci_lookup_table *)ldb->db_data;
  switch(ldb->check) {
  case CHECK_HOST:
      ret = lt_db->search(lt_db, http_info->site, &vals);
      break;
  case CHECK_DOMAIN:
      s = http_info->site;
      s--;   /* :-) */
      do {
	  s++;
	  ci_debug_printf(5, "Checking  domain %s ....\n", s);
	  ret = lt_db->search(lt_db, s, &vals);
	  lt_db->release_result(lt_db, vals);
      } while (!ret && (s=strchr(s, '.')));
      break;
  case CHECK_FULL_URL:
      full_url = 1;
  case CHECK_URL:
      /*for www.site.com/to/path/page.html need to test:

	www.site.com/to/path/page.html
	www.site.com/to/path/
	www.site.com/to/
	www.site.com/

	site.com/to/path/page.html
	site.com/to/path/
	site.com/to/
	site.com/

	com/to/path/page.html
	com/to/path/
	com/to/
	com/
       */
      s = http_info->url;
      if (!full_url && http_info->args)
	  end = http_info->args;
      else {
	  len = strlen(http_info->url);
	  end = s+len;
      }
      s--;
      do {
	  s++;
	  e = end; /*Point to the end of string*/
	  snext = strpbrk(s, "./");
	  if(!snext || *snext == '/') /*Do not search the top level domains*/
	      break;
	  do {
	      store = *e;
	      *e = '\0'; /*cut the string exactly here (the http_info->url must not change!) */
	      ci_debug_printf(9,"Going to check url: %s\n", s);
	      ret = lt_db->search(lt_db, s, &vals);
	      lt_db->release_result(lt_db, vals);
	      *e = store; /*... and restore string to its previous state :-), 
			    the http_info->url must not change */
	      if (full_url && e > http_info->args)
		  e = http_info->args;
	      else
		  e = find_last(s, e-1, '/' );
	  } while(!ret && e);
      } while (!ret && (s = snext));
      

      break;
  case CHECK_SRV_IP:
      break;
  case CHECK_SRV_NET:
      break;
  default:
      /*nothing*/
      break;
  }
  if(vals)
    lt_db->release_result(lt_db,vals);
  return (ret != NULL);
}

void lt_release_db(struct lookup_db *ldb)
{
  struct ci_lookup_table *lt_db = (struct ci_lookup_table *)ldb->db_data;
  ci_debug_printf(5, "Destroy lookup table %s\n", lt_db->path);
  ci_lookup_table_destroy(lt_db);
  ldb->db_data = NULL;
}


int cfg_load_lt_db(char *directive, char **argv, void *setdata) 
{
  struct lookup_db *ldb;
  unsigned int check;
  if (argv == NULL || argv[0] == NULL || argv[1] == NULL || argv[2] == NULL) {
    ci_debug_printf(1, "Missing arguments in directive:%s\n", directive);
    return 0;
  }

  if(strcmp(argv[1],"host")==0)
    check = CHECK_HOST;
  else if(strcmp(argv[1],"url")==0)
    check = CHECK_URL;
  else if(strcmp(argv[1],"full_url")==0)
      check = CHECK_FULL_URL;
  else if(strcmp(argv[1],"domain")==0)
    check = CHECK_DOMAIN;
  /* Not yet implemented
  else if(strcmp(argv[1],"server_ip")==0)
      check = CHECK_SRV_IP;
  else if(strcmp(argv[1],"server_net")==0)
      check = CHECK_SRV_NET;
  */
  else {
    ci_debug_printf(1, "Wrong argument %s for directive %s\n", 
		    argv[1], directive);
    return 0;
  }
  
  ldb = new_lookup_db(argv[0],
		      DB_LOOKUP, 
		      check,
		      lt_load_db,
		      lt_lookup_db,
		      lt_release_db);
  if(ldb) {
    if(!ldb->load_db(ldb, argv[2])) {
      free(ldb);
      return 0;
    }
    return add_lookup_db(ldb);
  }
  
  return 0;
}

/**********************************************************************/
/* Other */
int all_lookup_db(struct lookup_db *ldb, struct http_info *http_info)
{
  return 1;
}

#ifndef __SRV_CLAMAV_H
#define __SRV_CLAMAV_H

#include "body.h"
#include "request.h"
#include "acl.h"
#include "common.h"

#define VIRALATOR_MODE

#define LOG_URL_SIZE 256
struct av_file_types;
#ifdef USE_VSCAN_PROFILES
struct av_req_profile;
#endif

typedef struct av_virus_info {
    char *virus_name;
    int virus_found;
} av_virus_info_t;

typedef struct av_req_data{
     ci_simple_file_t *body;
     ci_request_t *req;
     int must_scanned ;
     int allow204;
     int virus_check_done;
     av_virus_info_t virus_info;
     ci_membuf_t *error_page;
     char url_log[LOG_URL_SIZE];
#ifdef USE_VSCAN_PROFILES
    const struct av_req_profile *profile;
#endif
#ifdef VIRALATOR_MODE
     time_t last_update;
     char *requested_filename;
     int vir_mode_state;
#endif
     ci_off_t expected_size;
     struct{
	  int enable204;
	  int forcescan;
	  int sizelimit;
	  int mode;
     } args;
     ci_off_t max_object_size;
     int send_percent_bytes;
     ci_off_t start_send_after;
}av_req_data_t;

struct av_file_types {
    int *scantypes;
    int *scangroups;
};

struct av_req_profile {
    char *name;
    int disable_scan;
    int send_percent_data;
    ci_off_t start_send_after; 
    ci_off_t max_object_size;
    struct av_file_types scan_file_types;
    ci_access_entry_t *access_list;
    struct av_req_profile *next;
};

enum {NO_SCAN=0,SCAN,VIR_SCAN};

#ifdef VIRALATOR_MODE

enum {VIR_ZERO, VIR_HEAD, VIR_MAIN, VIR_TAIL, VIR_END};

void init_vir_mode_data(ci_request_t *req,av_req_data_t *data);
int send_vir_mode_page(av_req_data_t *data,char *buf,int len,ci_request_t *req);
void endof_data_vir_mode(av_req_data_t *data,ci_request_t *req);
#endif

/*File types related functions*/
int av_file_types_init( struct av_file_types *ftypes);
void av_file_types_destroy( struct av_file_types *ftypes);

#ifdef USE_VSCAN_PROFILES
/*profiles related functions */
void av_req_profile_init_profiles();
void av_req_profile_release_profiles();
struct av_req_profile *av_req_profile_select(ci_request_t *req);
#endif

/*Clamav support functions*/
int clamav_init();
int clamav_scan(int fd,  av_virus_info_t *vinfo);
int clamav_get_versions(unsigned int *level, unsigned int *version, char *str, size_t len);
int clamav_init_virusdb();
int clamav_reload_virusdb();
void clamav_destroy_virusdb();


#endif

#ifndef __SRV_VIRUS_SCAN_H
#define __SRV_VIRUS_SCAN_H

#include "c_icap/body.h"
#include "c_icap/request.h"
#include "c_icap/acl.h"
#include "c_icap/array.h"
#include "c_icap/registry.h"
#include "common.h"
#include "av_body.h"

#define VIRALATOR_MODE

#define LOG_URL_SIZE 256
struct av_file_types;
#ifdef USE_VSCAN_PROFILES
struct av_req_profile;
#endif

#define AV_ENGINES_REGISTRY "virus_scan::engines"
#define AV_RELOAD_ISTAG     "virus_scan::reloadistag"

#define AV_NAME_SIZE 64
enum av_actions {AV_NONE = 0, AV_CLEAN, AV_FILE_REMOVED};

typedef struct av_virus_info {
    char virus_name[AV_NAME_SIZE];
    int virus_found;
    int disinfected;
    ci_vector_t *viruses;
} av_virus_info_t;

typedef struct av_virus {
    char virus[AV_NAME_SIZE];
    char type[AV_NAME_SIZE];
    int problemID;
    int action;
} av_virus_t;

#define AV_OPT_MEM_SCAN 0x01
#define AV_OPT_CLEAN    0x02

typedef struct av_engine {
    const char *name;
    uint64_t  options;
    int (*scan_membuf)(ci_membuf_t *body, av_virus_info_t *vinfo);
    int (*scan_simple_file)(ci_simple_file_t *body, av_virus_info_t *vinfo);
    const char *(*signature)();
    const char *(*version_str)();
} av_engine_t;

#define AV_MAX_ENGINES 64
typedef struct av_req_data{
    struct av_body_data body;
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
     int encoded;
     const av_engine_t *engine[AV_MAX_ENGINES];
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
    const av_engine_t *engines[AV_MAX_ENGINES];
    ci_access_entry_t *access_list;
    struct av_req_profile *next;
};

enum {NO_DECISION = -1, NO_SCAN=0,SCAN,VIR_SCAN};

#define av_register_engine(engine) ci_registry_add_item(AV_ENGINES_REGISTRY, (engine)->name, engine)
#define av_reload_istag() ci_command_schedule_on(AV_RELOAD_ISTAG, NULL, 0)

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

/*Decoding functions*/
int virus_scan_inflate(int fin, ci_simple_file_t *fout, ci_off_t max_size);
int virus_scan_inflate_mem(void *mem, size_t mem_size, ci_simple_file_t *fout, ci_off_t max_size);
const char *virus_scan_inflate_error(int err);
#endif

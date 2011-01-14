#include "c-icap.h"
#include "simple_api.h"
#include "body.h"
#include "srv_clamav.h"
#include "filetype.h"
#include "acl.h"
#include "access.h"
#include "cfg_param.h"
#include "debug.h"
#include "../../common.h"

static struct av_req_profile *PROFILES;

void av_req_profile_init_profiles() {
    PROFILES = NULL;
}

static void av_req_profile_destroy(struct av_req_profile *prof);
void av_req_profile_release_profiles() {
    struct av_req_profile *aprof;
    while ((aprof=PROFILES) != NULL) {
        PROFILES=PROFILES->next;
        av_req_profile_destroy(aprof);
    }
}

static struct av_req_profile *av_req_profile_create(char *name) {
    struct av_req_profile *aprof;
    if (!(aprof = malloc(sizeof(struct av_req_profile)))) {
        ci_debug_printf(1, "Error allocation memory for av_req_profile\n");
        return NULL;
    }
    aprof->name = strdup(name);
    aprof->disable_scan = 0;
    aprof->send_percent_data = -1;
    aprof->start_send_after = -1;
    aprof ->max_object_size = 0;
    av_file_types_init(&aprof->scan_file_types);
    aprof->next = NULL;
    return aprof;
}

static void av_req_profile_destroy(struct av_req_profile *prof) {
 
    av_file_types_destroy(&prof->scan_file_types);
    free(prof);
}

struct av_req_profile *av_req_profile_search(char *name)
{
    struct av_req_profile *aprof;
    aprof = PROFILES;
    while(aprof) {
        if(strcmp(aprof->name,name)==0)
            return aprof;
        aprof = aprof->next;
    }
    return NULL;
}

struct av_req_profile *av_req_profile_get(char *name) {
    struct av_req_profile *aprof;
    if ((aprof = av_req_profile_search(name)) != NULL)
        return aprof;

    aprof = av_req_profile_create(name);
    aprof->next = PROFILES;
    return (PROFILES = aprof);
}

struct av_req_profile *av_req_profile_select(ci_request_t *req)
{
    struct av_req_profile *aprof;
    aprof = PROFILES;
    while(aprof) {
        if(ci_access_entry_match_request(aprof->access_list, 
                                         req) == CI_ACCESS_ALLOW) {    
            return aprof;
        }
        aprof = aprof->next;
    }

    /*If none match return NULL;*/
    return NULL;    
}


/*Implemented in srv_clamav.c*/
int cfg_ScanFileTypes(char *directive, char **argv, void *setdata);
int cfg_SendPercentData(char *directive, char **argv, void *setdata);
/*******/
int ap_req_profile_config_param(struct av_req_profile *prof, char *param, char **args) 
{
    if (!prof || !param || !args)
        return 0;

    if (strcmp(param, "DisableVirusScan") ==0) {
        prof->disable_scan = 1;
        return 1;
    }
    else if (strcmp(param, "SendPercentData") ==0) {
        return cfg_SendPercentData(param, args, &prof->send_percent_data);
    }
    else if (strcmp(param, "ScanFileTypes") ==0) {
         return cfg_ScanFileTypes(param, args, &prof->scan_file_types);
    }
#ifdef VIRALATOR_MODE
    else if (strcmp(param, "VirScanFileTypes") ==0) {
         return cfg_ScanFileTypes(param, args, &prof->scan_file_types);
    }
#endif
    else if (strcmp(param, "MaxObjectSize") ==0) {        
        return ci_cfg_size_off(param, args, &prof->max_object_size);
    }
    else if (strcmp(param, "StartSendingDataAfter") ==0) {
        return ci_cfg_size_off(param, args, &prof->start_send_after);
    }

    return 0;
}

int cfg_av_req_profile(char *directive, char **argv, void *setdata)
{
    struct av_req_profile *prof;
    
    if(!argv[0] || !argv[1] || !argv[2])
        return 0;
    
    prof=av_req_profile_get(argv[0]);
    if (!prof) {
        ci_debug_printf(1, "srv_clamav: Error allocating profile %s\n", argv[0]);
        return 0;
    }

    if(ap_req_profile_config_param(prof, argv[1], (argv+2))==0) {
        ci_debug_printf(1, "srv_clamav: Unknown configuration parameter for clamav profiles %s\n", argv[1]);
        return 0;
    }
    return 1;
}

int cfg_av_req_profile_access(char *directive, char **argv, void *setdata)
{
    struct av_req_profile *prof;
    ci_access_entry_t *access_entry;
    int argc, error;
    char *acl_spec_name;
    
    if(!argv[0] || !argv[1])
        return 0;
    
    if (!(prof = av_req_profile_search(argv[0]))) {
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

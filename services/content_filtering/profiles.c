#ifdef HAVE_CONFIG_H
#include "common.h"
#else
#include "common-static.h"
#endif
#include "c_icap/debug.h"
#include "c_icap/body.h"
#include "filters.h"
#include <errno.h>

/*Array of srv_cf_profiles_t*/
ci_ptr_dyn_array_t *PROFILES = NULL;

srv_cf_profile_t DEFAULT_PROFILE = { .name = "default", .access_list =  NULL, .actions = NULL, .filters = NULL, .replaceInfo = NULL};


const srv_cf_profile_t *srv_srv_cf_profile_search(const char *name)
{
    if (!PROFILES)
        return NULL;
    return (const srv_cf_profile_t *)ci_ptr_dyn_array_search(PROFILES, name);
}

static int free_profile_step(void *data, const char *name, const void *value)
{
    int i;
    srv_cf_action_cfg_t action;
    srv_cf_profile_t *prof = (srv_cf_profile_t *)value;
    ci_debug_printf(8, "srv_content_filtering: Releasing profile '%s'...\n", prof->name);
    free(prof->name);
    ci_access_entry_release(prof->access_list);
    while(ci_list_pop(prof->actions, &action)) {
        for(i = 0; action.replaceInfo && action.replaceInfo[i]; ++i)
            free(action.replaceInfo[i]);
        if (action.replaceInfo)
            free(action.replaceInfo);
    }

    free(prof);
    return 0;
}

void srv_srv_cf_profiles_reset()
{
    if (!PROFILES)
        return;

    ci_ptr_dyn_array_iterate(PROFILES, NULL, free_profile_step);
    ci_ptr_dyn_array_destroy(PROFILES);
    PROFILES = NULL;
}


struct checkProfileData {
    ci_request_t *req;
    const srv_cf_profile_t *prof;
};

static int check_profile(void *data, const char *name, const void *value)
{
    struct checkProfileData *checkData = (struct checkProfileData *)data;
    const srv_cf_profile_t *prof = (const srv_cf_profile_t *)value;
    if (prof->access_list &&
        (ci_access_entry_match_request(prof->access_list,
                                       checkData->req) == CI_ACCESS_ALLOW)) {
        ci_debug_printf(5, "url_check: profile %s matches!\n", prof->name);
        checkData->prof = prof;
        return 1;
    }
    return 0;
}

const srv_cf_profile_t *srv_srv_cf_profile_select(ci_request_t *req)
{
    struct checkProfileData checkData;
    checkData.req = req;
    checkData.prof = NULL;
    if (PROFILES) {
        ci_ptr_dyn_array_iterate(PROFILES, &checkData, check_profile);
        if (checkData.prof) {
            ci_debug_printf(5, "url_check: profile %s matches!\n", checkData.prof->name);
            return checkData.prof;
        }
    }

    ci_debug_printf(5, "url_check: Default profile selected!\n");
    return &DEFAULT_PROFILE;
}

static void profile_filter_add(srv_cf_profile_t *prof, const srv_cf_user_filter_t *filter, int action)
{

    srv_cf_filter_apply_t rp, *prp ;
    if (prof->filters == NULL)
        prof->filters = ci_list_create(32768, sizeof(srv_cf_filter_apply_t));
    for (prp = ci_list_first(prof->filters); prp != NULL; prp = ci_list_next(prof->filters)) {

        if (prp->filter == filter) {
            /*Already exist in list. Check if must marked as possible to replace text*/
            if (action == CF_AC_REPLACE)
                prp->needReplaceParts = 1;
            return;
        }
    }
    rp.filter = filter;
    rp.needReplaceParts = (action == CF_AC_REPLACE ? 1 : 0);
    ci_list_push_back(prof->filters, &rp);
}

int srv_cf_cfg_profile(const char *directive, const char **argv, void *setdata)
{
    int action = CF_AC_NONE;
    int scoreOperator = -1;
    int score = 0;
    int i, count;
    const char *header = NULL;
    const char *template = NULL;
    srv_cf_profile_t *prof;
    char **replace = NULL;

    if(!argv[0] || !argv[1] || !argv[2])
        return 0;

    if ((action = srv_cf_action_parse(argv[1])) == CF_AC_NONE) {
        ci_debug_printf(1, "Action  must be one of the 'block', 'allow', replace or 'addHeader'\n");
        return 0;
    }

    const srv_cf_user_filter_t *filter;
    if (!(filter = srv_cf_action_score_parse(argv[2], &scoreOperator, &score))) {
        /*Debug message exist inside srv_cf_filter_parse*/
        return 0;
    }

    if (action == CF_AC_ADD_HEADER) {
        if (!argv[3]) {
            ci_debug_printf(1, "Missing header definition for add_header action!\n");
            return 0;
        }
        header = argv[3];
    } else if (action == CF_AC_BLOCK && argv[3]) {
        if (strncasecmp(argv[3], "template=", 9) == 0) {
            template = argv[3]+9;
        }
    }else if (action == CF_AC_REPLACE && argv[3]) {
        /*Count the replaceInfo arguments*/
        for (i = 3, count = 0; argv[i] != NULL; ++i) {
            if (strncasecmp(argv[i], "replaceInfo=", 12) == 0)
                ++count;
        }
        if (count) {
            replace = malloc(sizeof(char *) * (count + 1));
            for (i = 3, count = 0 ; argv[i] != NULL; ++i) {
                if (strncasecmp(argv[i], "replaceInfo=", 12) == 0) {
                    replace[count] = strdup(argv[i]+12);
                    ++count;
                }
            }
            replace[count] = NULL;
        }
    }

    if (!PROFILES) {
        if (! (PROFILES = ci_ptr_dyn_array_new(4096))) {
            ci_debug_printf(1, "srv_content_filtering: Error allocating memory for storing profiles!");
            return 0;
        }
    }

    if (strcasecmp(argv[0], "default") == 0)
        prof = &DEFAULT_PROFILE;
    else if (!(prof = (srv_cf_profile_t *)ci_ptr_dyn_array_search(PROFILES, argv[0]))) {
        prof = malloc(sizeof(srv_cf_profile_t));
        ci_ptr_dyn_array_add(PROFILES, argv[0], prof);
        prof->name = strdup(argv[0]);
        prof->anyContentType = 0;
        prof->maxBodyData = 0;
        prof->access_list = NULL;
        prof->actions = NULL;
        prof->filters = NULL;
        prof->replaceInfo = NULL;
    }

    srv_cf_action_cfg_t actionEntry;
    if (header) {
        strncpy(actionEntry.header, header, sizeof(actionEntry.header));
        actionEntry.header[sizeof(actionEntry.header) - 1] = '\0';
    } else
        actionEntry.header[0] = '\0';
    actionEntry.action = action;
    actionEntry.scoreOperator = scoreOperator;
    actionEntry.score = score;
    actionEntry.matchingFilter = filter;
    actionEntry.replaceInfo = replace;
    strncpy(actionEntry.template, ((template && template[0] != '\0') ? template : "BLOCK"), sizeof(actionEntry.template));
    actionEntry.template[sizeof(actionEntry.template) - 1] = '\0';

    if (prof->actions == NULL)
        prof->actions = ci_list_create(32768, sizeof(srv_cf_action_cfg_t));
    ci_list_push_back(prof->actions, &actionEntry);

    profile_filter_add(prof, filter, action);

    if (prof->replaceInfo == NULL)
        prof->replaceInfo = ci_list_create(1024, sizeof(const char *));
    if (replace) {
        for(i=0; replace[i] != NULL; ++i) /*we may store duplicates, but we do not care...*/
            ci_list_push_back(prof->replaceInfo, &(replace[i]));
    }

    ci_debug_printf(2,"\n");
    return 1;
}

int srv_cf_cfg_action(const char *directive,const char **argv,void *setdata)
{
    const char *newArgv[5];
    if (!argv[0] || ! argv[1]) {
        ci_debug_printf(1, "Missing action (block|allow|addHeader)\n");
        return 0;
    }

    newArgv[0] = "default";
    newArgv[1] = argv[0];
    newArgv[2] = argv[1];
    newArgv[3] = argv[2] ? argv[2] : NULL;
    newArgv[4] = NULL;

    return srv_cf_cfg_profile(directive, newArgv, setdata);
}


int srv_cf_cfg_profile_access(const char *directive, const char **argv, void *setdata)
{
   srv_cf_profile_t *prof;
   ci_access_entry_t *access_entry;
   int argc, error;
   const char *acl_spec_name;

   if(!argv[0] || !argv[1])
    return 0;

   if (!PROFILES || !(prof = (srv_cf_profile_t *)ci_ptr_dyn_array_search(PROFILES, argv[0]))) {
       ci_debug_printf(1, "srv_url_check: Error: Unknown profile %s!", argv[0]);
       return 0;
   }

   if ((access_entry = ci_access_entry_new(&(prof->access_list),
					   CI_ACCESS_ALLOW)) == NULL) {
         ci_debug_printf(1, "srv_url_check: Error creating access list for cfg profiles!\n");
         return 0;
     }

   error = 0;
   for (argc = 1; argv[argc]!= NULL; argc++) {
       acl_spec_name = argv[argc];
          /*TODO: check return type.....*/
          if (!ci_access_entry_add_acl_by_name(access_entry, acl_spec_name)) {
	      ci_debug_printf(1,"srv_url_check: Error adding acl spec: %s in profile %s."
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

int srv_cf_cfg_profile_option(const char *directive, const char **argv, void *setdata)
{
    srv_cf_profile_t *prof;
    char *e;
    if(!argv[0] || !argv[1])
        return 0;

    if (!PROFILES || !(prof = (srv_cf_profile_t *)ci_ptr_dyn_array_search(PROFILES, argv[0]))) {
        ci_debug_printf(1, "srv_url_check: Error: Unknown profile %s!", argv[0]);
        return 0;
    }

    if (strcasecmp(argv[1], "AnyContentType") == 0)
        prof->anyContentType = 1;
    else if (strcasecmp(argv[1], "MaxBodyData") == 0) {
        if (!argv[2]) {
            ci_debug_printf(1, "srv_url_check: Error: missing value for 'MaxBodyData' option!");
            return 0;
        }

        errno = 0;
        prof->maxBodyData = (int64_t)strtol(argv[2], &e, 10);
        if (errno != 0 || e == argv[2]) {
            ci_debug_printf(1, "srv_url_check: Error: expected integer value for 'MaxBodyData' option got: '%s'", argv[2]);
            return 0;
        }
        if (prof->maxBodyData < 0)
            prof->maxBodyData = 0;

        if (*e == 'k' || *e == 'K' )
            prof->maxBodyData = prof->maxBodyData * 1024;
        else if (*e == 'm' || *e == 'M' )
            prof->maxBodyData = prof->maxBodyData * 1024 * 1024;
    } else {
        ci_debug_printf(1, "srv_url_check: Error: profile option '%s'!", argv[1]);
        return 0;
    }
    return 1;
}

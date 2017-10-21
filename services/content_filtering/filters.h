#ifndef __FILTERS_H
#define __FILTERS_H
#include "c_icap/access.h"
#include "c_icap/acl.h"
#include "c_icap/header.h"
#include "c_icap/txt_format.h"
#include "c_icap/ci_regex.h"

enum srv_cf_action_operation {CF_AC_NONE, CF_AC_BLOCK, CF_AC_ALLOW, CF_AC_ADD_HEADER, CF_AC_REPLACE};

//typedef ci_list_t;
typedef struct srv_cf_user_filter{
    char *name;
    ci_list_t *data; /* list of srv_cf_user_filter_data_t elements*/
} srv_cf_user_filter_t;

enum srv_cf_operator {CF_OP_LESS, CF_OP_GREATER, CF_OP_EQUAL};
typedef struct srv_cf_action_cfg {
    const srv_cf_user_filter_t *matchingFilter;
    char header[128];
    int action;
    int scoreOperator;
    int score;
    char template[512];
    char **replaceInfo;
} srv_cf_action_cfg_t;

const char *srv_cf_action_str(int action);
int srv_cf_action_parse(const char *str);
const srv_cf_user_filter_t *srv_cf_action_score_parse(const char *str, int *scoreOperator, int *score);

void srv_cf_filters_reset();
void srv_cf_filters_debug_print(int dlevel);

typedef struct srv_cf_filter_apply {
    const srv_cf_user_filter_t *filter;
    int needReplaceParts;
} srv_cf_filter_apply_t;

typedef struct srv_cf_profile {
    char *name;
    int anyContentType;
    int64_t maxBodyData;
    ci_access_entry_t *access_list;
    ci_list_t *actions; /*ci_list of srv_cf_action_cfg entries*/
    ci_list_t *filters; /*ci_list of srv_cf_filter_apply_t. Filters to be applied*/
    ci_list_t *replaceInfo; /*ci_list of (const char *). The infos/tags holding the replacement info*/
} srv_cf_profile_t;

const srv_cf_profile_t *srv_srv_cf_profile_search(const char *name);
const srv_cf_profile_t *srv_srv_cf_profile_select(ci_request_t *req);
void srv_srv_cf_profiles_reset();
int srv_cf_cfg_profile(const char *directive, const char **argv, void *setdata);
int srv_cf_cfg_profile_option(const char *directive, const char **argv, void *setdata);
int srv_cf_cfg_profile_access(const char *directive, const char **argv, void *setdata);
int srv_cf_cfg_match(const char *directive,const char **argv,void *setdata);
int srv_cf_cfg_action(const char *directive,const char **argv,void *setdata);

typedef struct srv_cf_results {
    const srv_cf_action_cfg_t *action;
    int action_score;
    int action_matchesCount;
    ci_list_t *scores;
    ci_membuf_t *replaceBody;
    ci_headers_list_t *addHeaders;
} srv_cf_results_t;

int srv_cf_print_scores_list(ci_list_t *scores, char *buf, int buf_size);

int srv_cf_apply_actions(ci_request_t *req, const srv_cf_profile_t *prof, ci_membuf_t *body, srv_cf_results_t *result, struct ci_fmt_entry *fmtTable);


enum srv_cf_filters {BodyRegex, HeaderRegex, RequestHeaderRegex, UrlRegex};

typedef struct srv_cf_user_filter_data {
    int type; /*of type srv_cf_filters*/
    char *header; /*header name or NULL for all headers*/
    char *regex_str;
    int regex_flags;
    ci_regex_t regex_compiled;
    int recursive;
    /*Members for tagging or score or etc....*/
    int score;
    ci_str_array_t *infoStrings;
} srv_cf_user_filter_data_t;


#endif //__FILTERS_H

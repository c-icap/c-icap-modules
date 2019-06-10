#ifdef HAVE_CONFIG_H
#include "common.h"
#else
#include "common-static.h"
#endif
#include "c_icap/c-icap.h"
#include "c_icap/request.h"
#include "c_icap/array.h"
#include "c_icap/debug.h"
#include "c_icap/simple_api.h"
#include "c_icap/body.h"
#include "filters.h"

#include <assert.h>

typedef struct srv_cf_matcher {
    const char *name;
    void *(*parse_data)(const char *argv[]);
    void (*free_data)(void *data);
    int (*match)(const void *data, ci_request_t *req, ci_membuf_t *body);
} srv_cf_matcher_t;

struct FilterResult {
    const srv_cf_user_filter_t *matchingFilter;
    int score;
    int count;
};

ci_ptr_dyn_array_t *FILTERS = NULL;

int replacePartsToBody(ci_membuf_t *body, ci_membuf_t *newbody, ci_list_t *replacements, ci_list_t *tags);

void srv_cf_filters_reset()
{
    if (!FILTERS)
        return;
    ci_ptr_dyn_array_destroy(FILTERS);
    FILTERS = NULL;
}

const char *srv_cf_action_str(int action)
{
    switch(action) {
    case CF_AC_NONE:
        return "none";
        break;
    case CF_AC_BLOCK:
        return "block";
        break;
    case CF_AC_ALLOW:
        return "allow";
        break;
    case CF_AC_ADD_HEADER:
        return "add_header";
        break;
    case CF_AC_REPLACE:
        return "replace";
        break;
    }
    return "unknown";
}

#if 0
static int print_action(void *data, const void *element)
{
    int dlevel = *(int *)data;
    const srv_cf_action_cfg_t *a = (srv_cf_action_cfg_t *) element;
    ci_debug_printf(dlevel, "Action\n\t: %s score{%s%c%d}\n",
                    srv_cf_action_str(a->action),
                    (a->matchingFilter != NULL ? a->matchingFilter->name : "-"),
                    a->scoreOperator == CF_OP_LESS ? '<' : (a->scoreOperator == CF_OP_GREATER ? '>' : '='),
                    a->score
        );
    return 0;
}
#endif

static int print_srv_cf_user_filter_data(void *data, const void *element)
{
    int dlevel = *(int *)data;
    const srv_cf_user_filter_data_t *fd = (srv_cf_user_filter_data_t *) element;
    ci_debug_printf(dlevel, "\t: %s%s%s%s, /%s/ %d\n",
                    fd->type == BodyRegex ? "body" : (fd->type == HeaderRegex? "header": (fd->type == RequestHeaderRegex? "request_header" : "url")),
                    fd->header != NULL ? "{" : "",
                    fd->header != NULL ? fd->header : "",
                    fd->header != NULL ? "}" : "",
                    fd->regex_str,
                    fd->score
        );
    return 0;
}

static int print_user_filter(void *data, const char *name, const void *element)
{
    int dlevel = *(int *)data;
    srv_cf_user_filter_t *filter = (srv_cf_user_filter_t *)element;
    ci_debug_printf(dlevel, "Filter %s\n", filter->name);
    ci_list_iterate(filter->data, data, print_srv_cf_user_filter_data);
    return 0;
}

void srv_cf_filters_debug_print(int dlevel)
{
    /*We should pop elements and free them*/
    if (FILTERS)
        ci_ptr_dyn_array_iterate(FILTERS, &dlevel, print_user_filter);
}

static int matchBodyRegex(const srv_cf_user_filter_data_t *fd, ci_request_t *req, ci_membuf_t *body, int *count, ci_list_t *matches)
{
    int score, ret;
    const char *str = body->buf;
    int str_len = ci_membuf_size(body);

    score = 0;
    ret = ci_regex_apply(fd->regex_compiled, str, str_len, fd->recursive, matches, fd);

    if (ret > 0) {
        ci_debug_printf(5, "matchBodyRegex:Match rule type:%d regex:%s score:%d, count: %d\n", fd->type, fd->regex_str, fd->score, ret);
        if (count)
            *count += ret;
        score = ret * fd->score;
    }

    return score;
}

static int matchHeaderRegex(const srv_cf_user_filter_data_t *fd, ci_headers_list_t *headers, int *count, ci_list_t *matches)
{
    int i;
    const char *header;

    if (fd->header) {
        if ((header = ci_headers_search(headers, fd->header))) {
            ci_debug_printf(3, "matchHeaderRegex:Apply to the header %s the regex '%s'\n", header, fd->regex_str);
            if (ci_regex_apply(fd->regex_compiled, header, -1, 0, matches, fd)) {
                ci_debug_printf(3, "matchHeaderRegex:Match rule type:%d, regex:%s, header: %s, score:%d\n", fd->type, fd->regex_str, fd->header, fd->score);
                if (count)
                    ++(*count);
                return fd->score;
            }
        }
    } else {
        /*Apply to all headers*/
        for (i = 0; i < headers->used; ++i) {
            if (ci_regex_apply(fd->regex_compiled, headers->headers[i], -1, 0, matches, fd)) {
                ci_debug_printf(3, "matchHeaderRegex: Match rule type:%d regex:%s, score:%d\n", fd->type, fd->regex_str, fd->score);
                if (count)
                    ++(*count);
                return fd->score;
            }
        }
    }
    return 0;
}

static int matchResponseHeaderRegex(const srv_cf_user_filter_data_t *fd, ci_request_t *req, ci_membuf_t *body, int *count, ci_list_t *matches)
{
    ci_headers_list_t *headers;

    if (!(headers = ci_http_response_headers(req)))
        return 0;

    return matchHeaderRegex(fd, headers, count, matches);
}

static int matchRequestHeaderRegex(const srv_cf_user_filter_data_t *fd, ci_request_t *req, ci_membuf_t *body, int *count, ci_list_t *matches)
{
    ci_headers_list_t *headers;

    if (!(headers = ci_http_request_headers(req)))
        return 0;

    return matchHeaderRegex(fd, headers, count, matches);
}

#define header_end(e) (e == '\0' || e == '\n' || e == '\r')
static int get_full_http_request_url(ci_request_t * req, char *buf, int buf_size)
{
    ci_headers_list_t *heads;
    const char *str, *host;
    int i, bytes;
    /*The request must have the form:
      GET url HTTP/X.X
    */
    if (!(heads = ci_http_request_headers(req)))
        return 0;

    if (!heads->used)
        return 0;

    str = heads->headers[0];

    if ((str = strchr(str, ' ')) == NULL) { /*Ignore method i*/
        return 0;
    }
    while (*str == ' ') /*ignore spaces*/
        str++;

    bytes = 0;
    if (*str == '/' && (host = ci_headers_value(heads,"Host"))) {
        /*Looks like a transparent proxy, we do not know the protocol lets try
          to preserve the major part of the url....
        */
        for (i=0; (i < buf_size-1) && !header_end(host[i]) && !isspace(host[i]); i++) {
            buf[i] = host[i];
        }
        buf += i;
        buf_size -= i;
        bytes = i;
    }

    /*copy the url...*/
    for (i=0; (i < buf_size-1) && !header_end(str[i]) && !isspace(str[i]); i++) {
        buf[i] = str[i];
    }
    buf[i] = '\0';
    bytes += i;
    return bytes;
}

static int matchUrlRegex(const srv_cf_user_filter_data_t *fd, ci_request_t *req, char *url, int url_size, int *count, ci_list_t *matches)
{
    if (ci_regex_apply(fd->regex_compiled, url, url_size, 0, matches, fd)) {
        if (count)
            ++(*count);

        ci_debug_printf(3, "Match rule, type:%d regex:%s, score:%d\n", fd->type, fd->regex_str, fd->score);
        return fd->score;
    }
    return 0;
}

#define URL_MAX_SIZE 65535
struct FilterApplyData {
    ci_request_t *req;
    ci_membuf_t *body;
    char url[URL_MAX_SIZE];
    int url_size;
    int compute_replacements;
    ci_list_t *filterResults;
    ci_list_t *replaceParts; /*list of ci_regex_replace_part_t*/
};

static int apply_filter_step(struct FilterApplyData *fad, const srv_cf_user_filter_data_t *fd, int *score)
{
    int matchCount;
    ci_request_t *req = fad->req;
    ci_membuf_t *body= fad->body;

    ci_debug_printf(5, "apply_filter_step:Start filter applying\n");

    matchCount = 0;
    *score = 0;
    if (fd->type == BodyRegex) {
        *score = matchBodyRegex(fd, req, body, &matchCount, fad->replaceParts);
    } else if (fd->type == HeaderRegex) {
        *score = matchResponseHeaderRegex(fd, req, body, &matchCount, fad->replaceParts);
    } else if (fd->type == RequestHeaderRegex) {
        *score = matchRequestHeaderRegex(fd, req, body, &matchCount, NULL /*can not replace*/);
    } else if (fd->type == UrlRegex) {
        if (!(fad->url_size))
            fad->url_size = get_full_http_request_url(req, fad->url, URL_MAX_SIZE);

        if (fad->url_size)
            *score = matchUrlRegex(fd, req, fad->url, fad->url_size, &matchCount, NULL /*can not replace*/);
    }
    ci_debug_printf(5, "apply_filter_step: score:%d, matchCount:%d\n", *score, matchCount);
    return matchCount;
}

static int apply_filter( struct FilterApplyData *fad, const srv_cf_user_filter_t *filter)
{
    struct FilterResult result;
    const srv_cf_user_filter_data_t *fd;
    int matchCount, score, stepScore;

    ci_debug_printf(5, "Will apply filter %s\n", filter->name);

    matchCount = 0;
    stepScore = 0;
    for (fd = ci_list_first(filter->data); fd != NULL; fd = ci_list_next(filter->data)) {

        if (/*Need to replace parts &&*/ fad->replaceParts == NULL) {
            fad->replaceParts = ci_regex_create_match_list();
        }

        if (fd) {
            score = 0;
            matchCount += apply_filter_step(fad, fd, &score);
            stepScore += score;
        }
    }


    if (stepScore) {
        result.matchingFilter = filter;
        result.count = matchCount;
        result.score = stepScore;
        ci_debug_printf(3, "apply_filter: Match result for rule %s, count:%d, score: %d\n",
                        result.matchingFilter->name, result.count, result.score);
        if (fad->filterResults == NULL)
            fad->filterResults = ci_list_create(32768, sizeof(struct FilterResult));
        ci_list_push_back(fad->filterResults, &result);
    }

    return 0;
}

static int membuf_terminate(ci_membuf_t *mem)
{
    if (mem->bufsize > mem->endpos)
        mem->buf[mem->endpos] = '\0';
    else {
        char buf[1];
        buf[0] = '\0';
        if (ci_membuf_write(mem, buf, 1, 0) <= 0) // not able to write ???
            return 0;
        --mem->endpos;
    }

    return 1;
}

const struct FilterResult *findFilterResult(ci_list_t *results, const srv_cf_user_filter_t *f)
{
    ci_list_item_t *item;
    if (!results)
        return NULL;

    for (item = results->items; item != NULL; item = item->next) {
        const struct FilterResult *fr;
        fr = item->item;
        ci_debug_printf(3, "Check if %s/%p and %s/%p matches\n", fr->matchingFilter->name, fr->matchingFilter, f->name, f);
        if (fr && fr->matchingFilter == f) {
            return fr;
            ci_debug_printf(3, "Found rule %s, count: %d, score:%d\n", fr->matchingFilter->name, fr->count, fr->score);
        }
    }

    return NULL;
}

int srv_cf_print_scores_list(ci_list_t *scores, char *buf, int buf_size)
{
    ci_list_item_t *item;
    char *str;
    int bytes, str_len;
    if (!scores || buf_size <= 1)
        return 0;

    str = buf;
    str_len = buf_size;
    for (item = scores->items; item != NULL && str_len > 0; item = item->next) {
        const struct FilterResult *fr;
        fr = item->item;
        bytes = snprintf(str, str_len, "%s%s=%d", (str != buf ? ",": ""), fr->matchingFilter->name, fr->score);
        str += bytes;
        str_len -= bytes;
    }
    if (str_len <= 0) {
        buf[buf_size -1] = '\0';
        return buf_size;
    }
    return (buf_size - str_len);
}

int cmp_replacement_func(const void *obj, const void *user_data, size_t user_data_size)
{
    const ci_regex_replace_part_t *listRepl = (const ci_regex_replace_part_t *)obj;
    const ci_regex_replace_part_t *cmpRepl = (const ci_regex_replace_part_t *)user_data;
    assert(user_data_size == sizeof(ci_regex_replace_part_t));

    ci_debug_printf(5, "will compare (%p<>%p): %d-%d <> %d-%d :", listRepl, cmpRepl, (int)listRepl->matches[0].s, (int)listRepl->matches[0].e, (int)cmpRepl->matches[0].s, (int)cmpRepl->matches[0].e);
    /*If they are the same object stop searching*/
    if (listRepl == cmpRepl){
        ci_debug_printf(5,"the same\n");
        return 0;
    }
    const srv_cf_user_filter_data_t *list_filter_data = (const srv_cf_user_filter_data_t *)listRepl->user_data;
    const srv_cf_user_filter_data_t *cmp_filter_data = (const srv_cf_user_filter_data_t *)cmpRepl->user_data;
    /*if they are not the same type are not equal*/
    if (list_filter_data->type != cmp_filter_data->type){
        ci_debug_printf(5,"no same type\n");
        return -1;
    }

    if ((list_filter_data->type == HeaderRegex || list_filter_data->type == RequestHeaderRegex)) {
        /*if one of two objects does not have header definition are not equal*/
        if ((!list_filter_data->header && cmp_filter_data->header) ||
            (list_filter_data->header && !cmp_filter_data->header)) {
            ci_debug_printf(5,"no header one of them\n");
            return -1;
        }
        /*if one of two objects have header definition and header names are not the same then
          they are not equal*/
        if (list_filter_data->header && cmp_filter_data->header && strcmp(list_filter_data->header, cmp_filter_data->header) !=0) {
            ci_debug_printf(5,"different headers\n");
            return -1;
        }
    }

    /*Now check if the replacements intercepts*/
    if ((listRepl->matches[0].s <= cmpRepl->matches[0].s && listRepl->matches[0].e >= cmpRepl->matches[0].s) ||
        (listRepl->matches[0].s <= cmpRepl->matches[0].e && listRepl->matches[0].e >= cmpRepl->matches[0].e)
        ) {
        ci_debug_printf(5,"1\n");
        return 0;
    }
    if ((cmpRepl->matches[0].s <= listRepl->matches[0].s && cmpRepl->matches[0].e >= listRepl->matches[0].s) ||
        (cmpRepl->matches[0].s <= listRepl->matches[0].e && cmpRepl->matches[0].e >= listRepl->matches[0].e)
        ) {
                ci_debug_printf(5,"2\n");
        return 0;
    }
    ci_debug_printf(5,"not matches\n");
    return -1;
}

void remove_overlaped_replacement(ci_list_t *replaceParts)
{
    ci_regex_replace_part_t *replacement;
    const ci_regex_replace_part_t *tmp;


    if (!replaceParts)
        return;
    for (replacement = ci_list_first(replaceParts); replacement != NULL; replacement = ci_list_next(replaceParts)) {
        const srv_cf_user_filter_data_t *filter_data = (const srv_cf_user_filter_data_t *)replacement->user_data;
        ci_debug_printf(5, "Check %p of type %d '%s':start=%d,end=%d\n",replacement, filter_data->type, filter_data->regex_str, (int)replacement->matches[0].s,  (int)replacement->matches[0].e)
        tmp = ci_list_search2(replaceParts, replacement, cmp_replacement_func);
        if (tmp && tmp != replacement) {
            ci_debug_printf(5, "\tReplacement (%p<>%p) will be removed\n",replacement, tmp);
            ci_list_remove(replaceParts, replacement);
        }
    }
}


int cmp_replace_part_t_func(const void *obj1, const void *obj2, size_t user_data_size)
{
    int ret;
    const ci_regex_replace_part_t *repl1 = obj1;
    const ci_regex_replace_part_t *repl2 = obj2;
    const srv_cf_user_filter_data_t *repl1_filter_data = (const srv_cf_user_filter_data_t *)repl1->user_data;
    const srv_cf_user_filter_data_t *repl2_filter_data = (const srv_cf_user_filter_data_t *)repl2->user_data;
    assert(user_data_size == sizeof(ci_regex_replace_part_t));


    /*if they are not the same type are not equal*/
    if (repl1_filter_data->type != repl2_filter_data->type)
        return (repl1_filter_data->type - repl2_filter_data->type);

    /*if one of two objects does not have header definition are not equal*/
    if (!repl1_filter_data->header && repl2_filter_data->header)
        return -1;

    if (repl1_filter_data->header && !repl2_filter_data->header)
        return 1;

    /*if both of two objects have header definition and header names are not the same then
      they are not equal*/
    if (repl1_filter_data->header && repl2_filter_data->header &&
        (ret = strcmp(repl1_filter_data->header, repl2_filter_data->header)) != 0)
        return ret;

    /*The tow objects refers to the same data, compare start of their segments*/
    return (repl1->matches[0].s - repl2->matches[0].s);
}

int apply_filters_list(const srv_cf_profile_t *prof, struct FilterApplyData *fad)
{
    srv_cf_filter_apply_t *prp;
    int filtersCount = 0;
    for (prp = ci_list_first(prof->filters); prp != NULL; prp = ci_list_next(prof->filters)) {
        if (prp->filter) {
            ci_debug_printf(5, "Will apply filter %s\n", prp->filter->name);
            apply_filter(fad, prp->filter);
            ++filtersCount;
        }
    }
    return filtersCount;
}

int srv_cf_apply_actions(ci_request_t *req, const srv_cf_profile_t *profile, ci_membuf_t *body, srv_cf_results_t *result, struct ci_fmt_entry *fmtTable)
{
    char buf[1024];
    struct FilterApplyData fad;
    const struct FilterResult *fr;
    const srv_cf_action_cfg_t *actionEntry;
    ci_list_t *replaceInfoTags = NULL;  /*list of (const char *) */
    int filtersCount;
    int i;

    ci_debug_printf(5, "Going to do content filtering!\n");

    /*Null tetrminate the membuf*/
    if (!membuf_terminate(body))
        return  0;

    fad.req = req;
    fad.body = body;
    fad.filterResults = NULL;
    fad.replaceParts = NULL;
    fad.url[0] = '\0';
    fad.url_size = 0;

    filtersCount = apply_filters_list(profile, &fad);

    if (!filtersCount) {
        ci_debug_printf(2, "No filters configured for profile :%s!\n", profile->name);
        return 0;
    }


    if (fad.filterResults) {
        ci_debug_printf(5, "There are filter results\n");
        for (fr = ci_list_first(fad.filterResults); fr != NULL; fr = ci_list_next(fad.filterResults)) {
            ci_debug_printf(3, "Match rule %s, count: %d, score:%d\n", fr->matchingFilter->name, fr->count, fr->score);
        }
    } else {
        ci_debug_printf(5, "There are not filter results!\n");
    }

    const srv_cf_action_cfg_t *doAction = NULL;
    if (profile->actions) {
        for (actionEntry = ci_list_first(profile->actions); actionEntry != NULL && doAction == NULL; actionEntry = ci_list_next(profile->actions)) {
            fr = findFilterResult(fad.filterResults, actionEntry->matchingFilter);

            if (fr &&
                ((actionEntry->scoreOperator == CF_OP_LESS && fr->score < actionEntry->score) ||
                 (actionEntry->scoreOperator == CF_OP_GREATER && fr->score > actionEntry->score) ||
                 (actionEntry->scoreOperator == CF_OP_EQUAL && fr->score == actionEntry->score))
                )
            {
                /*Store to result the latest action*/
                result->action = actionEntry;
                result->action_score = fr->score;
                result->action_matchesCount = fr->count;
                if (actionEntry->action == CF_AC_REPLACE) {
                    if (fad.replaceParts && actionEntry->replaceInfo) {
                        if (!replaceInfoTags)
                            replaceInfoTags = ci_list_create(1024, 0);/*zero size object means store pointers*/
                        for (i = 0; actionEntry->replaceInfo[i] != NULL; ++i )
                            ci_list_push_back(replaceInfoTags, actionEntry->replaceInfo[i]);
                    }
                } else if (actionEntry->action == CF_AC_ADD_HEADER) {
                    if (actionEntry->header[0]) {
                        if (!result->addHeaders)
                            result->addHeaders = ci_headers_create();
                        if (ci_format_text(req, actionEntry->header, buf, sizeof(buf), fmtTable))
                            ci_headers_add(result->addHeaders, buf);
                    }
                } else if (actionEntry->action == CF_AC_BLOCK || actionEntry->action == CF_AC_ALLOW)
                    doAction = actionEntry; /*Final Action*/
            }
        }
    }

    if (doAction) {
        ci_debug_printf(3, "Found action : %s\n", srv_cf_action_str(doAction->action));
    }
    result->scores = fad.filterResults;

    if (replaceInfoTags) {
        ci_debug_printf(3, "DO REPLACE BODY!\n");
        ci_membuf_t *newbody = ci_membuf_new_sized((ci_membuf_size(body)));
        if (replacePartsToBody(body, newbody, fad.replaceParts, replaceInfoTags))
            result->replaceBody = newbody;
        ci_list_destroy(replaceInfoTags);
        replaceInfoTags = NULL;
    }

    /*
     The list must destroyed by the caller function!
      ci_list_destroy(fad.filterResults);
    */
    ci_list_destroy(fad.replaceParts);
    return doAction != NULL;
}

const char *getReplacementForFilterRegex(const srv_cf_user_filter_data_t *filter_data, ci_list_t *replaceInfoTags)
{
    const char *tag;
    const char *val;
    if (!filter_data->infoStrings)
        return NULL;

    for (tag = ci_list_first(replaceInfoTags); tag != NULL; tag = ci_list_next(replaceInfoTags)) {
        if (tag && (val = ci_str_array_search(filter_data->infoStrings, tag)) != NULL)
            return val;
    }

    return NULL;
}

int replacePartsToBody(ci_membuf_t *body, ci_membuf_t *newbody, ci_list_t *replacements, ci_list_t *replaceInfoTags)
{
    ci_regex_replace_part_t *rpart;
    const srv_cf_user_filter_data_t *filter_data;

    if (!replaceInfoTags)
        return 0;

    ci_debug_printf(5, "Initial list:\n");
    for (rpart = ci_list_first(replacements); rpart != NULL; rpart = ci_list_next(replacements)) {
        filter_data = (const srv_cf_user_filter_data_t *)rpart->user_data;
        ci_debug_printf(5, "\tReplace text type: %d regex:'%s' segment:%d-%d\n", (int)filter_data->type,  filter_data->regex_str,  (int)rpart->matches[0].s, (int)rpart->matches[0].e);
    }

    remove_overlaped_replacement(replacements);
    ci_list_sort2(replacements, cmp_replace_part_t_func);

    ci_debug_printf(5, "Final list:\n");
    for (rpart = ci_list_first(replacements); rpart != NULL; rpart = ci_list_next(replacements)) {
        filter_data = (const srv_cf_user_filter_data_t *)rpart->user_data;
        ci_debug_printf(5, "\tReplace text type: %d regex:'%s' segment:%d-%d\n", (int)filter_data->type,  filter_data->regex_str,  (int)rpart->matches[0].s, (int)rpart->matches[0].e);
    }

    int i;
    const char *replaceWithStr = " $1_$2_$3 ";
    size_t pos = 0;
    const char *data, *s;
    data = s = body->buf;
    for (rpart = ci_list_first(replacements); rpart != NULL; rpart = ci_list_next(replacements)) {
        filter_data = (const srv_cf_user_filter_data_t *)rpart->user_data;
        if (filter_data->type != BodyRegex)
            continue;
        if (!(replaceWithStr = getReplacementForFilterRegex(filter_data, replaceInfoTags)))
            continue;
        pos = rpart->matches[0].s;
        ci_debug_printf(5,"Will Add %lu of %s\n", (unsigned long)(pos - (s - data)), s);
        ci_membuf_write(newbody, s, pos - (s - data), 0);
        for (i = 0; i < strlen(replaceWithStr); ++i) {
            if (replaceWithStr[i] == '$' && (i == 0 || replaceWithStr[i-1] != '\\')
                && replaceWithStr[i +1] >= '0' && replaceWithStr[i +1] <= '9') {
                ci_membuf_write(newbody,
                                data + rpart->matches[replaceWithStr[i + 1] - '0' ].s,
                                rpart->matches[replaceWithStr[i + 1] - '0' ].e - rpart->matches[replaceWithStr[i + 1] - '0' ].s,
                                0);
                ++i;
            } else
                ci_membuf_write(newbody, replaceWithStr+i, 1, 0);
        }
        s = data + rpart->matches[0].e;
    }
    if (s && (body->endpos - (s - data)) > 0)
        ci_membuf_write(newbody, s, body->endpos - (s - data), 0);

    ci_membuf_write(newbody, "", 0, 1);
    return 1;
}

void free_srv_cf_user_filter_data(struct srv_cf_user_filter_data *fd)
{
    if (fd->header)
        free(fd->header);
    if (fd->regex_str) {
        free(fd->regex_str);
        ci_regex_free(fd->regex_compiled);
    }
    if (fd->infoStrings)
        ci_str_array_destroy(fd->infoStrings);
    free(fd);
}

void free_srv_cf_user_filter(srv_cf_user_filter_t *fdef)
{
    srv_cf_user_filter_data_t *fd;
    if (fdef->name)
        free(fdef->name);
    if (fdef->data) {
        while(ci_list_pop(fdef->data, &fd) != NULL) {
            free_srv_cf_user_filter_data(fd);
        }
        ci_list_destroy(fdef->data);
    }
    free(fdef);
}

int loadRulesFromFile(srv_cf_user_filter_t *filter, const char *file, int type, const char *typeArg)
{
    struct srv_cf_user_filter_data *fd = NULL;
    int lineNumber = 0;
    char line[65536];
    char *s, *e;
    char *infoName, *infoVal;

    FILE *f;
    if ((f = fopen(file, "r+")) == NULL) {
        ci_debug_printf(1, "Error opening file: %s\n", file);
        return 0;
    }

    while(fgets(line, sizeof(line) - 1, f)) {
        lineNumber++;
        line[sizeof(line) - 1] = '\0';
        e = line + strlen(line);
        // Remove spaces at the end of line.
        while (e > line && index(" \t\r\n", *e)) {
            *e = '\0';
            --e;
        }

        s = line + strspn(line, " \t\r\n");

        if (*s == '#' || *s == '\0') /*this is a comment or empty line*/
            continue;

        fd = malloc(sizeof(struct srv_cf_user_filter_data));
        if (!fd) {
            ci_debug_printf(1, "Error allocation memory, while parsing file '%s'!\n", file);
            fclose(f);
            return 0;
        }
        fd->type = type;
        fd->header = typeArg ? strdup(typeArg) : NULL;
        fd->regex_str = NULL;
        fd->regex_flags = 0;
        fd->recursive = 0;
        fd->regex_compiled = NULL;
        fd->score = 0;
        fd->infoStrings = NULL;

        while(*s) {
            if (strncmp(s, "score=", 6) == 0) {
                s += 6;
                fd->score = strtol(s, &e, 10);
                if (s == e) {
                    ci_debug_printf(1, "Error parsing file: %s, line %d: '%s'\n", file, lineNumber, s);
                    free_srv_cf_user_filter_data(fd);
                    fclose(f);
                    return 0;
                }
            } else if (strncmp(s, "info{", 5) == 0) {
                infoName = s + 5;
                if ((e = strchr(infoName, '}')) == NULL ||  *(e + 1) != '=') {
                    ci_debug_printf(1, "Error parsing file '%s', line %d,  Expecting info{InfoName}=InfoValue got '%s'\n", file, lineNumber, s);
                    free_srv_cf_user_filter_data(fd);
                    fclose(f);
                    return 0;
                }
                *e = '\0';
                infoVal = e + 2;
                e = infoVal + strcspn(infoVal, " \t\r");
                if (!e) {
                    ci_debug_printf(1, "Error parsing file '%s', line %d,  expecting regex expression at the end of line\n", file, lineNumber);
                    free_srv_cf_user_filter_data(fd);
                    fclose(f);
                    return 0;
                }
                *e = '\0';
                ++e;
                if (!fd->infoStrings) {
                    fd->infoStrings = ci_str_array_new(1024);
                }
                ci_str_array_add(fd->infoStrings, infoName, infoVal);
            } else
                break;
            s = e + strspn(e, " \t\r"); /*should point to space*/
        }

        if ((fd->regex_str = ci_regex_parse(s, &fd->regex_flags, &fd->recursive))) {
            fd->regex_compiled = ci_regex_build(fd->regex_str, fd->regex_flags);
        }
        if (!fd->regex_compiled) {
            ci_debug_printf(1, "Error parsing file '%s', line %d,  regex expression: '%s'\n", file, lineNumber, fd->regex_str);
            free_srv_cf_user_filter_data(fd);
            fclose(f);
            return 0;
        }

        if (!ci_list_push_back(filter->data, fd)) {
            ci_debug_printf(1, "Unable to add rule: %s\n", fd->regex_str);
            free_srv_cf_user_filter_data(fd);
            fclose(f);
            return 0;
        }
    }
    fclose(f);
    return 1;
}

int srv_cf_cfg_match(const char *directive,const char **argv,void *setdata)
{
    int argc, i, type;
    char *name, *infoName, *infoVal;
    srv_cf_user_filter_t *filter;
    struct srv_cf_user_filter_data *fd = NULL;
    const char *rulesFromFile = NULL;

    for (argc = 0; argv[argc] != NULL; ++argc);

    if (argc < 3) {
        ci_debug_printf(1, "Missing arguments for '%s' cfg parameter!\n", directive);
        return 0;
    }

    name = strdup(argv[0]);
    char *typeParam = strdup(argv[1]);
    char *typeArg = NULL;
    char *e;
    if ((typeArg = strchr(typeParam, '{'))) {
        *typeArg = '\0';
        typeArg++;
        e = strchr(typeArg, '}');
        if (e)
            *e = '\0';
    }
    ci_debug_printf(4, "Type parameter: %s arg:%s\n", typeParam, typeArg);

    if (strcasecmp(typeParam, "body") == 0)
        type = BodyRegex;
    else if (strcasecmp(typeParam, "header") == 0)
        type = HeaderRegex;
    else if (strcasecmp(typeParam, "request_header") == 0 || strcasecmp(typeParam, "requestHeader") == 0)
        type = RequestHeaderRegex;
    else if (strcasecmp(typeParam, "url") == 0)
        type = UrlRegex;
    else {
        ci_debug_printf(1, "Expecting [body|header|request_header|url], got '%s'!\n", typeParam);
        free(typeParam);
        return 0;
    }
    free(typeParam);


    if (strncasecmp(argv[2], "file:", 5) == 0) {
        rulesFromFile = argv[2] + 5;
    }

    if (!rulesFromFile) {
        fd = malloc(sizeof(struct srv_cf_user_filter_data));
        if (!fd) {
            ci_debug_printf(1, "Error allocation memory!\n");
            return 0;
        }
        fd->type = type;
        fd->header = typeArg ? strdup(typeArg) : NULL;
        fd->regex_str = NULL;
        fd->regex_flags = 0;
        fd->recursive = 0;
        fd->regex_compiled = NULL;
        fd->score = 0;
        fd->infoStrings = NULL;


        if ((fd->regex_str = ci_regex_parse(argv[2], &fd->regex_flags, &fd->recursive))) {
            fd->regex_compiled = ci_regex_build(fd->regex_str, fd->regex_flags);
        }
        if (!fd->regex_compiled) {
            ci_debug_printf(1, "Error parsing regex expression: %s\n", fd->regex_str);
            free_srv_cf_user_filter_data(fd);
            return 0;
        }

        fd->score = 1;

        if (argc > 3) {
            for (i = 3; i < argc; ++i) {
                if (strncmp(argv[i], "score=", 6) == 0) {
                    fd->score = strtol((argv[i] + 6), NULL, 10);
                } if (strncmp(argv[i], "info{", 5) == 0) {
                    ci_debug_printf(1, "Got: %s\n", argv[i]);
                    char *tmp = strdup(argv[i]);
                    infoName = tmp + 5;
                    if ((e = strchr(tmp, '}')) == NULL ||  *(e + 1) != '=') {
                        ci_debug_printf(1, "srv_cf_cfg_match: parse error: Expecting info{InfoName}=InfoValue got '%s'\n", tmp);
                        free_srv_cf_user_filter_data(fd);
                        free(tmp);
                        return 0;
                    }
                    *e = '\0';
                    infoVal = e + 2;
                    ci_debug_printf(1, "Got Name '%s', got value: '%s'\n", infoName, infoVal);
                    if (!fd->infoStrings) {
                        fd->infoStrings = ci_str_array_new(1024);
                    }
                    ci_str_array_add(fd->infoStrings, infoName, infoVal);
                    free(tmp);
                } else {
                    /*error*/
                }
            }
        }
    }

    if (!FILTERS)
        FILTERS = ci_ptr_dyn_array_new(4096);

    filter = (void *)ci_ptr_dyn_array_search(FILTERS, name);
    if (!filter) {
        filter = (srv_cf_user_filter_t *)malloc(sizeof(srv_cf_user_filter_t));
        filter->name = name;
        ci_ptr_dyn_array_add(FILTERS, name, filter);
        filter->data = ci_list_create(4096, 0); /*zero sized object mean store pointers*/
    } else {
        free(name);
    }

    if (rulesFromFile) {
        assert(!fd);
        return loadRulesFromFile(filter, rulesFromFile, type, typeArg);
    }

    assert(fd);

    if (!ci_list_push_back(filter->data, fd)) {
        ci_debug_printf(1, "Unable to add rule: %s\n", fd->regex_str);
        free_srv_cf_user_filter_data(fd);
        return 0;
    }

    return 1;
}

int srv_cf_action_parse(const char *str)
{
    if (strcasecmp(str, "block") == 0)
        return CF_AC_BLOCK;
    else if (strcasecmp(str, "allow") == 0)
        return CF_AC_ALLOW;
    else if (strcasecmp(str, "addheader") == 0 || strcasecmp(str, "add_header") == 0)
        return CF_AC_ADD_HEADER;
    else if (strcasecmp(str, "replace") == 0)
        return CF_AC_REPLACE;
    else
        return CF_AC_NONE;
}

const srv_cf_user_filter_t *srv_cf_action_score_parse(const char *str, int *scoreOperator, int *score)
{
    const srv_cf_user_filter_t *fd = NULL;
    char *scoreParam = strdup(str);
    char *scoreArg = NULL;
    char *e;
    *score = 0;
    *scoreOperator = -1;
    if ((scoreArg = strchr(scoreParam, '{'))) {
        *scoreArg = '\0';
        scoreArg++;
        if ((e = strchr(scoreArg, '}')))
            *e = '\0';
    }
    if (strcasecmp(scoreParam, "score") != 0 || !scoreArg) {
        ci_debug_printf(1, "Expecting 'score{...}' argument, got '%s'\n", scoreParam);
        free(scoreParam);
        return NULL;
    }
    ci_debug_printf(4, "Score parameter: %s argument:%s\n", scoreParam, scoreArg);
    size_t pos = strcspn(scoreArg, ">=<");
    char *op = scoreArg + pos;
    if (*op != '\0') {
        *scoreOperator = *op == '>' ? CF_OP_GREATER : (*op == '<' ? CF_OP_LESS : CF_OP_EQUAL);
        *op = '\0';
        if (*(op + 1) != '\0')
            *score = strtol(op + 1, NULL, 10);
    } else {
        *scoreOperator = CF_OP_GREATER;
    }
    if (FILTERS && !(fd = ci_ptr_dyn_array_search(FILTERS, scoreArg))) {
        ci_debug_printf(1, "Filter definition for '%s' not found\n", scoreArg);
    }
    /* End of parsing, free temporary buffer*/
    free(scoreParam);

    return fd;
}


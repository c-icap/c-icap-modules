#include "common.h"
#include "c-icap.h"
#include "array.h"
#include "module.h"
#include "lookup_table.h"
#include "commands.h"
#include "debug.h"
#include "util.h"

#include <tcutil.h>
#include <tcadb.h>

int init_tc_tables(struct ci_server_conf *server_conf);
void release_tc_tables();

static common_module_t tc_module = {
    "tc_tables",
    init_tc_tables,
    NULL,
    release_tc_tables,
    NULL,
};
_CI_DECLARE_COMMON_MODULE(tc_module)


void *tc_table_open(struct ci_lookup_table *table);
void  tc_table_close(struct ci_lookup_table *table);
void *tc_table_search(struct ci_lookup_table *table, void *key, void ***vals);
void  tc_table_release_result(struct ci_lookup_table *table_data,void **val);

struct ci_lookup_table_type tc_table_type = {
    tc_table_open,
    tc_table_close,
    tc_table_search,
    tc_table_release_result,
    NULL,
    "tc"
};


int init_tc_tables(struct ci_server_conf *server_conf)
{
    return (ci_lookup_table_type_register(&tc_table_type) != NULL);
}

void release_tc_tables()
{
    ci_debug_printf(3, "Module tc_table is going down\n");
    ci_lookup_table_type_unregister(&tc_table_type);
}

/***********************************************************/
/*  tc_table_type inmplementation                         */

typedef struct tc_data {
    TCADB *db;
    char *name;
    char *options;
    int stat_failures;
    int stat_hit;
    int stat_miss;
} tc_data_t;

static int check_suffix(const char *path, const char *suffix)
{
    _CI_ASSERT(*suffix == '.');
    const char *ss = strrchr(path, '.');
    if (!ss)
        return 0;
    return (strcmp(ss, suffix) == 0) ? 1 : 0;
}

void *tc_table_open(struct ci_lookup_table *table)
{
    int i;
    ci_dyn_array_t *args = NULL;
    const ci_array_item_t *arg = NULL;

    const int isBtree = check_suffix(table->path, ".tcb");
    const int isHash = check_suffix(table->path, ".tch");
    if (!isBtree && !isHash) {
        ci_debug_printf(1, "Only btree or hash based Tokyo Cabinet databases are supported.\nThe databases of type hash must be suffixed with '.tch' and database of type btree must be suffixed with '.tcb'\n");
        return NULL;
    }

    tc_data_t *dbdata = (tc_data_t *)calloc(1, sizeof(tc_data_t));
    if (!dbdata)
        return NULL;

    table->data = dbdata;
    dbdata->db = 0;
    dbdata->name = NULL;
    dbdata->options = NULL;

    if (table->args) {
        if ((args = ci_parse_key_value_list(table->args, ','))) {
            for (i = 0; (arg = ci_dyn_array_get_item(args, i)) != NULL; ++i) {
                if (strcasecmp(arg->name, "name") == 0) {
                    dbdata->name = strdup(arg->value);
                } else if (strcasecmp(arg->name, "options") == 0) {
                    dbdata->options = strdup(arg->value);
                } else {
                    ci_debug_printf(1, "WARNING:tc_table_open, db '%s', wrong parameter '%s=%s', ignoring\n", table->path, arg->name, (char *)arg->value);
                }
            }
        }
    }

    char buf[512];
    snprintf(buf, sizeof(buf), "tc(%s:%s)_errors",table->path, dbdata->name);
    dbdata->stat_failures = ci_stat_entry_register(buf, CI_STAT_INT64_T, "tc_lookup_table");
    snprintf(buf, sizeof(buf), "tc(%s:%s)_hits",table->path, dbdata->name);
    dbdata->stat_hit = ci_stat_entry_register(buf, CI_STAT_INT64_T, "tc_lookup_table");
    snprintf(buf, sizeof(buf), "tc(%s:%s)_miss",table->path, dbdata->name);
    dbdata->stat_miss = ci_stat_entry_register(buf, CI_STAT_INT64_T, "tc_lookup_table");
    dbdata->db = tcadbnew();
    char openpath[8192];
    snprintf(openpath, sizeof(openpath), "%s#mode=r%s%s",
             table->path,
             dbdata->options ? "#" : "",
             dbdata->options ? dbdata->options : ""
        );
    if (!tcadbopen(dbdata->db, openpath)) {
        tcadbdel(dbdata->db);
        dbdata->db = NULL;
        return NULL;
    }
    return dbdata;
}

void  tc_table_close(struct ci_lookup_table *table)
{
    tc_data_t *dbdata;
    dbdata = table->data;
    tcadbclose(dbdata->db);
    tcadbdel(dbdata->db);
    dbdata->db = NULL;
    free(dbdata);
}

void *tc_table_search(struct ci_lookup_table *table, void *key, void ***vals)
{
    tc_data_t *dbdata = (tc_data_t *)table->data;

    if (!dbdata) {
        ci_debug_printf(1,"table %s is not initialized?\n", table->path);
        ci_stat_uint64_inc(dbdata->stat_failures, 1);
        return NULL;
    }

    if (!dbdata->db) {
        ci_debug_printf(1,"table %s is not open?\n", table->path);
        ci_stat_uint64_inc(dbdata->stat_failures, 1);
        return NULL;
    }

    void *value = NULL;
    int value_size = 0;
    int key_size = table->key_ops->size(key);
    if ((value = tcadbget(dbdata->db, key, key_size, &value_size)) == NULL) {
        ci_stat_uint64_inc(dbdata->stat_miss, 1);
        ci_debug_printf(5, "tc_table_search: key does not exists\n");
        return NULL;
    }

    if (value_size) {
        if (ci_flat_array_size(value) <= value_size && ci_flat_array_check(value)) {
            *vals = ci_flat_array_to_ppvoid(value, NULL);
            if (!(*vals)) {
                if (value)
                    ci_buffer_free(value);
                ci_debug_printf(1, "Error while parsing data in lmdb_table_search.Is this a c-icap lmdb table?\n");
                ci_stat_uint64_inc(dbdata->stat_failures, 1);
            }
        }
    }
    ci_stat_uint64_inc(dbdata->stat_hit, 1);
    return key;
}

void  tc_table_release_result(struct ci_lookup_table *table,void **val)
{
    free(val);
}

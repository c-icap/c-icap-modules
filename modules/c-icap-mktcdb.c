#include "common.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <ctype.h>
#include "c-icap.h"
#include "lookup_table.h"
#include "cfg_param.h"
#include "debug.h"
#include "util.h"
#include <tcutil.h>
#include <tcadb.h>

#include <assert.h>


TCADB *db = NULL;
const ci_type_ops_t *key_type = &ci_str_ops;
const ci_type_ops_t *val_type = &ci_str_ops;

#define MAXLINE 65535

char *INFILE = NULL;
char *DBNAME = NULL;
char *DBPATH = NULL;
char *OPTIONS= NULL;
int ERASE_MODE = 0;
int DUMP_MODE = 0;
int VERSION_MODE = 0;

ci_mem_allocator_t *allocator = NULL;
int cfg_set_type(const char *directive, const char **argv, void *setdata);
int cfg_version(const char *directive, const char **argv, void *setdata);

static struct ci_options_entry options[] = {
    {"-V", NULL, &VERSION_MODE, cfg_version, "Print version and exits"},
    {
        "-d", "debug_level", &CI_DEBUG_LEVEL, ci_cfg_set_int,
        "The debug level"
    },
    {
        "-i", "in_file", &INFILE, ci_cfg_set_str,
        "The input file to load key/value pairs"
    },
    {
        "-p", "db_path.[tcb|tch]", &DBPATH, ci_cfg_set_str,
        "The database file path (required). Use .tcb suffix for btree and .tch for hash."
    },
    {
        "-o", "options", &OPTIONS, ci_cfg_set_str,
        "The database options to use separated by a '#'. One or more of the 'bnum', 'apow', 'fpow', 'opts', 'rcnum', 'xmsiz', and 'dfunit' for hash databases of one or more from 'lmemb', 'nmemb', 'bnum', 'apow', 'fpow', 'opts', 'lcnum', 'ncnum', 'xmsiz', and 'dfunit' for btree databases."
    },
    {
        "-t", "string|int|ip",NULL, cfg_set_type,
        "The type of the key (default is string)"
    },
    {
        "-v", "string|int|ip", NULL, cfg_set_type,
        "The type of values (default is string)"
    },
    {
        "--dump", NULL, &DUMP_MODE, ci_cfg_enable,
        "Do not update the database just dump it to the screen"
    },
    {
        "--erase", NULL, &ERASE_MODE, ci_cfg_enable,
        "Erase the keys/items listed in input file"
    },
    {NULL, NULL, NULL, NULL}
};

static int check_suffix(const char *path, const char *suffix)
{
    assert(*suffix == '.');
    const char *ss = strrchr(path, '.');
    if (!ss)
        return 0;
    return (strcmp(ss, suffix) == 0) ? 1 : 0;
}

int open_db()
{
    const int isBtree = check_suffix(DBPATH, ".tcb");
    const int isHash = check_suffix(DBPATH, ".tch");
    if (!isBtree && !isHash) {
        ci_debug_printf(1, "Only btree or hash based Tokyo Cabinet databases are supported.\nThe databases of type hash must be suffixed with '.tch' and database of type btree must be suffixed with '.tcb'\n");
        return 0;
    }

    /* * Create an environment and initialize it for additional error * reporting. */
    db = tcadbnew();
    char openpath[8192];
    snprintf(openpath, sizeof(openpath),
             "%s#mode=%s%s%s",
             DBPATH, (ERASE_MODE ? "w" :(INFILE != NULL ? "cw" : "r" )),
             OPTIONS ? "#" : "",
             OPTIONS ? OPTIONS : ""
        );
    if (!tcadbopen(db, openpath)) {
        ci_debug_printf(5, "tc_table_open: open string: '%s' is failed\n", openpath);
        tcadbdel(db);
        db = NULL;
        return 0;
    }
    ci_debug_printf(5, "tc_table_open: file %s created OK.\n", DBPATH);
    return 1;
}

void close_db()
{
    tcadbclose(db);
    tcadbdel(db);
}

int dump_db()
{
    int i;
    ci_debug_printf(4, "Going to dump database!\n");

    if (key_type != &ci_str_ops ||val_type != &ci_str_ops) {
        ci_debug_printf(1, "can not dump not string databases\n");
        return 0;
    }

    int records = 0, errors = 0;
    void *key, *flat;
    int key_size, flat_size;
    tcadbiterinit(db);
    while ((key = tcadbiternext(db, &key_size))) {
        records++;
        flat = tcadbget(db, key, key_size, &flat_size);
        printf("%s : ", (char *)key);
        if (ci_flat_array_size(flat) > flat_size || !ci_flat_array_check(flat)) {
            errors++;
            printf(" unknown_data_of_size_%d", (int)flat_size);
        } else {
            size_t item_size;
            const void *item;
            for (i = 0; (item = ci_flat_array_item(flat, i, &item_size)) != NULL; i++) {
                const char *val = (char *)(item);
                printf("%s'%s'", (i > 0 ? "| " : ""), val);
            }
        }
        printf("\n");
    }
    return 1;
}

int store_db(const void *key, int keysize, const void *val, int  valsize)
{
    static const char *zero = "";
    if (!val) {
        /*kyoto library does not allow null values, even if the
          value size is zero*/
        _CI_ASSERT(valsize == 0);
        val = zero;
    }
    if (!tcadbput(db, key, keysize, val, valsize)) {
        ci_debug_printf(1, "tcbdbput, key size:%d, val size:%d store error\n",
                        keysize, valsize);
        return 0;
    }
    return 1;
}

int erase_from_db(void *key, int keysize)
{
    if (!tcadbout(db, key, keysize)) {
        ci_debug_printf(1, "tcadbdel, key size:%d, store error\n", keysize);
        return 0;
    }
    return 1;
}

int cfg_set_type(const char *directive, const char **argv, void *setdata)
{
    const ci_type_ops_t *ops = &ci_str_ops;

    if (argv[0] == NULL) {
        ci_debug_printf(1, "error not argument for %s argument\n", argv[0]);
        return 0;
    }

    if (0 == strcmp(argv[0], "string")) {
        ops = &ci_str_ops;
    } else if (0 == strcmp(argv[0], "int")) {
        ci_debug_printf(1, "%s: not implemented type %s\n", directive, argv[0]);
        return 0;
    } else if (0 == strcmp(argv[0], "ip")) {
        ci_debug_printf(1, "%s: not implemented type %s\n", directive, argv[0]);
        return 0;
    }

    if (0 == strcmp(directive, "-t")) {
        key_type = ops;
    } else if (0 == strcmp(directive, "-v")) {
        val_type = ops;
    }
    return 1;
}

int cfg_version(const char *directive, const char **argv, void *setdata)
{
    if (setdata)
        *((int *) setdata) = 1;
    printf("c-icap-modules-%s / c-icap-%s\n", PACKAGE_VERSION, ci_lib_version_string());
    return 1;
}

void log_errors(void *unused, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
}

void vlog_errors(void *unused, const char *format, va_list ap)
{
    vfprintf(stderr, format, ap);
}




int main(int argc, char **argv)
{
    FILE *f = NULL;
    char line[MAXLINE];
    void *key, *val;
    size_t keysize, valsize;

    CI_DEBUG_LEVEL = 1;
    ci_mem_init();
    ci_cfg_lib_init();

    if (!ci_args_apply(argc, argv, options) || (!DBPATH && !DUMP_MODE && !VERSION_MODE)) {
        ci_args_usage(argv[0], options);
        exit(-1);
    }
    if (VERSION_MODE)
        exit(0);

#if ! defined(_WIN32)
    __log_error = (void (*)(void *, const char *,...)) log_errors;     /*set c-icap library log  function */
#else
    __vlog_error = vlog_errors;        /*set c-icap library  log function for win32..... */
#endif

    if (!(allocator = ci_create_os_allocator())) {
        ci_debug_printf(1, "Error allocating mem allocator!\n");
        return -1;
    }

    if (DUMP_MODE && !DBPATH) {
        ci_debug_printf(1, "\nError: You need to specify the database to dump ('-o file.db')\n\n");
        ci_args_usage(argv[0], options);
        exit(-1);
    }

    if (!open_db()) {
        ci_debug_printf(1, "Error opening lmdb database %s\n", DBPATH);
        if (f)
            fclose(f);
        return -1;
    }

    if (DUMP_MODE) {
        dump_db();
    } else {
        if ((f = fopen(INFILE, "r+")) == NULL) {
            ci_debug_printf(1, "Error opening file: %s\n", INFILE);
            return -1;
        }

        unsigned lines = 0, stored = 0, parse_fails = 0, store_fails = 0, removed = 0, removed_fails = 0;
        while (fgets(line,MAXLINE,f)) {
            lines++;
            line[MAXLINE-1]='\0';
            ci_vector_t *values = NULL;
            if (ci_parse_key_mvalues(line, ':', ',', key_type, val_type, &key, &keysize,  &values) < 0) {
                ci_debug_printf(1, "Error parsing line : %s\n", line);
                parse_fails++;
                break;
            } else if (key && keysize) {
                if (ERASE_MODE) {
                    if (erase_from_db(key, keysize))
                        removed++;
                    else
                        removed_fails++;
                } else {
                    val = values ? ci_flat_array_build_from_vector(values) : NULL;
                    valsize = val ? ci_flat_array_size(val) : 0;
                    if (store_db(key, keysize, val, valsize))
                        stored++;
                    else
                        store_fails++;
                }
                if (key) {
                    allocator->free(allocator, key);
                    key = NULL;
                }
                if (values) {
                    ci_vector_destroy(values);
                    values = NULL;
                }
                if (val) {
                    ci_buffer_free(val);
                    val = NULL;
                }
            }
        }
        fclose(f);
        ci_debug_printf(1, "Lines processed %u\n", lines);
        ci_debug_printf(1, "Lines ignored (comments, blank lines, parse errors etc) %u\n", parse_fails);
        ci_debug_printf(1, "Stored keys %u\n", stored);
        ci_debug_printf(1, "Removed keys %u\n", removed);
        ci_debug_printf(1, "Failed to store keys %u\n", store_fails);
        ci_debug_printf(1, "Failed to removed keys %u\n", removed_fails);
    }

    close_db();
    ci_mem_allocator_destroy(allocator);
    return 0;
}

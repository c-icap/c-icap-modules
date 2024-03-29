#include "../../common.h"
#include "c_icap/mem.h"
#include "c_icap/debug.h"
#ifdef BUILD_SGUARD_TOOL
#include "c_icap/cfg_param.h"
#include <assert.h>
#endif
#include "sguardDB.h"

#if defined(HAVE_BDB)
extern sg_db_type_t BDB_TYPE;
#endif
#if defined(HAVE_LMDB)
extern sg_db_type_t LMDB_TYPE;
#endif
sg_db_type_t *ForceType = NULL;

const sg_db_type_t *db_type_to_use(const char *db_path)
{
    struct stat file;
    char dbFile[CI_MAX_PATH];
#if defined(HAVE_LMDB)
    snprintf(dbFile, sizeof(dbFile), "%s/data.mdb", db_path);
    if (stat(dbFile, &file) == 0) /*Looks like an LMDB database*/
        return &LMDB_TYPE;
#endif
#if defined(HAVE_BDB)
    int isBDB = 0;
    snprintf(dbFile, sizeof(dbFile), "%s/domains.db", db_path);
    if (stat(dbFile, &file) == 0) /*Squard with Berkeley DB database*/
        isBDB = 1;
    else {
        snprintf(dbFile, sizeof(dbFile), "%s/urls.db", db_path);
        if (stat(dbFile, &file) == 0) /*Squard with Berkeley DB with only urls database*/
            isBDB = 1;
    }
    if (isBDB)
        return &BDB_TYPE;
#endif

    /*There is not existing database, maybe we are going to build a new one.
      By default prefer to use an lmdb database.
     */

    if (ForceType)
        return ForceType;

#if defined(HAVE_LMDB)
    return &LMDB_TYPE;
#endif
#if defined(HAVE_BDB)
    return &BDB_TYPE;
#endif
    return NULL;
}

sg_db_t *sg_init_db(const char *name, const char *home, enum sgDBopen otype)
{
    sg_db_t *sg_db;
    char buf[256];
    const sg_db_type_t *db_type = db_type_to_use(home);
    if (!db_type) {
        ci_debug_printf(1, "ERROR: Not a valid Database System is implemented/supported for  Sguard-like databases\n");
        return NULL;
    }

    sg_db = (sg_db_t *)calloc(1, sizeof(sg_db_t));
    if(!sg_db)
	return NULL;

    sg_db->domains_db_name = NULL;
    sg_db->urls_db_name = NULL;
    sg_db->db_home = NULL;
    sg_db->db_type = db_type;
    sg_db->data = db_type->init_db(home, otype);
    if (!sg_db->data) {
        /*Error messages should already generated by init_db*/
        free(sg_db);
        return NULL;
    }

    snprintf(buf, 256, "%s/domains", (name?name:""));
    buf[255] = '\0';
    sg_db->domains_db_name = strdup(buf);
    snprintf(buf, 256, "%s/urls", (name?name:""));
    buf[255] = '\0';
    sg_db->urls_db_name = strdup(buf);
    sg_db->db_home = strdup(home);
    ci_debug_printf(3, "Sguard DBs for %s at path '%s' opened successfully\n", name, home);
    return sg_db;
}

void sg_close_db(sg_db_t *sg_db)
{
    sg_db->db_type->close_db(sg_db->data);
    sg_db->data = NULL;

    if (sg_db->domains_db_name)
        free(sg_db->domains_db_name);
    if (sg_db->urls_db_name)
        free(sg_db->urls_db_name);
    if(sg_db->db_home)
        free(sg_db->db_home);

    free(sg_db);
}

int compdomainkey(const char *dkey, const char *domain, int dkey_len)
{
    int domain_len=strlen(domain);
    const char *d_end,*k_end;

    if(domain_len<dkey_len-1)
	return 1;

    k_end=dkey+dkey_len;
    d_end=domain+domain_len;

    do {
	d_end--;
	k_end--;
	if(*d_end!=*k_end)
            return d_end-k_end;
    } while(d_end>domain && k_end>dkey);

    if(*k_end=='.' && *d_end=='.')
        return 0;
    if(d_end==domain && *(--k_end)=='.')
        return 0;
    return 1;
}

int compurlkey(const char *ukey, const char *url, int ukey_len)
{
    return strncmp(ukey, url, ukey_len);
}


int sg_domain_exists(sg_db_t *sg_db, char *domain)
{
    if (!sg_db->data || !sg_db->db_type)
        return 0;

    return sg_db->db_type->entry_exists(sg_db->data, sgDomain, domain, compdomainkey);
}

int sg_url_exists(sg_db_t *sg_db, char *url)
{
    char  *s;
    if (!sg_db->data || !sg_db->db_type)
        return 0;

    /*squidGuard removes the www[0-9]*, ftp[0-9]* and web[0-9]*
      prefixes from urls*/
    if ( (url[0] == 'w' && url[1] == 'w' && url[2] == 'w') ||
         (url[0] == 'w' && url[1] == 'e' && url[2] == 'b') ||
         (url[0] == 'f' && url[1] == 't' && url[2] == 'p') ) {
        s = url + 3;
        while ( *s >= '0' && *s <= '9') s++;
        if (*s == '.')
            url = s+1;
    }
    return sg_db->db_type->entry_exists(sg_db->data, sgUrl, url, compurlkey);
}

/**************************************************************/
#ifdef BUILD_SGUARD_TOOL



static char *prepare_entry(char *url, int type)
{
    char *s, *d, *a, *p;

    /*The first char must be a space!*/
    assert(url[0] == ' ');
    /*ignore spaces*/
    while(*url != '\0' && isspace(*url)) url++;

    if (*url == '#')
        return NULL; /*it is a comment*/

    if (type == sgDomain && *url != '.') {
        /*if it is domain we need a '.' at the beggining*/
        --url;
        *url = '.';
    }

    /*convert to lower case:*/
    for (s= url, d = url; *d != '\0'; s++, d++)
        *d = tolower(*s);

    /*d now points at the end of string, strip spaces at the end of string*/
    while ((--d) > url && isspace(*d)) *d = '\0';

    if (type == sgUrl) {
        /*We need to strip out authentication and port info*/
        p = strchr(url, '/');
        a = strchr(url, '@');
        if (a && (a < p || p == NULL) )
            url = a + 1; /*remove the authentication info at the beggining*/

        /*Try to see if there is port part*/
        d = strchr(url, ':');
        if (d && p == NULL) /*No path*/
            *d = '\0'; /*Cut here to keep only domain hostname*/
        else if (d && d < p) {
            while(*p != '0') *d++ = *p++; /*Copy path over port info*/
        }
    }

    return url;
}

static int db_update_from_file(sg_db_t *db, const char *file, int mode, int type)
{
    char buffer[8192], *s;
    FILE *f;
    if (!db->data || !db->db_type)
        return 0;

    ci_debug_printf(4, "sguard/db_update_from_file: going to update from '%s'\n", file);
    if ((f = fopen(file, "r+")) == NULL) {
        ci_debug_printf(1, "Error opening file: %s\n", file);
        return 0;
    }
    if (db->db_type->start_modify)
        db->db_type->start_modify(db->data);
    while(!feof(f)) {
        buffer[0] =' ';

        if (!fgets(buffer+1, sizeof(buffer) - 1, f))
            break;

        buffer[sizeof(buffer) - 1] = '\0';
        if (mode == sgDBupdate) {
            if (buffer[1] == '+') {
                buffer[1] = ' ';
                s = prepare_entry(buffer, type);
                if (s)
                    db->db_type->entry_add(db->data, type, s);
            } else if (buffer[1] == '-') {
                buffer[1] = ' ';
                s = prepare_entry(buffer, type);
                if (s) {
                    db->db_type->entry_remove(db->data, type, s);
                }
            } else {
                /*Just ignore*/
                ci_debug_printf(3, "Ignore line: %s \n", buffer);
            }
        }
        else if (mode == sgDBrebuild){
            s = prepare_entry(buffer, type);
            if (s)
                db->db_type->entry_add(db->data, type, s);
        }
    }
    if (db->db_type->start_modify)
        db->db_type->stop_modify(db->data);
    fclose(f);
    return 1;
}

int dbUpdate( const char *dbhome, const char *fname, int updatetype)
{
    char path[CI_MAX_PATH];
    sg_db_t *l_db;
    int onlydomains = 0, onlyurls = 0;
    if (!fname)
        /*do nothing*/;
    else if (strcmp(fname, "urls") == 0)
        onlyurls = 1;
    else if (strcmp(fname, "domains") == 0)
        onlydomains = 1;

    l_db = sg_init_db("LocalName", dbhome, updatetype);
    if (!l_db)
        return -1;

    if (!onlyurls) {
        snprintf(path, CI_MAX_PATH, "%s/domains%s", dbhome, updatetype==sgDBupdate? ".diff":"");
        db_update_from_file(l_db, path, updatetype, sgDomain);
    }

    if (!onlydomains) {
        snprintf(path, CI_MAX_PATH, "%s/urls%s", dbhome, updatetype==sgDBupdate? ".diff":"");
        db_update_from_file(l_db, path, updatetype, sgUrl);
    }

    sg_close_db(l_db);
    return 0;
}

int urlSearch( sg_db_t *l_db, const char *fname, char *url)
{
    char domain[512];
    int i;
    int onlydomains = 0, onlyurls = 0;

    if (!fname)
        ;
    else  if (strcmp(fname, "urls") == 0)
        onlyurls = 1;
    else if (strcmp(fname, "domains") == 0)
        onlydomains = 1;

    if (!onlydomains) {
        if (sg_url_exists(l_db, url) ) {
            ci_debug_printf(2, "Found %s in urls db\n", url);
            return 0;
        }
    }

    if (!onlyurls) {
        for (i = 0; i < (sizeof(domain) -1) && url[i] != '\0' && url[i] != '/'; i++)
            domain[i] = url[i];
        domain[i] = '\0';

        if (sg_domain_exists(l_db, domain)) {
            ci_debug_printf(2, "Found %s in domains db\n", domain);
            return 0;
        }
    }

    return -1;
}

int print_url(const char *key, int keysize, const char *data, int datasize)
{
    printf("\t%*s\n", keysize, key);
    return 1;
}

int dbDump( sg_db_t *l_db, const char *fname)
{
    int onlydomains = 0, onlyurls = 0;
    if (fname) {
        if (strcmp(fname, "urls") == 0)
            onlyurls = 1;
        else if (strcmp(fname, "domains") == 0)
            onlydomains = 1;
    }

    if (!onlyurls) {
        printf("DOMAINS:\n");
        l_db->db_type->iterate(l_db->data, sgDomain, print_url);
    }

    if (!onlydomains) {
        printf("URLS:\n");
        l_db->db_type->iterate(l_db->data, sgUrl, print_url);
    }
    return 0;
}

static int cfg_select_dbtype(const char *directive, const char **argv, void *setdata)
{
    if (argv == NULL || argv[0] == NULL) {
        return 0;
    }
#if defined(HAVE_BDB)
    if (strcasecmp(argv[0], "bdb") == 0) {
        ForceType= &BDB_TYPE;
        return 1;
    }
#endif
#if defined(HAVE_LMDB)
    if (strcasecmp(argv[0], "lmdb") == 0) {
        ForceType= &LMDB_TYPE;
        return 1;
    }
#endif
    return 0;
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

char *sgDB = NULL;
char *sgDBFILE = NULL;
char *URL = NULL;
int HELP_MODE = 0;
int DUMP_MODE = 0;
int CREATE_MODE = 0;
int UPDATE_MODE = 0;
int SEARCH_MODE = 0;
#if defined(HAVE_LMDB)
extern size_t MAX_LMDB_SIZE;
long int CFG_SET_MAX_LMDB_SIZE = 0;
#endif

static struct ci_options_entry options[] = {
    {"-h", NULL, &HELP_MODE, ci_cfg_enable, "Show this help"},
    {"-d", "debug_level", &CI_DEBUG_LEVEL, ci_cfg_set_int,
     "The debug level"},
    {"-db", "dbpath", &sgDB, ci_cfg_set_str,
     "The database path (required)"},
    {"-f", "urls|domains", &sgDBFILE, ci_cfg_set_str,
     "Select database table to operate, \"urls\" or \"domains\" table"},
    {"-C", NULL, &CREATE_MODE, ci_cfg_enable,
     "Create the database"},
    {"-T", "bdb|lmdb", NULL, cfg_select_dbtype,
     "Force BerkeleyDB or LMDB database type when building new database"
    },
#if defined(HAVE_LMDB)
    {
        "-S", "max-size", &CFG_SET_MAX_LMDB_SIZE, ci_cfg_size_long,
        "Sets the maximum database size. For LMDB databases only."
    },
#endif
    {"-u", NULL, &UPDATE_MODE, ci_cfg_enable,
     "Update the database from diff files"},
    {"-s", "url", &URL, ci_cfg_set_str,
     "Search in the database for the given url"},
    {"--dump", NULL, &DUMP_MODE, ci_cfg_enable,
     "Do not update the database just dump it to the screen"},
    {NULL, NULL, NULL, NULL}
};

int main(int argc, char *argv[])
{
    sg_db_t *l_db = NULL;
    int ret, modes;
    CI_DEBUG_LEVEL = 1;
#if ! defined(_WIN32)
    __log_error = (void (*)(void *, const char *,...)) log_errors;     /*set c-icap library log  function */
#else
    __vlog_error = vlog_errors;        /*set c-icap library  log function for win32..... */
#endif
    ci_mem_init();
    ci_cfg_lib_init();

    if (!ci_args_apply(argc, argv, options) || HELP_MODE) {
        ci_args_usage(argv[0], options);
        exit(-1);
    }

#if defined(HAVE_LMDB)
    if (CFG_SET_MAX_LMDB_SIZE)
        MAX_LMDB_SIZE = CFG_SET_MAX_LMDB_SIZE;
#endif

    if (URL)
        SEARCH_MODE = 1;

    modes = DUMP_MODE + UPDATE_MODE + CREATE_MODE + SEARCH_MODE;
    if (modes != 1) {
        ci_debug_printf(1, "\n%s one from the \"-C\", \"-u\", \"-s\" or \"--dump\" arguments must be specified.\nUse -h to see your options\n", modes == 0? "At least" : "Only");
        exit(-1);
    }

    if (!sgDB && ! HELP_MODE) {
        ci_debug_printf(1, "\nThe \"-db\" argument is required. Use -h to see your options\n");
        exit(-1);
    }

    if(CREATE_MODE) {
        return dbUpdate(sgDB, sgDBFILE, sgDBrebuild);
    }

    if (UPDATE_MODE) {
        return dbUpdate(sgDB, sgDBFILE, sgDBupdate);
    }

    /*Open Database to operate on*/
    l_db=sg_init_db("LocalName", sgDB, 0);
    if (!l_db) {
        ci_debug_printf(1, "Can not open database: %s\n", sgDB);
        exit(-1);
    }

    ret = 0;
    if(SEARCH_MODE) {
        printf("Search in database for \"%s\" ... ", URL);
        ret = urlSearch(l_db, sgDBFILE, URL);
        if (ret == 0) {
            printf("Found\n");
        } else {
            printf("Not found\n");
        }
    } else if (DUMP_MODE)
        ret = dbDump(l_db, sgDBFILE);

    if (l_db)
        sg_close_db(l_db);

    return ret;
}

#endif

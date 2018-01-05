#include "c_icap/mem.h"
#include "c_icap/debug.h"
#include "../../common.h"
#ifdef BUILD_SGUARD_TOOL
#include "c_icap/cfg_param.h"
#include <assert.h>
#endif
#include "sguardDB.h"

#define CREATE_FLAGS 0664
#define TABLE        NULL

int domainCompare (DB *dbp, const DBT *a, const DBT *b)
{
    const char *a1 , *b1;
    char ac1 , bc1;
    a1=(char *) a->data + a->size - 1;
    b1=(char *) b->data + b->size - 1;
    while (*a1 == *b1){
	if(b1 == b->data || a1 == a->data)
	    break;
	a1--; b1--;
    }
    ac1 = *a1 == '.' ? '\1' : *a1;
    bc1 = *b1 == '.' ? '\1' : *b1;
    if(a1 == a->data && b1 == b->data)
	return ac1 - bc1;
    if(a1 == a->data)
	return -1;
    if(b1 == b->data)
	return 1;
    return ac1 - bc1;
}

DB_ENV *db_setup(const char *home)
{
    DB_ENV *dbenv;
    int ret;

    /* * Create an environment and initialize it for additional error * reporting. */
    if ((ret = db_env_create(&dbenv, 0)) != 0) {
	return (NULL);
    }
    ci_debug_printf(5,"Environment created OK.\n");


//	dbenv->set_data_dir(dbenv, "");
    dbenv->set_data_dir(dbenv, home);
    ci_debug_printf(5,"Data dir set to %s.\n", home);
    /*
      dbenv->set_shm_key(dbenv, 888888L);
      ci_debug_printf(5,"Shared memory set.\n");
    */
    /* * Specify the shared memory buffer pool cachesize: 5MB. * Databases are in a subdirectory of the environment home. */
    //     if ((ret = dbenv->set_cachesize(dbenv, 0, 5 * 1024 * 1024, 0)) != 0) {
    //	  dbenv->err(dbenv, ret, "set_cachesize");
    //	  goto err;
    //     }

    /* Open the environment  */
    if ((ret = dbenv->open(dbenv, home, DB_CREATE | DB_INIT_LOCK | DB_INIT_MPOOL|DB_THREAD /*| DB_SYSTEM_MEM*/, 0)) != 0){
	ci_debug_printf(1, "Environment open failed: %s\n", db_strerror(ret));
	dbenv->close(dbenv, 0);
	return NULL;
    }
    ci_debug_printf(5,"DB setup OK.\n");


    return (dbenv);
}

int remove_dbenv(char *home)
{
    DB_ENV *dbenv;
    int ret;

    if ((ret = db_env_create(&dbenv, 0)) != 0) {
	ci_debug_printf(1, " %s\n", db_strerror(ret));
	return 0;
    }
    if(dbenv->remove(dbenv, home, 0)!=0){
	ci_debug_printf(1, "Error removing environment....\n");
	return 0;
    }
    else
	ci_debug_printf(5, "OK removing environment\n");
    return 1;
}

DB *sg_open_db(DB_ENV *dbenv, char *filename, enum sgDBopen otype,
	       int (*bt_compare_fcn)(DB *, const DBT *, const DBT *) )
{
    int ret;
    uint32_t flags;
    DB *dbp = NULL;

    if ((ret = db_create(&dbp, dbenv , 0)) != 0) {
	ci_debug_printf(1, "db_create: %s\n", db_strerror(ret));
	return NULL;
    }
    //     dbp->set_flags(dbp, DB_DUP);
    if (bt_compare_fcn)
        dbp->set_bt_compare(dbp, bt_compare_fcn);


#if(DB_VERSION_MINOR>=1)
    if (otype == sgDBreadonly)
        flags = DB_RDONLY|DB_THREAD;
    else
        flags =DB_CREATE | DB_THREAD;

     if ((ret = dbp->open( dbp, NULL, filename, NULL,
			  DB_BTREE, flags, 0)) != 0)
#else
         if (otype == sgDBreadonly)
             flags = DB_RDONLY;
         else
             flags = DB_CREATE;

     if ((ret = dbp->open( dbp, filename, NULL,
                           DB_BTREE, flags, 0)) != 0)
#endif
     {
         ci_debug_printf(1, "open db %s: %s\n", filename, db_strerror(ret));
         dbp->close(dbp, 0);
         return NULL;
     }
    return dbp;
}

int SGDB_T_POOL = -1;

sg_db_t *sg_init_db(const char *name, const char *home, enum sgDBopen otype)
{
    sg_db_t *sg_db;
    char buf[256];

    if(SGDB_T_POOL < 0 )
	SGDB_T_POOL = ci_object_pool_register("sg_db_t", sizeof(sg_db_t));

    if(SGDB_T_POOL < 0 )
	return NULL;

    sg_db = ci_object_pool_alloc(SGDB_T_POOL);
    if(!sg_db)
	return NULL;

    sg_db->env_db=NULL;
    sg_db->domains_db=NULL;
    sg_db->urls_db=NULL;
    sg_db->domains_db_name = NULL;
    sg_db->urls_db_name = NULL;
    sg_db->db_home = NULL;

    sg_db->env_db = db_setup(home);
    if(sg_db->env_db==NULL){
	ci_object_pool_free(sg_db);
	return NULL;
    }

    sg_db->domains_db = sg_open_db(sg_db->env_db, "domains.db", otype, domainCompare);
    sg_db->urls_db = sg_open_db(sg_db->env_db, "urls.db", otype, NULL);

    if(sg_db->domains_db == NULL && sg_db->urls_db== NULL) {
	sg_close_db(sg_db);
	ci_object_pool_free(sg_db);
	return NULL;
    }

    snprintf(buf, 256, "%s/domains", (name?name:""));
    buf[255] = '\0';
    sg_db->domains_db_name = strdup(buf);
    snprintf(buf, 256, "%s/urls", (name?name:""));
    buf[255] = '\0';
    sg_db->urls_db_name = strdup(buf);
    sg_db->db_home = strdup(home);

    ci_debug_printf(5,"DBs opened\n");
    ci_debug_printf(5,"Finished initialisation\n");
    return sg_db;
}

void sg_close_db(sg_db_t *sg_db)
{
    if(sg_db->domains_db){
	sg_db->domains_db->close(sg_db->domains_db, 0);
	sg_db->domains_db = NULL;
    }

    if(sg_db->urls_db){
	sg_db->urls_db->close(sg_db->urls_db, 0);
	sg_db->urls_db = NULL;
    }

    if(sg_db->env_db){
	sg_db->env_db->close(sg_db->env_db, 0);
	sg_db->env_db=NULL;
    }

    if (sg_db->domains_db_name)
        free(sg_db->domains_db_name);
    if (sg_db->urls_db_name)
        free(sg_db->urls_db_name);
    if(sg_db->db_home)
        free(sg_db->db_home);

    ci_object_pool_free(sg_db);
}

int compdomainkey(char *dkey,char *domain,int dkey_len)
{
    int domain_len=strlen(domain);
    char *d_end,*k_end;

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

int compurlkey(char *ukey,char *url,int ukey_len)
{
    return strncmp(ukey,url,ukey_len);
}

static int db_entry_exists(DB *dDB, char *entry,int (*cmpkey)(char *,char *,int ))
{
    int ret,found=0;
    DBT key, data;
    DBC *L_dDBC;
	
    if ((ret = dDB->cursor(dDB, NULL, &L_dDBC, 0)) != 0) {
	ci_debug_printf(1, "db->cursor: %s\n", db_strerror(ret));
	return 0;
    }

    memset(&data, 0, sizeof(data));
    memset(&key, 0, sizeof(key));
    key.data = entry;
    key.size = strlen(entry);

    if ((ret = L_dDBC->c_get(L_dDBC, &key, &data, DB_SET_RANGE)) != 0){
	ci_debug_printf(5, "db_entry_exists: does not exists: %s\n", db_strerror(ret));
    }
    else{
	if((*cmpkey)((char*)key.data,entry,key.size)==0)
	    found = 1;
	else
	    if ((ret = L_dDBC->c_get(L_dDBC, &key, &data, DB_PREV)) == 0){/*Also check previous key*/
		if((*cmpkey)((char*)key.data,entry,key.size)==0)
		    found = 2;
	    }
    }
    if (found)
        ci_debug_printf(5, "db_entry_exists: Matching key: %s (step %d)\n", (char *) key.data, found);
    L_dDBC->c_close(L_dDBC);
    return found;
}

int sg_domain_exists(sg_db_t *sg_db, char *domain)
{
    if (!sg_db->domains_db)
        return 0;

    return db_entry_exists(sg_db->domains_db,domain,compdomainkey);
}

int sg_url_exists(sg_db_t *sg_db, char *url)
{
    char  *s;
    if (!sg_db->urls_db)
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
    return db_entry_exists(sg_db->urls_db,url,compurlkey);
}



int iterate_db(DB *dDB, int (*action)(char *,int,char *,int))
{
    int ret, count = 0;
    DBT key, data;
    DBC *L_dDBC;

    if ((ret = dDB->cursor(dDB, NULL, &L_dDBC, 0)) != 0) {
	ci_debug_printf(1, "db->cursor: %s\n", db_strerror(ret));
	return 0;
    }
    memset(&data, 0, sizeof(data));
    memset(&key, 0, sizeof(key));

    if ((ret = L_dDBC->c_get(L_dDBC, &key, &data, DB_FIRST)) != 0){
	L_dDBC->c_close(L_dDBC);
	return 0;
    }
    do{
	count ++;
	if(action)
	    (*action)((char *)(key.data),key.size,(char *)(data.data),data.size);
	ret = L_dDBC->c_get(L_dDBC, &key, &data, DB_NEXT);
    }while(ret==0);

    L_dDBC->c_close(L_dDBC);
    return count;
}


/**************************************************************/
#ifdef BUILD_SGUARD_TOOL

enum {sgDomain, sgUrl};

static int db_entry_add(DB *dDB, char *entry)
{
    int ret;
    DBT key, data;
    memset(&data, 0, sizeof(data));
    memset(&key, 0, sizeof(key));
    key.data = entry;
    key.size = strlen(entry);
    data.data = "";
    data.size = 1 ;
    ret = dDB->put(dDB, NULL, &key, &data, 0);
    if (ret !=0 ) {
	ci_debug_printf(1, "db_entry_add: Can not add entry \"%s\" %s\n", entry, db_strerror(ret));
	return 0;
    }

    return 1;
}

static int db_entry_remove(DB *dDB, char *entry)
{
    //Must use cursors ......
    DBT key, data;
    int ret, removed = 0;
    DBC *L_dDBC;
	
    if ((ret = dDB->cursor(dDB, NULL, &L_dDBC, 0)) != 0) {
	ci_debug_printf(1, "db_entry_remove: db->cursor: %s\n", db_strerror(ret));
	return 0;
    }

    memset(&data, 0, sizeof(data));
    memset(&key, 0, sizeof(key));
    key.data = entry;
    key.size = strlen(entry);

    if ((ret = L_dDBC->c_get(L_dDBC, &key, &data, DB_SET)) == 0){
	ci_debug_printf(5, "db_entry_remove: key exists, going to remove\n");
        ret = L_dDBC->c_del(L_dDBC, 0);
        if (ret != 0) {
            ci_debug_printf(1, "db_entry_remove: The entry \"%s\" can not removed: %s\n", entry, db_strerror(ret));
        } else
            removed = 1;
    }
    else {
        ci_debug_printf(5, "db_entry_remove: The entry \"%s\" does not exist: %s\n", entry, db_strerror(ret));
    }
    L_dDBC->c_close(L_dDBC);
    return removed;
}

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

static int db_update_from_file(DB *dDB, const char *file, int mode, int type)
{
    uint32_t *countp = 0;
    char buffer[8192], *s;
    FILE *f;

    if (type == sgDBappend)
        dDB->truncate(dDB, NULL, countp, 0);

    if ((f = fopen(file, "r+")) == NULL) {
        ci_debug_printf(1, "Error opening file: %s\n", file);
        return 0;
    }
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
                    db_entry_add(dDB, s);
            } else if (buffer[1] == '-') {
                buffer[1] = ' ';
                s = prepare_entry(buffer, type);
                if (s) {
                    db_entry_remove(dDB, s);
                }
            } else {
                /*Just ignore*/
                ci_debug_printf(3, "Ignore line: %s \n", buffer);
            }
        }
        else if (mode == sgDBappend){
            s = prepare_entry(buffer, type);
            if (s)
                db_entry_add(dDB, s);
        }
    }
    fclose(f);
    return 1;
}

int dbUpdate( const char *dbhome, const char *fname, int updatetype)
{
    char path[CI_MAX_PATH];
    sg_db_t *l_db;
    int onlydomains = 0, onlyurls = 0;
    if (!fname)
        ;
    else if (strcmp(fname, "urls") == 0)
        onlyurls = 1;
    else if (strcmp(fname, "domains") == 0)
        onlydomains = 1;

    l_db = sg_init_db("LocalName", dbhome, updatetype);
    if (!l_db)
        return -1;

    if (!onlyurls) {
        snprintf(path, CI_MAX_PATH, "%s/domains%s", dbhome, updatetype==sgDBupdate? ".diff":"");
        db_update_from_file(l_db->domains_db, path, updatetype, sgDomain);
    }

    if (!onlydomains) {
        snprintf(path, CI_MAX_PATH, "%s/urls%s", dbhome, updatetype==sgDBupdate? ".diff":"");
        db_update_from_file(l_db->urls_db, path, updatetype, sgUrl);
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

int print_url(char *key, int keysize, char *data, int datasize)
{
    key[keysize] = '\0';
    printf("\t%s\n", key);
    return 1;
}

int dbDump( sg_db_t *l_db, const char *fname)
{
    int onlydomains = 0, onlyurls = 0;
    if (strcmp(fname, "urls") == 0)
        onlyurls = 1;
    else if (strcmp(fname, "domains") == 0)
        onlydomains = 1;

    if (!onlyurls) {
        printf("DOMAINS:\n");
        iterate_db(l_db->domains_db, print_url);
    }

    if (!onlydomains) {
        printf("URLS:\n");
        iterate_db(l_db->urls_db, print_url);
    }
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
int DUMP_MODE = 0;
int CREATE_MODE = 0;
int UPDATE_MODE = 0;
int SEARCH_MODE = 0;

static struct ci_options_entry options[] = {
    {"-d", "debug_level", &CI_DEBUG_LEVEL, ci_cfg_set_int,
     "The debug level"},
    {"-db", "dbpath", &sgDB, ci_cfg_set_str,
     "The database path (required)"},
    {"-f", "file", &sgDBFILE, ci_cfg_set_str,
     "Select database file to operate (\"urls\" or \"domains\")"},
    {"-C", NULL, &CREATE_MODE, ci_cfg_enable,
     "Create the database"},
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
    ci_cfg_lib_init();

    if (!ci_args_apply(argc, argv, options) || !sgDB) {
        if (!sgDB)
            ci_debug_printf(1, "\nThe \"-db\" argument required\n\n");
        ci_args_usage(argv[0], options);
        exit(-1);
    }

    if (URL)
        SEARCH_MODE = 1;

    modes = DUMP_MODE + UPDATE_MODE + CREATE_MODE + SEARCH_MODE;
    if (modes != 1) {
        ci_debug_printf(1, "\n\n%s one from the \"-C\", \"-u\", \"-s\" or \"--dump\" arguments must be specified\n\n", modes == 0? "At least" : "Only");
        ci_args_usage(argv[0], options);
        exit(-1);
    }

    if(CREATE_MODE) {
        return dbUpdate(sgDB, sgDBFILE, sgDBappend);
    }

    if (UPDATE_MODE) {
        return dbUpdate(sgDB, sgDBFILE, sgDBupdate);
    }

    /*Open Database to operate on*/
    l_db=sg_init_db("LocalName", sgDB, 0);

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

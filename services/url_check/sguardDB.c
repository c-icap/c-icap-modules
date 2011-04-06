#include "sguardDB.h"
#include "mem.h"
#include "debug.h"
#include "../../common.h"
/*
DB_ENV *envDB;
DB *DomainsDB = NULL;
DB *UrlsDB = NULL;
*/


#define CREATE_FLAGS 0664
#define TABLE        NULL

int compare_str(DB *dbp, const DBT *a, const DBT *b)
{

    /* * Returns: 
     * < 0 if a < b 
     * = 0 if a = b 
     * > 0 if a > b 
     */ 
    return strcmp((char *)(a->data),(char *)(b->data)); 
}


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






DB *sg_open_db(DB_ENV *dbenv, char *filename,
	       int (*bt_compare_fcn)(DB *, const DBT *, const DBT *) )
{
    int ret;
    DB *dbp = NULL;

    if ((ret = db_create(&dbp, dbenv , 0)) != 0) {
	ci_debug_printf(1, "db_create: %s\n", db_strerror(ret));
	return NULL;
    }
    //     dbp->set_flags(dbp, DB_DUP);
    dbp->set_bt_compare(dbp, bt_compare_fcn);


#if(DB_VERSION_MINOR>=1)
    if ((ret = dbp->open( dbp, NULL, filename, NULL,
			  DB_BTREE, DB_RDONLY|DB_THREAD, 0)) != 0)
#else
	if ((ret = dbp->open( dbp, filename, NULL,
			      DB_BTREE, DB_RDONLY, 0)) != 0)
#endif
	{
	    ci_debug_printf(1, "open db %s: %s\n", filename, db_strerror(ret));
	    dbp->close(dbp, 0);
	    return NULL;
	}
    return dbp;
}

int SGDB_T_POOL = -1;

sg_db_t *sg_init_db(const char *name, const char *home)
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

    sg_db->env_db = db_setup(home);
    if(sg_db->env_db==NULL){
	ci_object_pool_free(sg_db);
	return NULL;
    }

    sg_db->domains_db = sg_open_db(sg_db->env_db, "domains.db", domainCompare);
    sg_db->urls_db = sg_open_db(sg_db->env_db, "urls.db", compare_str);

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
	ci_debug_printf(5, "db_entry_exists does not exists: %s\n", db_strerror(ret));
    }
    else{
	if((*cmpkey)((char*)key.data,entry,key.size)==0)
	    found = 1;
	else
	    if ((ret = L_dDBC->c_get(L_dDBC, &key, &data, DB_PREV)) == 0){/*Also check previous key*/
		if((*cmpkey)((char*)key.data,entry,key.size)==0)
		    found = 1;
	    }
    }
    if (found)
        ci_debug_printf(5, "db_entry_exists: Matching key: %s\n", (char *) key.data);
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
    if (!sg_db->urls_db)
        return 0;

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
#if 0


sg_db_t *l_db;
#define DATABASE_DIR    "/home/tsantila/sources/squidGuard-1.2.10/BUILD/squidGuard/db/blacklists/adult/"
#define DATABASEHOME  "/home/tsantila/sources/squidGuard-1.2.10/BUILD/squidGuard/db/blacklists/adult/"

int initDB(int  create)
{
    l_db=sg_init_db(DATABASEHOME);
    return 1;
}


void closeDB()
{
    if(!l_db)
	return;
    sg_close_db(l_db);
    free(l_db);
}

int DomainExists(char *domain)
{
    return sg_domain_exists(l_db,domain);
}

int UrlExists(char *url)
{
    return sg_url_exists(l_db,url);
}


int iterateDomains(int (*action)(char *,int,char *,int))
{
    return iterate_db(l_db->domains_db, action);
}

int iterateUrls(int (*action)(char *,int,char *,int))
{
    return iterate_db(l_db->urls_db, action);
}


#endif

#include "../../common.h"
#include "c_icap/debug.h"
#include "sguardDB.h"
#include BDB_HEADER_PATH(db.h)

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

static DB_ENV *setup_env_bdb(const char *home)
{
    DB_ENV *dbenv;
    int ret;

    /* Create an environment and initialize it for additional error reporting. */
    if ((ret = db_env_create(&dbenv, 0)) != 0) {
	return (NULL);
    }
    ci_debug_printf(5,"Environment created OK.\n");
    dbenv->set_data_dir(dbenv, home);
    ci_debug_printf(5,"Data dir set to %s.\n", home);
    if ((ret = dbenv->open(dbenv, home, DB_CREATE | DB_INIT_LOCK | DB_INIT_MPOOL | DB_THREAD /*| DB_SYSTEM_MEM*/, 0)) != 0) {
	ci_debug_printf(1, "Environment open failed: %s\n", db_strerror(ret));
	dbenv->close(dbenv, 0);
	return NULL;
    }
    ci_debug_printf(5,"DB setup OK.\n");
    return (dbenv);
}

static DB *open_db_bdb(DB_ENV *dbenv, char *filename, enum sgDBopen otype,
                           int (*bt_compare_fcn)(DB *, const DBT *, const DBT *) )
{
    int ret;
    uint32_t flags;
    DB *dbp = NULL;
    if ((ret = db_create(&dbp, dbenv , 0)) != 0) {
        ci_debug_printf(1, "db_create: %s\n", db_strerror(ret));
        return NULL;
    }
    if (bt_compare_fcn)
        dbp->set_bt_compare(dbp, bt_compare_fcn);

    if (otype == sgDBreadonly)
        flags = DB_RDONLY | DB_THREAD;
    else
        flags = DB_CREATE | DB_THREAD;

    if ((ret = dbp->open( dbp, NULL, filename, NULL, DB_BTREE, flags, 0)) != 0) {
        ci_debug_printf(1, "open db %s: %s\n", filename, db_strerror(ret));
        dbp->close(dbp, 0);
        return NULL;
    }
    if (otype == sgDBrebuild) {
        uint32_t countp = 0;
        dbp->truncate(dbp, NULL, &countp, 0);
    }
    return dbp;
}

typedef struct sg_bdb_data {
    DB_ENV *env_db;
    DB *domains_db;
    DB *urls_db;
} sg_bdb_data_t;

void sg_close_bdb(void *data)
{
    sg_bdb_data_t *sg_bdb = (sg_bdb_data_t *)data;
    if(sg_bdb->domains_db){
	sg_bdb->domains_db->close(sg_bdb->domains_db, 0);
	sg_bdb->domains_db = NULL;
    }
    if(sg_bdb->urls_db){
	sg_bdb->urls_db->close(sg_bdb->urls_db, 0);
	sg_bdb->urls_db = NULL;
    }
    if(sg_bdb->env_db){
	sg_bdb->env_db->close(sg_bdb->env_db, 0);
	sg_bdb->env_db=NULL;
    }
    free(sg_bdb);
}

int sg_entry_exists_bdb(void *dbdata, sgQueryType type, char *entry,int (*cmpkey)(const char *, const char *,int ))
{
    if (!dbdata)
        return 0;
    sg_bdb_data_t *bdb_data = (sg_bdb_data_t *)dbdata;
    DB *dDB  = (type == sgDomain ? bdb_data->domains_db : bdb_data->urls_db);
    if (!dDB)
        return 0;

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
    } else {
	if((*cmpkey)((char*)key.data,entry,key.size)==0) {
	    found = 1;
	} else if ((ret = L_dDBC->c_get(L_dDBC, &key, &data, DB_PREV)) == 0) {
            if((*cmpkey)((char*)key.data,entry,key.size)==0)
                found = 2;
        }
    }
    if (found)
        ci_debug_printf(5, "db_entry_exists: Matching key: %s (step %d)\n", (char *) key.data, found);
    L_dDBC->c_close(L_dDBC);
    return found;
}

void *sg_init_bdb(const char *home, enum sgDBopen otype)
{
    sg_bdb_data_t *sg_bdb;
    sg_bdb = (sg_bdb_data_t *) calloc(1, sizeof(sg_bdb_data_t));
    sg_bdb->env_db = setup_env_bdb(home);
    if(sg_bdb->env_db==NULL){
	free(sg_bdb);
	return NULL;
    }
    sg_bdb->domains_db = open_db_bdb(sg_bdb->env_db, "domains.db", otype, domainCompare);
    sg_bdb->urls_db = open_db_bdb(sg_bdb->env_db, "urls.db", otype, NULL);

    if(sg_bdb->domains_db == NULL && sg_bdb->urls_db== NULL) {
	sg_close_bdb(sg_bdb);
	return NULL;
    }

    return (void *)sg_bdb;
}

static int sg_entry_add_bdb(void *dbdata, sgQueryType type, char *entry)
{
    if (!dbdata)
        return 0;
    sg_bdb_data_t *bdb_data = (sg_bdb_data_t *)dbdata;
    DB *dDB  = (type == sgDomain ? bdb_data->domains_db : bdb_data->urls_db);
    if (!dDB)
        return 0;

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

static int sg_entry_remove_bdb(void *dbdata, sgQueryType type, char *entry)
{
    if (!dbdata)
        return 0;
    sg_bdb_data_t *bdb_data = (sg_bdb_data_t *)dbdata;
    DB *dDB  = (type == sgDomain ? bdb_data->domains_db : bdb_data->urls_db);
    if (!dDB)
        return 0;

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
    } else {
        ci_debug_printf(5, "db_entry_remove: The entry \"%s\" does not exist: %s\n", entry, db_strerror(ret));
    }
    L_dDBC->c_close(L_dDBC);
    return removed;
}

int sg_iterate_bdb(void *dbdata, sgQueryType type, int (*action)(const char *, int, const char *, int))
{
    if (!dbdata)
        return 0;
    sg_bdb_data_t *bdb_data = (sg_bdb_data_t *)dbdata;
    DB *dDB  = (type == sgDomain ? bdb_data->domains_db : bdb_data->urls_db);
    if (!dDB)
        return 0;

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
    } while(ret == 0);
    L_dDBC->c_close(L_dDBC);
    return count;
}

sg_db_type_t BDB_TYPE = {
    sg_init_bdb,
    sg_close_bdb,
    sg_entry_exists_bdb,
    sg_entry_add_bdb,
    sg_entry_remove_bdb,
    sg_iterate_bdb,
    "sg_bdb"
};

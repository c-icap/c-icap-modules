#include "../../common.h"
#include "c_icap/c-icap.h"
#include "c_icap/debug.h"
#include "c_icap/util.h"
#include "c_icap/ci_threads.h"
#include "sguardDB.h"
#include <lmdb.h>

/*This is used only by c-icap-mods-sguardDB utility to set
  maximum mapsize while building or updating the database.
  The maximum mapsize in practice is the maximum database size.
  Probably it would be better if this variable moved inside
  sg_lmdb_data structure and set per database, not globally.
  However because the c-icap-mods-sguardDB utility operates
  in one database using one thread we can use a global variable
  like this.
*/
size_t MAX_LMDB_SIZE = 64*1024*1024;

static int domainCompare (const MDB_val *a, const MDB_val *b)
{
    const char *a1 , *b1;
    char ac1 , bc1;
    a1=(const char *) a->mv_data + a->mv_size - 1;
    b1=(const char *) b->mv_data + b->mv_size - 1;
    while (*a1 == *b1){
	if(b1 == b->mv_data || a1 == a->mv_data)
	    break;
	a1--; b1--;
    }
    ac1 = *a1 == '.' ? '\1' : *a1;
    bc1 = *b1 == '.' ? '\1' : *b1;
    if(a1 == a->mv_data && b1 == b->mv_data)
	return ac1 - bc1;
    if(a1 == a->mv_data)
	return -1;
    if(b1 == b->mv_data)
	return 1;
    return ac1 - bc1;
}

static MDB_env *setup_env_lmdb(const char *home, enum sgDBopen otype)
{
    MDB_env *dbenv;
    int ret;
    if ((ret = mdb_env_create(&dbenv)) != 0) {
        ci_debug_printf(1, "sguard/setup_env_lmdb, mdb_env_create  failed: %s\n", mdb_strerror(ret));
	return NULL;
    }
    ci_debug_printf(5,"Environment created OK.\n");
    /*We need two databases one for urls and one for domains:*/
    mdb_env_set_maxdbs  (dbenv, 2);

    mdb_mode_t mode = 0;
    unsigned int flags = MDB_NOTLS;
    if (otype == sgDBrebuild) {
        /*In practice maximum size of db. */
        mdb_env_set_mapsize(dbenv, MAX_LMDB_SIZE);
        mode = S_IRUSR | S_IWUSR | S_IRGRP;
    } else if (otype == sgDBreadonly) {
        /*For a reason the MDB_RDONLY parameter does not work
          TODO: recheck
         */
        /* flags |= MDB_RDONLY;*/
    }

    if ((ret = mdb_env_open(dbenv, home, flags, mode)) != 0) {
        ci_debug_printf(1, "sguard/setup_env_lmdb, mdb_env_open: Environment open failed, db '%s': %s\n", home, mdb_strerror(ret));
        mdb_env_close(dbenv);
        return NULL;
    }
    ci_debug_printf(5, "sguard/setup_env_lmdb, mdb_env_open: DB environment setup OK.\n");
    return dbenv;
}

static int open_db_lmdb(MDB_txn *txn, char *name, enum sgDBopen otype,
                        int (*bt_compare_fcn)(const MDB_val *, const MDB_val *),
                        MDB_dbi *dbi)
{
    int ret;
    uint32_t flags;

    if (otype == sgDBreadonly)
        flags = 0;
    else
        flags = MDB_CREATE;

    if ((ret = mdb_dbi_open(txn, name, flags, dbi)) != 0) {
        const char *path;
        if (mdb_env_get_path(mdb_txn_env(txn), &path) != 0)
            path = "unknown_path";
        ci_debug_printf(1, "sguard/open_db_lmdb %s/%s failed %s\n", path, name, mdb_strerror(ret));
        return 0;
    }

    if (bt_compare_fcn) {
        ret = mdb_set_compare(txn, *dbi, bt_compare_fcn);
        _CI_ASSERT(ret == 0);
    }

    if (otype == sgDBrebuild) {
        /*Empty the database*/
        mdb_drop(txn, *dbi, 0);
    }
    return 1;
}

typedef struct lmdb_txn_pool {
    ci_thread_mutex_t mtx;
    ci_thread_cond_t cnd;
    ci_list_t *pool;
    int stat_readers_full;
} lmdb_txn_pool_t;

typedef struct sg_lmdb_data {
    MDB_env *env_db;
    MDB_dbi domains_db;
    int domains_db_open;
    MDB_dbi urls_db;
    int urls_db_open;
    lmdb_txn_pool_t pool;
    MDB_txn *txn;
    int txn_uses;
    int txn_failures;
} sg_lmdb_data_t;

static  MDB_txn *lmdb_txn_pool_get_reader(MDB_env *env_db, lmdb_txn_pool_t *pool)
{
    int ret;
    if (!env_db)
        return NULL;
    if (!pool || !pool->pool)
        return NULL; /*Should assert?*/

    const char *dbpath = NULL;
    if (mdb_env_get_path(env_db, &dbpath) != 0)
        dbpath = "[unknown]";
    MDB_txn *txn = NULL;
    int wait_list = 0;
    int tries = 10;
    do {
        ci_thread_mutex_lock(&pool->mtx);
        if (wait_list)
            ci_thread_cond_wait(&pool->cnd, &pool->mtx);
        ci_list_pop(pool->pool, &txn);
        ci_thread_mutex_unlock(&pool->mtx);

        if (txn) {
            ci_debug_printf(8, "lmdb_tables/lmdb_txn_pool_get_reader: db '%s' git transaction from pool\n", dbpath);
            ret = mdb_txn_renew(txn);
            if (ret != 0) {
                ci_debug_printf(1, "lmdb_tables/lmdb_txn_pool_get_reader: db '%s', wrong transaction object in pool: %s\n", dbpath, mdb_strerror(ret));
                mdb_txn_abort(txn);
                txn = NULL;
            }
        }

        if (txn == NULL && !wait_list) {
            /*Pool is empty. Try only once to build a txn.
              If fails return error or if we reach maximum readers
              wait one to be available */
            if ((ret = mdb_txn_begin(env_db, NULL, MDB_RDONLY, &txn)) != 0) {
                if (ret == MDB_READERS_FULL) {
                    pool->stat_readers_full++;
                    wait_list = 1;
                } else {
                    ci_debug_printf(1, "lmdb_tables/mdb_txn_begin: db '%s', can not create transaction object: %s\n", dbpath, mdb_strerror(ret));
                    return NULL;
                }
            }
        }
        /*If txn is nil probably condition aborted by a signal, retry*/
        tries--;
    } while (txn == NULL && tries > 0);

    if (!txn) {
        ci_debug_printf(1, "lmdb_tables/lmdb_txn_pool_get_reader: db '%s', can not create or retrieve from pool a transaction object\n", dbpath);
    }
    return txn;
}

static void lmdb_txn_pool_push_txn(lmdb_txn_pool_t *pool, MDB_txn *txn)
{
    mdb_txn_reset(txn);
    ci_thread_mutex_lock(&pool->mtx);
    if (ci_list_first(pool->pool) == NULL)
        ci_thread_cond_signal(&pool->cnd); /*pool is empty, maybe there are waiters*/
    ci_list_push(pool->pool, &txn);
    ci_thread_mutex_unlock(&pool->mtx);

}

static void lmdb_txn_pool_init(lmdb_txn_pool_t *pool)
{
    ci_thread_mutex_init(&pool->mtx);
    ci_thread_cond_init(&pool->cnd);
    pool->pool = ci_list_create(2048, sizeof(void *));
    pool->stat_readers_full = 0;
}

static void lmdb_txn_pool_mkempty(lmdb_txn_pool_t *pool)
{
    if (!pool || !pool->pool)
        return;

    MDB_txn *txn = NULL;
    const char *dbpath = NULL;
    int n = 0;
    while(ci_list_pop(pool->pool, &txn)) {
        if (dbpath == NULL)
            mdb_env_get_path(mdb_txn_env(txn), &dbpath);
        mdb_txn_abort(txn);
        n++;
    }
    if (n) {
        if (!dbpath) dbpath = "[unknwon]";
        ci_debug_printf(3, "lmdb_table txn pool db: %s released, %d transactions in pool\n", dbpath, n);
    }
}

static void lmdb_txn_pool_destroy(lmdb_txn_pool_t *pool)
{
    lmdb_txn_pool_mkempty(pool);
    ci_list_destroy(pool->pool);
}

void sg_close_lmdb(void *data)
{
    sg_lmdb_data_t *sg_lmdb = (sg_lmdb_data_t *)data;
    if(sg_lmdb->domains_db_open){
	mdb_dbi_close(sg_lmdb->env_db, sg_lmdb->domains_db);
	sg_lmdb->domains_db_open = 0;
    }
    if(sg_lmdb->urls_db_open){
	mdb_dbi_close(sg_lmdb->env_db, sg_lmdb->urls_db);
	sg_lmdb->urls_db_open = 0;
    }
    lmdb_txn_pool_destroy(&sg_lmdb->pool);
    if(sg_lmdb->env_db){
	mdb_env_close(sg_lmdb->env_db);
	sg_lmdb->env_db=NULL;
    }
    free(sg_lmdb);
}

void *sg_init_lmdb(const char *home, enum sgDBopen otype)
{
    sg_lmdb_data_t *sg_lmdb;
    sg_lmdb = (sg_lmdb_data_t *) calloc(1, sizeof(sg_lmdb_data_t));
    sg_lmdb->env_db = setup_env_lmdb(home, otype);
    if(sg_lmdb->env_db==NULL){
	free(sg_lmdb);
	return NULL;
    }
    lmdb_txn_pool_init(&sg_lmdb->pool);
    MDB_txn *txn = NULL;
    int ret;
    if ((ret = mdb_txn_begin(sg_lmdb->env_db, NULL, 0, &txn)) != 0) {
        ci_debug_printf(1, "sguard/sg_init_lmdb/mdb_txn_begin: db %s, can not create transaction object: %s\n", home, mdb_strerror(ret));
        mdb_env_close(sg_lmdb->env_db);
        sg_lmdb->env_db = NULL;
        free(sg_lmdb);
        return 0;
    }

    sg_lmdb->domains_db_open = open_db_lmdb(txn, "domains", otype, domainCompare, &sg_lmdb->domains_db);
    sg_lmdb->urls_db_open = open_db_lmdb(txn, "urls", otype, NULL, &sg_lmdb->urls_db);

    if(!sg_lmdb->domains_db_open && !sg_lmdb->urls_db_open) {
        mdb_txn_abort(txn);
	sg_close_lmdb(sg_lmdb);
	return NULL;
    }
    mdb_txn_commit(txn);
    return (void *)sg_lmdb;
}

int sg_entry_exists_lmdb(void *dbdata, sgQueryType type, char *entry,int (*cmpkey)(const char *, const char *,int ))
{
    if (!dbdata)
        return 0;
    sg_lmdb_data_t *lmdb_data = (sg_lmdb_data_t *)dbdata;
    MDB_dbi dDB  = (type == sgDomain ? lmdb_data->domains_db : lmdb_data->urls_db);
    int ret,found=0;
    MDB_val key, data;
    MDB_cursor *cursor;
    MDB_txn *txn = lmdb_txn_pool_get_reader(lmdb_data->env_db, &lmdb_data->pool);
    if (!txn) {
        return 0;
    }
    if ((ret = mdb_cursor_open(txn, dDB, &cursor)) != 0) {
	ci_debug_printf(1, "sguard/sg_entry_exists_lmdb/mdb_cursor_open: %s\n", mdb_strerror(ret));
	return 0;
    }
    memset(&data, 0, sizeof(data));
    memset(&key, 0, sizeof(key));
    key.mv_data = entry;
    key.mv_size = strlen(entry);
    if ((ret = mdb_cursor_get(cursor, &key, &data, MDB_SET_RANGE)) != 0){
	ci_debug_printf(5, "sguard/sg_entry_exists_lmdb/mbd_cursor_get: does not exists: %s\n", mdb_strerror(ret));
    } else {
	if((*cmpkey)((char*)key.mv_data, entry, key.mv_size)==0) {
	    found = 1;
	} else if ((ret = mdb_cursor_get(cursor, &key, &data, MDB_PREV)) == 0) {
            if((*cmpkey)((char*)key.mv_data, entry, key.mv_size)==0)
                found = 2;
        }
    }
    if (found)
        ci_debug_printf(5, "db_entry_exists: Matching key: %s (step %d)\n", (char *) key.mv_data, found);
    mdb_cursor_close(cursor);
    lmdb_txn_pool_push_txn(&lmdb_data->pool, txn);
    return found;
}

static int sg_entry_add_lmdb(void *dbdata, sgQueryType type, char *entry)
{
    if (!dbdata)
        return 0;
    sg_lmdb_data_t *lmdb_data = (sg_lmdb_data_t *)dbdata;
    MDB_dbi db  = (type == sgDomain ? lmdb_data->domains_db : lmdb_data->urls_db);
    int ret;
    MDB_txn *txn;
    if (lmdb_data->txn) {
        // If a transaction is built for multiple additions/removals
        txn = lmdb_data->txn;
        lmdb_data->txn_uses++;
    } else if ((ret = mdb_txn_begin(lmdb_data->env_db, NULL, 0, &txn)) != 0) {
        const char *path;
        if (mdb_env_get_path(lmdb_data->env_db, &path) != 0)
            path = "unknown_path";
        ci_debug_printf(1, "sguard/sg_entry_add_lmdb/mdb_txn_begin: db %s, can not create transaction object: %s\n", path, mdb_strerror(ret));
        return 0;
    }
    ci_debug_printf(8, "Going to add entry: %s\n", entry);

    MDB_val key, data;
    memset(&data, 0, sizeof(data));
    memset(&key, 0, sizeof(key));
    key.mv_data = entry;
    key.mv_size = strlen(entry);
    data.mv_data = "";
    data.mv_size = 1 ;
    ret = mdb_put(txn, db, &key, &data, MDB_NODUPDATA );
    if (ret != 0) {
        if (ret != MDB_KEYEXIST) {
            ci_debug_printf(1, "db_entry_add: Can not add entry \"%s\" %s\n", entry, mdb_strerror(ret));
            lmdb_data->txn_failures++;
        }
        /*If MDB_KEYEXIST returned which meas key duplicate
          this function will return 0 but the txn_failures will not updated
          so the error will be ignored when multiple additions/removals are
          executed in one transaction/txn object.
         */
    }
    if (!lmdb_data->txn) {
        if (ret == 0)
            mdb_txn_commit(txn);
        else
            mdb_txn_abort(txn);
    }
    return ret == 0 ? 1 : 0;
}

static int sg_entry_remove_lmdb(void *dbdata, sgQueryType type, char *entry)
{
    if (!dbdata)
        return 0;
    sg_lmdb_data_t *lmdb_data = (sg_lmdb_data_t *)dbdata;
    MDB_dbi db  = (type == sgDomain ? lmdb_data->domains_db : lmdb_data->urls_db);
    int ret;
    MDB_txn *txn;
    if (lmdb_data->txn) {
        // If a transaction is built for multiple additions/removals
        txn = lmdb_data->txn;
        lmdb_data->txn_uses++;
    } else if ((ret = mdb_txn_begin(lmdb_data->env_db, NULL, 0, &txn)) != 0) {
        const char *path;
        if (mdb_env_get_path(lmdb_data->env_db, &path) != 0)
            path = "unknown_path";
        ci_debug_printf(1, "sguard/sg_entry_remove_lmdb/mdb_txn_begin: db %s, can not create transaction object: %s\n", path, mdb_strerror(ret));
        return 0;
    }

    MDB_val key, data;
    memset(&data, 0, sizeof(data));
    memset(&key, 0, sizeof(key));
    key.mv_data = entry;
    key.mv_size = strlen(entry);
    ret = mdb_del(txn, db, &key, &data);
    if (ret != 0) {
	ci_debug_printf(1, "db_entry_add: Can not remove entry \"%s\" %s\n", entry, mdb_strerror(ret));
        lmdb_data->txn_failures++;
	return 0;
    }
    if (!lmdb_data->txn) {
        if (ret == 0)
            mdb_txn_commit(txn);
        else
            mdb_txn_abort(txn);
    }
    return (ret == 0 ? 1 : 0);
}

int sg_iterate_lmdb(void *dbdata, sgQueryType type, int (*action)(const char *, int, const char *, int))
{
    if (!dbdata)
        return 0;
    sg_lmdb_data_t *lmdb_data = (sg_lmdb_data_t *)dbdata;
    MDB_dbi db  = (type == sgDomain ? lmdb_data->domains_db : lmdb_data->urls_db);
    MDB_txn *txn = lmdb_txn_pool_get_reader(lmdb_data->env_db, &lmdb_data->pool);
    if (!txn) {
        return 0;
    }

    int ret;
    MDB_cursor *cursor;
    if ((ret = mdb_cursor_open(txn, db, &cursor)) != 0) {
	ci_debug_printf(1, "sguard/sg_iterate_lmdb/mdb_cursor_open: %s\n", mdb_strerror(ret));
        lmdb_txn_pool_push_txn(&lmdb_data->pool, txn);
	return 0;
    }

    int count = 0;
    MDB_val key, data;
    memset(&data, 0, sizeof(data));
    memset(&key, 0, sizeof(key));
    if ((ret = mdb_cursor_get(cursor, &key, &data, MDB_FIRST)) != 0){
        do{
            count ++;
            if(action)
                (*action)((char *)(key.mv_data), key.mv_size, (char *)(data.mv_data),data.mv_size);
            ret = mdb_cursor_get(cursor, &key, &data, MDB_NEXT);
        } while(ret == 0);
    }
    mdb_cursor_close(cursor);
    lmdb_txn_pool_push_txn(&lmdb_data->pool, txn);
    return count;
}

void sg_start_modify(void *dbdata)
{
    sg_lmdb_data_t *lmdb_data = (sg_lmdb_data_t *)dbdata;
    if (!lmdb_data->txn) {
        int ret = mdb_txn_begin(lmdb_data->env_db, NULL, 0, &lmdb_data->txn);
        if (ret != 0)
            lmdb_data->txn = NULL;
    }
}

void sg_stop_modify(void *dbdata)
{
    sg_lmdb_data_t *lmdb_data = (sg_lmdb_data_t *)dbdata;
    if (lmdb_data->txn) {
        if (lmdb_data->txn_failures) {
            ci_debug_printf(1, "There are failed operations, will not commit\n");
            mdb_txn_abort(lmdb_data->txn);
        } else
            mdb_txn_commit(lmdb_data->txn);
        lmdb_data->txn = NULL;
        lmdb_data->txn_uses = 0;
        lmdb_data->txn_failures = 0;
    }
}


sg_db_type_t LMDB_TYPE = {
    sg_init_lmdb,
    sg_close_lmdb,
    sg_entry_exists_lmdb,
    sg_entry_add_lmdb,
    sg_entry_remove_lmdb,
    sg_iterate_lmdb,
    sg_start_modify,
    sg_stop_modify,
    "sg_lmdb"
};

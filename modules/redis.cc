#include "common.h"
#include "array.h"
#include "cache.h"
#include "ci_threads.h"
#include "debug.h"
#include "md5.h"
#include "mem.h"
#include "module.h"
#include "stats.h"

#include <assert.h>
#include <hiredis/hiredis.h>

#include <memory>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <mutex>
#include <algorithm>

#include <crypt.h>

class RedisServer {
public:
    RedisServer(const std::string &aServer, int aPort, int db = 0, const std::string &aPwFile = std::string("")): server(aServer), port(aPort), globalDB(db), pwFile(aPwFile) {};
    ~RedisServer();
    void initialize();
    redisContext *getContext();
    void storeContext(redisContext *);

    bool checkHealth(redisContext *);

public:
    std::string server;
    int port;
    int globalDB;
private:
    std::string pwFile;
    std::string pw;
    std::vector<redisContext *> contextPool;
    std::mutex ContextMtx;
    // Statistic ids:
    int stat_connections_reuse;
    int stat_connections_new;
    int stat_connections_closed;
    int stat_connections_errors;
};

#define REDIS_MAXKEYLEN 4096

class RedisCacheData {
public:
    RedisCacheData(const char *aName);
    ~RedisCacheData();

    redisContext *getContext(RedisServer * &srv);
    void releaseContext(redisContext *, RedisServer *srv);

    bool get(const char *key, void *&value, size_t &value_size);
    bool store(const char *key, const void *value, size_t value_size, int ttl);
    const char *getName() {return name.c_str();};
    static int MaxStoreTime; // The default is 1 hour

private:
    void computeKey(const char *key, std::string &outKey);

    std::string name;
    int db = 0;

    int stat_updates = -1;
    int stat_hits = -1;
    int stat_miss = -1;
    int stat_fails = -1;
    int stat_ignore = -1;
public:
    static int UseDBs;
    static int DBBase;
    static int DBCount;
    static const char *ServerSelectionModelsList[];
    static char *ServerSelectionModel;
} ;

int RedisCacheData::MaxStoreTime = 60 * 60;
int RedisCacheData::DBCount = 0;
int RedisCacheData::DBBase = 0;
int RedisCacheData::UseDBs = 0;
const char *RedisCacheData::ServerSelectionModelsList[] = {"Failover", "RoundRobin"};
char ServerModelDefault[] = "Failover";
char *RedisCacheData::ServerSelectionModel = ServerModelDefault;

static int USE_MD5_SUM_KEYS = 0;
static ci_list_t *Servers = NULL;
static int ServersCount = 0;
static std::mutex ServersMtx;

static void redis_releasedb();

// Redis cache declaration
extern "C"
{
static int redis_cache_init(struct ci_cache *cache, const char *name);
static const void *redis_cache_search(struct ci_cache *cache, const void *key, void **val, void *data, void *(*dup_from_cache)(const void *stored_val, size_t stored_val_size, void *data));
static int redis_cache_update(struct ci_cache *cache, const void *key, const void *val, size_t val_size, void *(*copy_to_cache)(void *buf, const void *val, size_t buf_size));
static void redis_cache_destroy(struct ci_cache *cache);
}
static struct ci_cache_type redis_cache = {
    redis_cache_init,
    redis_cache_search,
    redis_cache_update,
    redis_cache_destroy,
    "redis"
};


// Redis module declaration
extern "C" int redis_cfg_server_set(const char *directive, const char **argv, void *setdata);

CI_BUILD_VAR_CFG_STRING_LIST(varSrvModelsList, RedisCacheData::ServerSelectionModel, RedisCacheData::ServerSelectionModelsList);
/*Configuration Table .....*/
static struct ci_conf_entry redis_conf_variables[] = {
    {"Server", NULL, redis_cfg_server_set, NULL},
    {"UseDiscreteDBs", &RedisCacheData::UseDBs, ci_cfg_onoff, NULL},
    {"DiscreteDBBase", &RedisCacheData::DBBase, ci_cfg_set_int, NULL},
    {"UseMD5Keys", &USE_MD5_SUM_KEYS, ci_cfg_onoff, NULL},
    {"ServerSelectionModel", &varSrvModelsList, ci_cfg_set_str_set, NULL},
    {NULL, NULL, NULL, NULL}
};

extern "C"
{
static int redis_module_init(struct ci_server_conf *server_conf);
static int redis_module_post_init(struct ci_server_conf *server_conf);
static void redis_module_release();
}
CI_DECLARE_MOD_DATA common_module_t module = {
    "redis",
    redis_module_init,
    redis_module_post_init,
    redis_module_release,
    redis_conf_variables,
};

extern "C" int redis_module_init(struct ci_server_conf *server_conf)
{
    Servers = ci_list_create(2048, 0);
    ci_cache_type_register(&redis_cache);
    ci_debug_printf(3, "redis: cache sucessfully registered!\n");
    return 1;
}

extern "C" int redis_module_post_init(struct ci_server_conf *server_conf)
{
    _CI_ASSERT(Servers);
    RedisServer *srv = nullptr;
    if (!ci_list_first(Servers)) {
        srv = new RedisServer(std::string("127.0.0.1"), 6379);
        ci_list_push_back(Servers, (void *)srv);
    }
    ci_list_iterator_t it;
    ServersCount = 0;
    for (srv = (RedisServer *)ci_list_iterator_first(Servers, &it); srv != nullptr; srv = (RedisServer *)ci_list_iterator_next(&it)) {
        try {
            srv->initialize();
        } catch (std::exception &e) {
            ci_debug_printf(1, "Error initializing server '%s:%d': %s\n", srv->server.c_str(), srv->port, e.what());
        }
        ServersCount++;
    }
    return 1;
}

extern "C" void redis_module_release()
{
    redis_releasedb();
}

void redis_releasedb()
{
    RedisServer *srv;
    while(ci_list_pop(Servers, &srv)) {
        delete srv;
    }
    RedisCacheData::DBCount = 0;
    RedisCacheData::DBBase = 0;
    RedisCacheData::UseDBs = 0;
}


/*******************************************/
/* redis cache implementation          */

extern "C" int redis_cache_init(struct ci_cache *cache, const char *name)
{
    if (cache->key_ops != &ci_str_ops) {
        ci_debug_printf(3, "redis: Can not create redis cache '%s' for non-string keys\n", name);
        return 0;
    }

    // TODO: Parse name/params to get db id. The c-icap cache interface
    // does not support it yet.
    cache->cache_data = new RedisCacheData(name);
    ci_debug_printf(3, "redis: cache '%s' created\n", name);
    return 1;
}

extern "C" void redis_cache_destroy(struct ci_cache *cache)
{
    RedisCacheData *redis_data = (RedisCacheData *)cache->cache_data;
    delete redis_data;
    cache->cache_data = nullptr;
}

extern "C" const void *redis_cache_search(struct ci_cache *cache, const void *key, void **val, void *data, void *(*dup_from_cache)(const void *stored_val, size_t stored_val_size, void *data))
{
    void *value = nullptr;
    size_t value_len = 0;
    RedisCacheData *redis_data = (RedisCacheData *)cache->cache_data;

    const bool found = redis_data->get((const char *)key, value, value_len);
    if (!found)
        return nullptr;

    if (dup_from_cache && value) {
        *val = dup_from_cache(value, value_len, data);
        ci_buffer_free(value);
        value = nullptr;
    } else {
        if (value && value_len)
            *val = value;
        else
            *val = nullptr;
    }
    return key;
}

extern "C" int redis_cache_update(struct ci_cache *cache, const void *key, const void *val, size_t val_size, void *(*copy_to_cache)(void *buf, const void *val, size_t buf_size))
{
    void *value = NULL;
    RedisCacheData *redis_data = (RedisCacheData *)cache->cache_data;

    if (copy_to_cache && val_size) {
        if ((value = ci_buffer_alloc(val_size)) == NULL)
            return 0; /*debug message?*/

        if (!copy_to_cache(value, val, val_size))
            return 0;  /*debug message?*/
    }

    // update
    redis_data->store((const char *)key, value ? value : val, val_size, cache->ttl);

    if (value)
        ci_buffer_free(value);

    ci_debug_printf(5, "redis: redis_cache_update successfully update key '%s'\n", (char *)key);
    return 1;
}

extern "C" int redis_cfg_server_set(const char *directive, const char **argv, void *setdata)
{
    char *s;
    char hostname[1024];
    int port = 0;
    int db = 0;
    strncpy(hostname, argv[0], sizeof(hostname));
    hostname[sizeof(hostname) - 1] = '\0';
    if (hostname[0] != '/' && (s = strchr(hostname, ':')) != NULL) {
        *s = '\0';
        s++;
        port = atoi(s);
        if (!port)
            port = 6379;
    } else
        port = 6379;
    int i;
    const char *pwFile = nullptr;
    for (i = 1; argv[i] != nullptr; ++i) {
        if (strncasecmp(argv[i], "pwfile=", 7) == 0)
            pwFile = argv[i] + 7;
        if (strncasecmp(argv[i], "db=", 3) == 0) {
            db = atoi(argv[i] + 3);
            if (port < 0) {
                ci_debug_printf(1, "%s: Wrong argument %s\n", directive, argv[i]);
                return 0;
            }
        }
    }
    RedisServer *srv = new RedisServer(hostname, port, db, pwFile ? std::string(pwFile) : std::string(""));
    ci_list_push_back(Servers, (void *)srv);
    ci_debug_printf(2, "redis: setup redis server %s:%d\n", hostname, port);
    return 1;
}

void RedisServer::initialize()
{
    if (!pwFile.empty()) {
        std::ifstream pwstream(pwFile);
        if (!pwstream) {
            throw std::runtime_error(std::string("Can not open file '").append(pwFile).append("'"));
        }
        if (!std::getline(pwstream, pw)) {
            throw std::runtime_error(std::string("Can not read password from file '").append(pwFile).append("'"));
        }
    }
    char buf[256];
    snprintf(buf, sizeof(buf), "redis_server_%s_connections_reuse", server.c_str());
    stat_connections_reuse = ci_stat_entry_register(buf, CI_STAT_INT64_T, "redis_cache");
    snprintf(buf, sizeof(buf), "redis_server_%s_connections_new", server.c_str());
    stat_connections_new = ci_stat_entry_register(buf, CI_STAT_INT64_T, "redis_cache");
    snprintf(buf, sizeof(buf), "redis_server_%s_connections_closed", server.c_str());
    stat_connections_closed = ci_stat_entry_register(buf, CI_STAT_INT64_T, "redis_cache");
    snprintf(buf, sizeof(buf), "redis_server_%s_connections_errors", server.c_str());
    stat_connections_errors = ci_stat_entry_register(buf, CI_STAT_INT64_T, "redis_cache");
}

RedisServer::~RedisServer()
{
    redisContext *redisCtx = nullptr;
    while (!contextPool.empty()) {
        redisCtx = contextPool.back();
        contextPool.pop_back();
        redisFree(redisCtx);
        ci_stat_uint64_inc(stat_connections_closed, 1);
    }
}

bool RedisServer::checkHealth(redisContext *ctx)
{
    redisReply *reply = (redisReply *)redisCommand(ctx, "PING");
    const int type = reply->type;
    const bool ok = type == REDIS_REPLY_STRING || type == REDIS_REPLY_STATUS;
    ci_debug_printf(7, "redis %p: is %s healthy (type=%d:%s)\n", ctx, ok ? "" : "NOT", type, reply->str);
    freeReplyObject(reply);
    return ok;
}

redisContext *RedisServer::getContext()
{
    redisContext *redisCtx = nullptr;
    bool emptyQueue = false;
    do {
        ContextMtx.lock();
        if (!contextPool.empty()) {
            redisCtx = contextPool.back();
            contextPool.pop_back();
        }
        emptyQueue = contextPool.empty();
        ContextMtx.unlock();
        if (redisCtx && !checkHealth(redisCtx)) {
            redisFree(redisCtx);
            redisCtx = nullptr;
            ci_stat_uint64_inc(stat_connections_closed, 1);
        }
    } while(redisCtx == nullptr && !emptyQueue);

    if (redisCtx) {
        ci_stat_uint64_inc(stat_connections_reuse, 1);
    } else {
        redisCtx = redisConnect(server.c_str(), port);
        ci_debug_printf(7, "redis: Got new connection %p!\n", redisCtx);
        if (redisCtx == nullptr) {
            ci_debug_printf(1, "redis: connection allocation error\n");
            ci_stat_uint64_inc(stat_connections_errors, 1);
            return nullptr;
        }

        if (redisCtx != nullptr && redisCtx->err) {
            ci_debug_printf(1, "redis: connecting error: %s\n",   redisCtx->errstr);
            redisFree(redisCtx);
            ci_stat_uint64_inc(stat_connections_errors, 1);
            return nullptr;
        }

	if (pw.length()) {
	    redisReply *reply = (redisReply *)redisCommand(redisCtx, "AUTH %s", pw.c_str());
	    if (reply)
	        freeReplyObject(reply);
	}
        ci_stat_uint64_inc(stat_connections_new, 1);
    }

    ci_debug_printf(7, "redis %p: retrieved\n", redisCtx);
    return redisCtx;
}

void RedisServer::storeContext(redisContext *ctx)
{
    ContextMtx.lock();
    contextPool.push_back(ctx);
    ContextMtx.unlock();
    ci_debug_printf(7, "redis %p: stored\n", ctx);
}

RedisCacheData::RedisCacheData(const char *aName) : name(aName), db((UseDBs ? (DBBase + DBCount++) : 0))
{
    char buf[256];
    snprintf(buf, sizeof(buf), "redis_%s_updates", aName);
    stat_updates = ci_stat_entry_register(buf, CI_STAT_INT64_T, "redis_cache");
    snprintf(buf, sizeof(buf), "redis_%s_hits", aName);
    stat_hits = ci_stat_entry_register(buf, CI_STAT_INT64_T, "redis_cache");
    snprintf(buf, sizeof(buf), "redis_%s_miss", aName);
    stat_miss = ci_stat_entry_register(buf, CI_STAT_INT64_T, "redis_cache");
    snprintf(buf, sizeof(buf), "redis_%s_fails", aName);
    stat_fails = ci_stat_entry_register(buf, CI_STAT_INT64_T, "redis_cache");
    snprintf(buf, sizeof(buf), "redis_%s_ignore", aName);
    stat_ignore = ci_stat_entry_register(buf, CI_STAT_INT64_T, "redis_cache");
    if (UseDBs) {
        ci_debug_printf(1, "Redis cache '%s' uses the redis DB %d", aName, db);
    }
}

RedisCacheData::~RedisCacheData()
{
}

redisContext *RedisCacheData::getContext(RedisServer * &selectedServer)
{
    if (toupper(*ServerSelectionModel) == 'F') {/*Failover*/
        ci_list_iterator_t it;
        for (RedisServer *srv = (RedisServer *)ci_list_iterator_first(Servers, &it); srv != nullptr; srv = (RedisServer *)ci_list_iterator_next(&it)) {
            redisContext *redisCtx = srv ? srv->getContext() : nullptr;
            if (redisCtx) {
                ci_debug_printf(3, "Redis server '%s' got connection\n", srv->server.c_str());
                selectedServer = srv;
                return redisCtx;
            }
        }
    }
    if (toupper(*ServerSelectionModel) == 'R') {/*RoundRobin*/
        std::vector<RedisServer *> availableServers;
        availableServers.reserve(ServersCount);
        ci_list_iterator_t it;
        ServersMtx.lock();
        RedisServer *srv;
        for (srv = (RedisServer *)ci_list_iterator_first(Servers, &it); srv != nullptr; srv = (RedisServer *)ci_list_iterator_next(&it)) {
            _CI_ASSERT(srv);
            availableServers.push_back(srv);
        }
        ci_list_pop(Servers, &srv);
        ci_list_push_back(Servers, (void*)srv);
        ServersMtx.unlock();

        for (auto it = availableServers.begin(); it != availableServers.end(); ++it) {
            redisContext *redisCtx = (*it)->getContext();
            if (redisCtx) {
                ci_debug_printf(3, "Redis server '%s' connected ok\n", srv->server.c_str());
                selectedServer = srv;
                return redisCtx;
            }
        }
    }
    ci_debug_printf(1, "redis: Error connecting to any of the redis server\n");
    selectedServer = nullptr;
    return nullptr;
}

void RedisCacheData::releaseContext(redisContext *ctx, RedisServer *srv)
{
    if (!ctx)
        return;

    // TODO: Check if srv exists in Servers.
    if (srv)
        srv->storeContext(ctx);
    else
        redisFree(ctx);
}

void RedisCacheData::computeKey(const char *key, std::string &outKey)
{
    ci_MD5_CTX md5;
    unsigned char digest[16];
    outKey.reserve(REDIS_MAXKEYLEN);
    /*
      If no different redis DB is used for each redis c-icap cache user
      we need to use keys in the form "v[search_domain]:[key]"
      plus a char for "\0".
     */
    const size_t keySize = UseDBs ? strlen(key) : strlen(key) + name.length() + 3;
    if (keySize < REDIS_MAXKEYLEN) {
        if (!UseDBs) {
            outKey.assign("v", 1);
            outKey.append(name);
            outKey.append(":", 1);
        }
        outKey.append(key);
        return;
    }

    if (USE_MD5_SUM_KEYS) {
        ci_MD5Init(&md5);
        ci_MD5Update(&md5, (const unsigned char *)key, strlen(key));
        ci_MD5Final(digest, &md5);
        char digestStr[128];
        size_t digestStrSize = snprintf(digestStr, sizeof(digestStr),
                                "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
                                digest[0], digest[1], digest[2], digest[3],
                                digest[4], digest[5], digest[6], digest[7],
                                digest[8], digest[9], digest[10], digest[11],
                                digest[12], digest[13], digest[14], digest[15]);

        outKey.assign("v", 1);
        outKey.append(name);
        outKey.append(":", 1);
        outKey.append(digestStr, digestStrSize);
        return;
    }

    outKey.clear();
}

bool RedisCacheData::get(const char *key,  void *& value, size_t &value_len)
{
    ci_debug_printf(5, "redis: search for string : %s\n", key);
    std::string useKey;
    computeKey(key, useKey);
    if (useKey.empty()) {
        ci_stat_uint64_inc(stat_ignore, 1);
        return false;
    }

    RedisServer *usedServer = nullptr;
    redisContext *redisCtx = getContext(usedServer);
    if (!redisCtx) {
        ci_stat_uint64_inc(stat_fails, 1);
        return false;
    }

    redisReply *reply = nullptr;
    const int useDB = db > 0 ? db : (usedServer ? usedServer->globalDB : 0);
    if (useDB > 0) {
        reply = (redisReply *)redisCommand(redisCtx, "SELECT %s", std::to_string(useDB).c_str());
        bool error = false;
        if (!reply || reply->type == REDIS_ERR) {
            ci_debug_printf(1, "redis: Failed to select database %d\n", useDB);
            error = true;
        }
        if (reply) {
            freeReplyObject(reply);
            reply = nullptr;
        }
        if (error) {
            ci_stat_uint64_inc(stat_fails, 1);
            return false;
        }
    }

    reply = (redisReply *)redisCommand(redisCtx, "GET %s", useKey.c_str());
    releaseContext(redisCtx, usedServer);

    if (reply) {
        if (reply->type != REDIS_REPLY_STRING) {
            ci_debug_printf(5, "redis: Not found! Error type: %d\n", reply->type);
            freeReplyObject(reply);
            ci_stat_uint64_inc(stat_miss, 1);
            return false;
        }

        bool ok = true;
        if (reply->len > 0) {
            if ((value = ci_buffer_alloc(reply->len))) {
                memcpy(value, reply->str, reply->len);
                value_len = reply->len;
            } else
                ok = false;
        } else {
            value_len = 0;
            value = nullptr;
        }
        freeReplyObject(reply);
        ci_debug_printf(5, "redis: success\n");
        ci_stat_uint64_inc(stat_hits, 1);
        return ok;
    }

    ci_debug_printf(5, "redis: search failed\n");
    ci_stat_uint64_inc(stat_fails, 1);
    return false;
}

bool RedisCacheData::store(const char *key, const void *value, size_t value_len, int ttl)
{
    int expire = ttl > 0 ? ttl : MaxStoreTime;
    std::string expireStr(std::to_string(expire));
    ci_debug_printf(5, "redis: store string : %s, expire after: %s (%d)\n", key, expireStr.c_str(), ttl);

    int status = REDIS_ERR;

    std::string useKey;
    computeKey(key, useKey);
    if (useKey.empty()) {
        ci_stat_uint64_inc(stat_ignore, 1);
        return false;
    }

    RedisServer *usedServer = nullptr;
    redisContext *redisCtx = getContext(usedServer);
    if (!redisCtx) {
        ci_stat_uint64_inc(stat_fails, 1);
        return false;
    }

    redisReply *reply = nullptr;
    const int useDB = db > 0 ? db : (usedServer ? usedServer->globalDB : 0);
    if (useDB > 0) {
        reply = (redisReply *)redisCommand(redisCtx, "SELECT %s", std::to_string(useDB).c_str());
        bool error = false;
        if (!reply || reply->type == REDIS_ERR) {
            ci_debug_printf(1, "redis: Failed to select database %d\n", useDB);
            error = true;
        }
        if (reply) {
            freeReplyObject(reply);
            reply = nullptr;
        }
        if (error) {
            ci_stat_uint64_inc(stat_fails, 1);
            return false;
        }
    }

    reply = (redisReply *)redisCommand(redisCtx, "SET %s %b NX EX %s", useKey.c_str(), value, value_len, expireStr.c_str());
    releaseContext(redisCtx, usedServer);

    if (reply) {
        status = reply->type;
        ci_debug_printf(7, "redis: DB return reply type: '%d',  error: '%s' \tQuery was %s\n", reply->type, (reply->str ? reply->str : "(nil)"), useKey.c_str());
        freeReplyObject(reply);
    } else {
        ci_debug_printf(2, "redis: NULL reply from redis?\n");
    }

    if (status == REDIS_REPLY_NIL) {
        ci_stat_uint64_inc(stat_updates, 1);
        return false; // already exist
    } else if (status == REDIS_REPLY_STATUS) {
        ci_stat_uint64_inc(stat_updates, 1);
        return true;
    } else {
        ci_stat_uint64_inc(stat_fails, 1);
        return false; // Error?
    }
}

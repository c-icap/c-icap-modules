#include "virus_scan.h"
#include "c_icap/commands.h"
#include "c_icap/mem.h"
#include "c_icap/module.h"
#include "c_icap/debug.h"
#include "c_icap/body.h"
#include "c_icap/stats.h"
#include "../../common.h"

#include <assert.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

/**********************************/
/*    Clamd support                            */
#ifdef HAVE_FD_PASSING
char *CLAMD_SOCKET_PATH = "/var/run/clamav/clamd.ctl";
#endif
int CLAMD_PORT = -1;
char *CLAMD_HOST = "127.0.0.1";
static int VIRUSONFAILURE = 0;
#ifdef HAVE_FD_PASSING
int USE_UNIX_SOCKETS = 1;
#endif
int CLAMD_SESSION_REUSE = 100;
int CLAMD_SESSION_TIMEOUT = 10; /*seconds*/
int CLAMD_MAX_CONNECTIONS = -1;
char CLAMD_ADDR[CI_MAX_PATH];

static struct ci_conf_entry clamd_conf_variables[] = {
#ifdef HAVE_FD_PASSING
    {"ClamdSocket", &CLAMD_SOCKET_PATH, ci_cfg_set_str, NULL},
#endif
    {"ClamdHost", &CLAMD_HOST, ci_cfg_set_str, NULL},
    {"ClamdPort", &CLAMD_PORT, ci_cfg_set_int, NULL},
    {"ReportVirusOnFailure", &VIRUSONFAILURE, ci_cfg_onoff, NULL},
    {"SessionReuse", &CLAMD_SESSION_REUSE, ci_cfg_set_int, NULL},
    {"SessionTimeout", &CLAMD_SESSION_TIMEOUT, ci_cfg_set_int, NULL},
    {"MaxConnections", &CLAMD_MAX_CONNECTIONS, ci_cfg_set_int, NULL},
    {NULL, NULL, NULL, NULL}
};

int clamd_init(struct ci_server_conf *server_conf);
int clamd_post_init(struct ci_server_conf *server_conf);
void clamd_release();

CI_DECLARE_MOD_DATA common_module_t module = {
    "clamd_mod",
    clamd_init,
    clamd_post_init,
    clamd_release,
    clamd_conf_variables,
};


int clamd_scan(ci_simple_file_t *body, av_virus_info_t *vinfo);
const char *clamd_version();
const char *clamd_signature();

av_engine_t  clamd_engine = {
    "clamd",
    0x0,
    NULL,
    clamd_scan,
    clamd_signature,
    clamd_version
};

#define CLAMD_VERSION_SIZE 256
static char CLAMD_VERSION[CLAMD_VERSION_SIZE];
#define CLAMD_SIGNATURE_SIZE 256
static char CLAMD_SIGNATURE[CLAMD_SIGNATURE_SIZE];
static void clamd_set_versions();

#define CLAMD_CONN_CLOSED 0x1
#define CLAMD_CONN_ERROR 0x2
#define CLAMD_CONN_SESSION 0x4

struct clamd_conn {
    time_t start;
    time_t last_use;
    int sockd;
    int flags;
    int requests_num;
};

/*
  Connection pool with SESSION connections to clamd server.
  TODO: each clamd session connection supports multiple concurrent requests  
*/
static ci_list_t *Pool = NULL;
static ci_thread_mutex_t PoolMtx;
static ci_thread_mutex_t ConnectionsMtx;
ci_thread_cond_t ConnectionsCond;
int PoolGoingDown = 0;
int ActiveConnectionsStatID = -1;
uint64_t *ActiveConnections = NULL;
int ConnectionWaiters = 0;

/*Statistics*/
int CLAMD_STAT_NEW_CONN = -1;
int CLAMD_STAT_CONN_FAILED = -1;
int CLAMD_STAT_REUSED = -1;
int CLAMD_STAT_REQUESTS = -1;
int CLAMD_STAT_SCAN_FAILED = -1;

struct clamd_scan_info {
    int connection_status; /*-1/failed, 0/reused, 1/new */
    int io_error;
    const char *err;
};

static void clamd_release_connection(struct clamd_conn *conn, int forceClose);
static int clamd_command(struct clamd_conn *conn, const char *buf, size_t size);
static void checkPool();
static void per_process_init_pool_command(const char *name, int type, void *data);

static void check_pool_command(const char *name, int type, void *data)
{
    checkPool();
    ci_command_schedule("clamd_mod:check_connections_pool", NULL, 1);
}

static void initPool()
{
    ActiveConnectionsStatID = ci_stat_entry_register("Active connections", CI_STAT_INT64_T, "clamd_mod");
    ci_command_register_action("clamd_mod:per_process_init_pool_command", CHILD_START_CMD, NULL, per_process_init_pool_command);
    ci_command_register_action("clamd_mod:check_connections_pool", ONDEMAND_CMD,
                               NULL, check_pool_command);
}

static void per_process_init_pool_command(const char *name, int type, void *data)
{
    ci_command_schedule("clamd_mod:check_connections_pool", NULL, 1);
    // TODO: print error messags on errors.
    int ret = ci_thread_mutex_init(&PoolMtx);
    if (ret != 0)
        return;
    Pool = ci_list_create(1024, sizeof(struct clamd_conn));
    if (!Pool) {
        ci_thread_mutex_destroy(&PoolMtx);
        return;
    }
    if (ActiveConnectionsStatID > 0) {
        ActiveConnections = ci_stat_uint64_ptr(ActiveConnectionsStatID);
        ci_debug_printf(5, "Store active connections to %d/%p\n", ActiveConnectionsStatID, ActiveConnections);
    }
}

static void releasePool()
{
    if (!Pool)
        return;

    PoolGoingDown = 1;
    ci_thread_mutex_destroy(&PoolMtx);
    
    struct clamd_conn tmp;
    while(ci_list_pop(Pool, &tmp)) {
        clamd_release_connection(&tmp, 1);
    }
    ci_list_destroy(Pool);
    Pool = NULL;
}

static void checkPool()
{
    struct clamd_conn *e = NULL;
    struct clamd_conn tmp;
    if (!Pool)
        return;

    time_t now;
    time(&now);
    ci_thread_mutex_lock(&PoolMtx);
    while ((e = (struct clamd_conn *)ci_list_head(Pool)) && (now - e->last_use) > CLAMD_SESSION_TIMEOUT) {
        clamd_release_connection(e, 1);
        ci_list_pop(Pool, &tmp);
    }
    ci_thread_mutex_unlock(&PoolMtx);
}

static int poolConnection(struct clamd_conn *conn)
{
    if (!Pool)
        return 0;

    ci_thread_mutex_lock(&PoolMtx);
    if ((const struct clamd_conn *)ci_list_head(Pool) != NULL)
        ci_list_pop(Pool, conn);
    else
        conn = NULL;
    ci_thread_mutex_unlock(&PoolMtx);    
    return conn != NULL ? 1 : 0;
}

static int clamd_connect(struct clamd_conn *conn)
{
#ifdef HAVE_FD_PASSING
    struct sockaddr_un usa;
#endif
    struct sockaddr_in isa;
    struct sockaddr *addr = NULL;
    size_t addr_len = 0;

    if (!conn)
        return -1;

    conn->sockd = -1;
    conn->last_use = 0;
    conn->flags = 0;
    conn->requests_num = 1;

#ifdef HAVE_FD_PASSING
    if (USE_UNIX_SOCKETS) {
        if((conn->sockd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
            ci_debug_printf(1, "clamd_connect: Can not create unix socket to connect to clamd server!\n" );
            return -1;
        }

        memset((void *)&usa, 0, sizeof(struct sockaddr_un));
        usa.sun_family = AF_UNIX;
        strncpy(usa.sun_path, CLAMD_SOCKET_PATH, sizeof(usa.sun_path));
        usa.sun_path[sizeof(usa.sun_path) - 1] = '\0';
        addr = (struct sockaddr *)&usa;
        addr_len = sizeof(struct sockaddr_un);
    } else
#endif
    {
        if (CLAMD_PORT < 0) {
            ci_debug_printf(1, "clamd_connect: No connection method available!\n" );
            return -1;
        }

        if((conn->sockd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            ci_debug_printf(1, "clamd_connect: Can not create socket to connect to clamd server!\n" );
            return -1;
        }

        memset((void *)&isa, 0, sizeof(struct sockaddr_in));
        isa.sin_family = AF_INET;
        isa.sin_port = htons(CLAMD_PORT);
        isa.sin_addr.s_addr = inet_addr(CLAMD_HOST);
        addr = (struct sockaddr *)&isa;
        addr_len = sizeof(struct sockaddr_in);
    }


    if(connect(conn->sockd, addr, addr_len) < 0) {
        ci_debug_printf(1, "clamd_connect: Can not connect to clamd server on %s!\n", CLAMD_ADDR);
        close(conn->sockd);
        return -1;
    }

    time(&conn->start);
    ci_thread_mutex_lock(&ConnectionsMtx);
    if (ActiveConnections) (*ActiveConnections)++;
    ci_thread_mutex_unlock(&ConnectionsMtx);
    return conn->sockd;
}

static void clamd_release_connection(struct clamd_conn *conn, int forceClose)
{
    int doSignal;
    if (!conn)
        return;

    int hardClose = (conn->flags & CLAMD_CONN_CLOSED) || (conn->flags & CLAMD_CONN_ERROR);
    forceClose = forceClose || hardClose || (conn->requests_num > CLAMD_SESSION_REUSE);

    ci_thread_mutex_lock(&ConnectionsMtx);
    doSignal = (ConnectionWaiters > 0);
    ci_thread_mutex_unlock(&ConnectionsMtx);
    if (doSignal)
        ci_thread_cond_signal(&ConnectionsCond);

    if ((conn->flags & CLAMD_CONN_SESSION) && !forceClose) {
        time(&conn->last_use);
        ci_thread_mutex_lock(&PoolMtx);
        ci_list_push_back(Pool, conn);
        ci_thread_mutex_unlock(&PoolMtx);
        return;
    }

    if (!hardClose && (conn->flags & CLAMD_CONN_SESSION))
        clamd_command(conn, "zEND", 5);
    close(conn->sockd);
    conn->sockd = -1;
    ci_thread_mutex_lock(&ConnectionsMtx);
    if (ActiveConnections) (*ActiveConnections)--;
    ci_thread_mutex_unlock(&ConnectionsMtx);
}

static int clamd_single_connection(struct clamd_conn *conn)
{
    clamd_connect(conn);
    return conn->sockd;
}

static int clamd_session_connection(struct clamd_conn *conn)
{
    if (!Pool)
        return clamd_single_connection(conn);

retryPool:
    if (poolConnection(conn)) {
        conn->requests_num++;
        ci_debug_printf(8, "Reuse session connection to clamd: %d\n", conn->sockd);
        return conn->sockd;
    }
    
    ci_thread_mutex_lock(&ConnectionsMtx);
    if ((CLAMD_MAX_CONNECTIONS > 0) && ActiveConnections && ((*ActiveConnections + ConnectionWaiters) >= CLAMD_MAX_CONNECTIONS)) {
        ConnectionWaiters++;
        ci_thread_cond_wait(&ConnectionsCond, &ConnectionsMtx);
        ConnectionWaiters--;
        ci_thread_mutex_unlock(&ConnectionsMtx);
        goto retryPool;
    }
    ci_thread_mutex_unlock(&ConnectionsMtx);

    if (clamd_connect(conn) < 0)
        return -1;

    if (clamd_command(conn, "zIDSESSION", 11) < 0) {
        clamd_release_connection(conn, 1);
        return -1;
    }
    conn->flags |= CLAMD_CONN_SESSION;
    ci_debug_printf(8, "Create new session connection to clamd: %d\n", conn->sockd);
    return conn->sockd;
}

static int clamd_command(struct clamd_conn *conn, const char *buf, size_t size)
{
    int bytes = 0;
    size_t remains = size;

    if (!conn || conn->sockd < 0)
        return -1;

    while(remains) {
        do {
            bytes = send(conn->sockd, buf, remains, 0);
        }  while (bytes == -1 && errno == EINTR);

        if (bytes <= 0)
            return bytes;

        buf += bytes;
        remains -= bytes;
     }
    return size;
}

static const char *clamd_response(struct clamd_conn *conn, char *buf, size_t size)
{
    char *s;
    int bytes, written, remains;

    if (!conn || conn->sockd < 0)
        return NULL;

    int done = 0;
    size --;  /* left 1 byte for '\0' */
    remains = size;
    s = buf;
    do {
        do {
            bytes = recv(conn->sockd, s, remains, 0);
        }  while (bytes == -1 && errno == EINTR);

        if (bytes < 0) {
            conn->flags &= CLAMD_CONN_ERROR;
            return NULL;
        }

        if (bytes == 0)
            conn->flags &= CLAMD_CONN_CLOSED;
        else {
            s += bytes;
            remains -= bytes;
        }

        done = *(s - 1) == '\0' || (conn->flags & CLAMD_CONN_CLOSED);
    } while (remains > 0 && !done);

    /*mark the eof even if we read the '\0' at the end of command*/
    written = size - remains;
    buf[written] = '\0';

    if (!done) {
        /*To huge response? Mark connection as error*/
        conn->flags &= CLAMD_CONN_ERROR;
    }

    if ((conn->flags & CLAMD_CONN_SESSION)) {
        // Parse the requestID before return the response
        int reqId = strtol(buf, NULL, 0);
        if (!(s = strchr(buf, ':'))) {
            ci_debug_printf(6, "Got wrong response from clamd: '%s'\n", buf);
            conn->flags &= CLAMD_CONN_ERROR;
        } else {
            s += 2; /*':' plus a space*/
            ci_debug_printf(6, "Got Session request ID %d (/%d): %s\n", reqId, conn->requests_num, s);
        }
        return s;
    }

    return buf;
}

static int send_filename(struct clamd_conn *conn, const char *filename)
{
    int len;
    char buf[CI_MAX_PATH];

    if (!conn || conn->sockd < 0)
        return -1;

    if (! filename) {
        ci_debug_printf(1, "send_filename: Filename to be sent to clamd cannot be NULL!\n");
        return 0;
    }
    ci_debug_printf(5, "send_filename: File '%s' should be scanned.\n", filename);

    len = snprintf(buf, sizeof(buf),  "zSCAN %s", filename);
    if (len >= sizeof(buf)) {
        ci_debug_printf(1, "Too long filename: %s\n", filename);
        return 0;
    }

    ci_debug_printf(5, "send_filename: Send '%s' to clamd (len=%d)\n", buf, len);
    if (clamd_command(conn, buf, len + 1) <= 0) {
        return 0;
    }

    return 1;
}

#ifdef HAVE_FD_PASSING
static int send_fd(struct clamd_conn *conn, int fd)
{
    struct msghdr mh;
    struct cmsghdr cmh[2];
    struct iovec iov;
    int fd_to_send, ret;

    if (!conn || conn->sockd < 0)
        return 0;

    if (clamd_command(conn, "zFILDES", 8) <= 0) {
        return 0;
    }

    memset(&mh,0,sizeof(mh));
    mh.msg_name = 0;
    mh.msg_namelen = 0;
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = (void *)&cmh[0];
    mh.msg_controllen = sizeof(cmh[0]) + sizeof(int);
    mh.msg_flags = 0;
    iov.iov_base = "";
    iov.iov_len = 1;
    cmh[0].cmsg_level = SOL_SOCKET;
    cmh[0].cmsg_type = SCM_RIGHTS;
    cmh[0].cmsg_len = sizeof(cmh[0]) + sizeof(int);
    fd_to_send = dup(fd);
    *(int *)&cmh[1] = fd_to_send;
    ret = sendmsg(conn->sockd,&mh,0);
    close(fd_to_send);

    if (ret<0)
        return 0;

    return 1;
}
#endif

int clamd_init(struct ci_server_conf *server_conf)
{
    initPool();
    CLAMD_STAT_NEW_CONN = ci_stat_entry_register("New connections", CI_STAT_INT64_T, "clamd_mod");
    CLAMD_STAT_CONN_FAILED = ci_stat_entry_register("Failed connections", CI_STAT_INT64_T, "clamd_mod");
    CLAMD_STAT_REUSED = ci_stat_entry_register("Reused connections", CI_STAT_INT64_T, "clamd_mod");
    CLAMD_STAT_REQUESTS = ci_stat_entry_register("Requests", CI_STAT_INT64_T, "clamd_mod");
    CLAMD_STAT_SCAN_FAILED = ci_stat_entry_register("Scan failed", CI_STAT_INT64_T, "clamd_mod");
    return CI_OK;
}

int clamd_post_init(struct ci_server_conf *server_conf)
{
    /* try connect to see if clamd running*/
    char buf[1024];
    int ret;
    struct clamd_conn conn;

    ret = ci_thread_mutex_init(&ConnectionsMtx);
    if (ret != 0) {
        ci_debug_printf(1, "clamd_init: Error on mutex initialization\n");
        return CI_ERROR;
    }
    ret = ci_thread_cond_init(&ConnectionsCond);
    if (ret != 0) {
        ci_debug_printf(1, "clamd_init: Error on pthread_cond initialization\n");
        return CI_ERROR;
    }

    if (CLAMD_PORT > 0) {
        ci_debug_printf(5, "clamd_init: Use TCP socket\n");
#ifdef HAVE_FD_PASSING
        USE_UNIX_SOCKETS = 0;
#endif
        snprintf(CLAMD_ADDR, sizeof(CLAMD_ADDR), "%s:%d", CLAMD_HOST, CLAMD_PORT);
    } else {
#ifdef HAVE_FD_PASSING
        ci_debug_printf(5, "clamd_init: Use Unix socket\n");
        USE_UNIX_SOCKETS = 1;
        strncpy(CLAMD_ADDR, CLAMD_SOCKET_PATH, sizeof(CLAMD_ADDR));
        CLAMD_ADDR[sizeof(CLAMD_ADDR) - 1] = '\0';
#else
        ci_debug_printf(1, "clamd_init: Clamd TCP port is not defined and requored\n");
        return CI_ERROR;
#endif
    }
    ci_debug_printf(5, "clamd_init: connect address %s\n", CLAMD_ADDR);

    ret = clamd_single_connection(&conn);
    if (!ret) {
        ci_debug_printf(1, "clamd_init: Error while connecting to server\n");
        return CI_ERROR;
    }

    if (clamd_command(&conn, "zPING", 6) <= 0) {
        ci_debug_printf(1, "clamd_init: Error while sending command to clamd server\n");
        clamd_release_connection(&conn, 1);
        return CI_ERROR;
    }
    const char *response = clamd_response(&conn, buf, 1024);

    if (!response || strcmp(response, "PONG") != 0) {
        ci_debug_printf(1, "clamd_init: Not valid response from server: %s\n", buf);
        clamd_release_connection(&conn, 1);
        return CI_ERROR;
    }

    clamd_release_connection(&conn, 0);

    clamd_set_versions();
    av_register_engine(&clamd_engine);
    av_reload_istag();
    return CI_OK;
}

void clamd_release()
{
    releasePool();
    ci_thread_mutex_destroy(&ConnectionsMtx);
    ci_thread_cond_destroy(&ConnectionsCond);
}

int clamd_get_versions(unsigned int *level, unsigned int *version, char *str_version, size_t str_version_len)
{
    char buffer[1024];
    const char *s;
    int ret, v1, v2, v3;
    struct clamd_conn conn;

    ret = clamd_single_connection(&conn);
    if (ret < 0)
        return 0;

    if (clamd_command(&conn, "zVERSION", 9) <= 0) {
        ci_debug_printf(1, "clamd_get_versions: Error while sending command to clamd server\n");
        clamd_release_connection(&conn, 1);
        return 0;
    }
    const char *response = clamd_response(&conn, buffer, 1024);
    if (!response) { //error
        ci_debug_printf(1, "clamd_get_versions: Error reading response from clamd server\n");
        clamd_release_connection(&conn, 1);
        return 0;
    }

    if (strncasecmp(response, "ClamAV", 6) != 0) {
        ci_debug_printf(1, "clamd_get_versions: Wrong response from clamd server: %s\n", response);
        clamd_release_connection(&conn, 1);
        return 0;
    }

    s = strchr(response, '/');
    *version = 0;
    if (s) {
        ++s;
        *version = strtol(s, NULL, 10);
    }
    v1 = v2 = v3 = 0;
    ret = sscanf(response + 7, "%d.%d.%d", &v1, &v2, &v3);
    if (*version == 0 || ret < 2) {
        ci_debug_printf(1, "clamd_get_versions: WARNING: Can not parse response from clamd server: %s\n", response);
    }

    snprintf(str_version, str_version_len, "%d%d%d", v1,v2,v3);
    *level = 0; /*We are not able to retrieve level*/

    ci_debug_printf(6, "clamd_get_versions: Succesfully parse response from clamd server: %s (version: %d, strversion: '%s')\n", response, *version, str_version);
    clamd_release_connection(&conn, 0);
    return 1;
}

static int clamd_scan_simple_file(ci_simple_file_t *body, av_virus_info_t *vinfo, struct clamd_scan_info *sinfo)
{
    char buffer[1024], *s, *f, *v, *filename;
    int ret, status;
    av_virus_t a_virus;
    struct clamd_conn conn;
    int fd = body->fd;

    vinfo->virus_name[0] = '\0';
    vinfo->virus_found = 0;

    ret = clamd_session_connection(&conn);
    if (ret < 0) {
        ci_debug_printf(1, "clamd_scan: Unable to connect to clamd server!\n");
        sinfo->connection_status = -1;
        sinfo->err = "Clamd connection failed";
        return 0;
    }

    sinfo->connection_status = conn.requests_num == 1 ? 1/*new connection*/ : 0 /*reused*/;

#ifdef HAVE_FD_PASSING
    if (USE_UNIX_SOCKETS) {
        ret = send_fd(&conn, fd);
    } else
#endif
    {
        /*
          Change the file mode to 0640, to be readable by
          a clamd daemon having the same group with us
        */
        fchmod(fd, 0666);
        filename = body->filename;
        ci_debug_printf(5, "clamd_scan: Scan file '%s'\n", body->filename);
        ret = send_filename(&conn, filename);
    }
    const char *response = clamd_response(&conn, buffer, sizeof(buffer));
    if (ret < 0) {
        ci_debug_printf(1, "clamd_scan: Error reading response from clamd server!\n");
        clamd_release_connection(&conn, 1);
        sinfo->err = "Clamd response failed";
        sinfo->io_error = 1;
        return 0;
    }

    ci_debug_printf(5, "clamd_scan response: '%s'\n", response);
    s = strchr(response, ':');
    if (!s) {
        ci_debug_printf(1, "clamd_scan: parse error. Response string: %s", response);
        clamd_release_connection(&conn, 1);
        sinfo->err = "Clamd unknown response";
        return 0;
    }
    s++; /*point after ':'*/
    while (*s == ' ')  s++;

    status = 1;
    if ((f = strstr(s, "FOUND"))) {
        /* A virus found */
        vinfo->virus_found = 1;
        for ( v = vinfo->virus_name; s != f && (v - vinfo->virus_name)< AV_NAME_SIZE; v++, s++)
            *v = *s;
        /*There is a space before "FOUND" and maybe v points after the end of string*/
        *(v - 1) = '\0';

        vinfo->viruses = ci_vector_create(512);
        strcpy(a_virus.virus, vinfo->virus_name); // Both of ize AV_NAME_SIZE
        a_virus.type[0]= '\0';
        a_virus.problemID = 0;
        a_virus.action = AV_NONE;
        ci_vector_add(vinfo->viruses, &a_virus, sizeof(av_virus_t));
    } else if (strncmp(s, "OK", 2) != 0) {
        ci_debug_printf(1, "clamd_scan: Error scanning file. Response string: %s", response);
        status = 0;
        sinfo->err = "Clamd scan error";
    }

    clamd_release_connection(&conn, 0);
    return status;
}

int clamd_scan(ci_simple_file_t *body, av_virus_info_t *vinfo)
{
    struct clamd_scan_info sinfo = {0, 0, NULL};
    int ret = clamd_scan_simple_file(body, vinfo, &sinfo);
    if (!ret && VIRUSONFAILURE) {
        strncpy(vinfo->virus_name, (sinfo.err != NULL ? sinfo.err : "clamd failed"), AV_NAME_SIZE);
        vinfo->virus_name[AV_NAME_SIZE - 1] = '\0';
        vinfo->virus_found = 1;
        return 1;
    }
    int connWhat = (sinfo.connection_status == 1 ? CLAMD_STAT_NEW_CONN :
                    (sinfo.connection_status == 0 ? CLAMD_STAT_REUSED :CLAMD_STAT_CONN_FAILED));

    ci_stat_item_t stats[3] = {
        {CI_STAT_INT64_T, connWhat, 1},
        {CI_STAT_INT64_T, CLAMD_STAT_REQUESTS, 1},
        {CI_STAT_INT64_T, CLAMD_STAT_SCAN_FAILED, (sinfo.err != NULL ? 1 : 0)},
    };
    ci_stat_update(stats, 3);
    return ret;
}

static void clamd_set_versions()
{
    char str_version[64];
    int cfg_version = 0;
    unsigned int version = 0, level = 0;

    clamd_get_versions(&level, &version, str_version, sizeof(str_version));

    /*Set clamav signature*/
    snprintf(CLAMD_SIGNATURE, CLAMD_SIGNATURE_SIZE - 1, "-%.3d-%s-%u%u",
             cfg_version, str_version, level, version);

     /*set the clamav version*/
     snprintf(CLAMD_VERSION, CLAMD_VERSION_SIZE - 1, "%s/%d", str_version, version);
}

const char *clamd_version()
{
    return CLAMD_VERSION;
}

const char *clamd_signature()
{
    return CLAMD_SIGNATURE;
}

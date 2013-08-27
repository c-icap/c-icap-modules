#include "virus_scan.h"
#include "commands.h"
#include "mem.h"
#include "module.h"
#include "debug.h"
#include "../../common.h"

#include <assert.h>
#ifdef HAVE_FD_PASSING
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#endif

/**********************************/
/*    Clamd support                            */
#ifdef HAVE_FD_PASSING
char *CLAMD_SOCKET_PATH = "/var/run/clamav/clamd.ctl";

static struct ci_conf_entry clamd_conf_variables[] = {
    {"ClamdSocket", &CLAMD_SOCKET_PATH, ci_cfg_set_str, NULL},
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


int clamd_scan(struct av_body_data *body, av_virus_info_t *vinfo);
const char *clamd_version();
const char *clamd_signature();

av_engine_t  clamd_engine = {
    "clamd",
    0x0, 
    clamd_scan,
    clamd_signature,
    clamd_version
};

#define CLAMD_VERSION_SIZE 64
static char CLAMD_VERSION[CLAMD_VERSION_SIZE];
#define CLAMD_SIGNATURE_SIZE SERVICE_ISTAG_SIZE
static char CLAMD_SIGNATURE[CLAMD_SIGNATURE_SIZE];
static void clamd_set_versions();

static int clamd_connect()
{
    struct sockaddr_un usa;
    int sockd;

    if((sockd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        ci_debug_printf(1, "clamd_connect: Can not create socket to connect to clamd server!\n" );
	return -1;
    }

    memset((void *)&usa, 0, sizeof(struct sockaddr_un));
    usa.sun_family = AF_UNIX;
    strncpy(usa.sun_path, CLAMD_SOCKET_PATH, sizeof(usa.sun_path));
    usa.sun_path[sizeof(usa.sun_path) - 1] = '\0';
    
    if(connect(sockd, (struct sockaddr *)&usa, sizeof(struct sockaddr_un)) < 0) {
        ci_debug_printf(1, "clamd_connect: Can not connect to clamd server!\n" );
        close(sockd);
	return -1;
    }

    return sockd;
}

static void clamd_release_connection(int sockfd)
{
    close(sockfd);
}

static int clamd_command(int fd, const char *buf, size_t size)
{
    int bytes = 0;
    size_t remains = size;
    while(remains) {
        do {
            bytes = send(fd, buf, remains, 0);
        }  while (bytes == -1 && errno == EINTR);

        if (bytes <= 0)
            return bytes;

        buf += bytes;
        remains -= bytes;
     }
    return size;
}

static int clamd_response(int fd, char *buf, size_t size)
{
    char buffer[1024], *s;
    int bytes, written, remains;
    size --;  /*left 1 byte for '\0' */
    remains = size;
    s = buf;
    do {
        do {
            bytes = recv(fd, s, remains, 0);
        }  while (bytes == -1 && errno == EINTR);

        if (bytes < 0)
            return bytes;

        if (bytes == 0) {
            written = size - remains;
            buf[written] = '\0';
            return written; /*return read bytes*/
        }

        s += bytes; 
        remains -= bytes;
    } while(remains > 0 );

    /*Our buffer is full. try read untill eof*/
    do {
         do {
             bytes = recv(fd, buffer, 1024, 0);
         }  while (bytes == -1 && errno == EINTR);
    } while(bytes > 0);

    if (bytes < 0)
        return -1;

    written = size - remains;
    buf[written] = '\0';
    return written; /*return read bytes*/
}

static int send_fd(int sockfd, int fd)
{
    struct msghdr mh;
    struct cmsghdr cmh[2];
    struct iovec iov;
    int fd_to_send, ret;

    if (clamd_command(sockfd, "zFILDES", 8) <= 0) {
        return 0;
    }

    memset(&mh,0,sizeof(mh));
    mh.msg_name = 0;
    mh.msg_namelen = 0;
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = (caddr_t)&cmh[0];
    mh.msg_controllen = sizeof(cmh[0]) + sizeof(int);
    mh.msg_flags = 0;
    iov.iov_base = "";
    iov.iov_len = 1;
    cmh[0].cmsg_level = SOL_SOCKET;
    cmh[0].cmsg_type = SCM_RIGHTS;
    cmh[0].cmsg_len = sizeof(cmh[0]) + sizeof(int);
    fd_to_send = dup(fd);
    *(int *)&cmh[1] = fd_to_send;
    ret = sendmsg(sockfd,&mh,0);
    clamd_release_connection(fd_to_send);

    if (ret<0)
        return 0;

    return 1;
}

int clamd_init(struct ci_server_conf *server_conf)
{
    return CI_OK;
}

int clamd_post_init(struct ci_server_conf *server_conf)
{
    /* try connect to see if clamd running*/
    char buf[1024];
    int ret;
    int sockfd = clamd_connect();
    if (!sockfd) {
        ci_debug_printf(1, "clamd_init: Error while connecting to server\n");
        return CI_ERROR;
    }

    if (clamd_command(sockfd, "zPING", 6) <= 0) {
        ci_debug_printf(1, "clamd_init: Error while sending command to clamd server\n");
        clamd_release_connection(sockfd);
        return CI_ERROR;
    }
    ret = clamd_response(sockfd, buf, 1024);

    if (ret <= 0 || strcmp(buf, "PONG") != 0) {
        ci_debug_printf(1, "clamd_init: Not valid response from server: %s\n", buf);
        clamd_release_connection(sockfd);
        return CI_ERROR;
    }

    clamd_release_connection(sockfd);

    clamd_set_versions();
    av_register_engine(&clamd_engine);
    av_reload_istag();
    return CI_OK;
}

void clamd_release()
{
}

int clamd_get_versions(unsigned int *level, unsigned int *version, char *str_version, size_t str_version_len)
{
    char buf[1024];
    int ret, v1, v2, v3;
    int sockfd = clamd_connect();
    if (sockfd < 0)
        return 0;

    if (clamd_command(sockfd, "zVERSION", 9) <= 0) {
        ci_debug_printf(1, "clamd_get_versions: Error while sending command to clamd server\n");
        clamd_release_connection(sockfd);
        return 0;
    }
    ret = clamd_response(sockfd, buf, 1024);
    if (ret <= 0) { //error
        ci_debug_printf(1, "clamd_get_versions: Error reading response from clamd server\n");
        clamd_release_connection(sockfd);
        return 0;
    }

    ret = sscanf(buf, "ClamAV %d.%d.%d/%d/", &v1, &v2, &v3, version);
    if (ret != 4) {
        ci_debug_printf(1, "clamd_get_versions: parse error. Response string: %s\n", buf);
        clamd_release_connection(sockfd);
        return 0;
    }
    snprintf(str_version, str_version_len, "%d%d%d", v1,v2,v3);
    str_version[str_version_len - 1] = '\0';
    *level = 0; /*We are not able to retrieve level*/

    clamd_release_connection(sockfd);
    return 1;
}

int clamd_scan(struct av_body_data *body, av_virus_info_t *vinfo)
{
    char resp[1024], *s, *f, *v;
    int sockfd, ret, status;
    int fd = body->decoded_fd >= 0 ? body->decoded_fd : body->store.file->fd;
    /*clamd can scan only file data.*/
    assert(body->type == AV_BT_FILE);

    vinfo->virus_name[0] = '\0';
    vinfo->virus_found = 0;

    sockfd = clamd_connect();
    if (sockfd < 0) {
        ci_debug_printf(1, "clamd_scan: Unable to connect to clamd server!\n");
        return 0;
    }

    ret = send_fd(sockfd, fd);
    ret = clamd_response(sockfd, resp, sizeof(resp));
    if (ret < 0) {
        ci_debug_printf(1, "clamd_scan: Error reading response from clamd server!\n");
        clamd_release_connection(sockfd);
        return 0;
    }

    ci_debug_printf(5, "clamd_scan response: '%s'\n", resp);
    s = strchr(resp, ':');
    if (!s) {
        ci_debug_printf(1, "clamd_scan: parse error. Response string: %s", resp);
        clamd_release_connection(sockfd);
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
    } else if (strncmp(s, "OK", 2) != 0) {
        ci_debug_printf(1, "clamd_scan: Error scanning file. Response string: %s", resp);
        status = 0;
    }

    clamd_release_connection(sockfd);
    return status;
}

static void clamd_set_versions()
{
    char str_version[64];
    int cfg_version = 0;
    unsigned int version, level;

    clamd_get_versions(&level, &version, str_version, sizeof(str_version));

    /*Set clamav signature*/
    snprintf(CLAMD_SIGNATURE, CLAMD_SIGNATURE_SIZE - 1, "-%.3d-%s-%u%u",
             cfg_version, str_version, level, version);
    CLAMD_SIGNATURE[CLAMD_SIGNATURE_SIZE - 1] = '\0';

     /*set the clamav version*/
     snprintf(CLAMD_VERSION, CLAMD_VERSION_SIZE - 1, "%s/%d", str_version, version);
     CLAMD_VERSION[CLAMD_VERSION_SIZE - 1] = '\0';
}

const char *clamd_version()
{
    return CLAMD_VERSION;
}

const char *clamd_signature()
{
    return CLAMD_SIGNATURE;
}

#endif  /*HAVE_FD_PASSING*/

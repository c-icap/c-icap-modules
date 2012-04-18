/*
 *  Copyright (C) 2004-2010 Christos Tsantilas
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "virus_scan.h"
#include "ci_threads.h"
#include "mem.h"
#include "debug.h"
#include "../../common.h"
#include <clamav.h>

#ifdef HAVE_FD_PASSING
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#endif

extern long int CLAMAV_MAXRECLEVEL;
extern long int CLAMAV_MAX_FILES;
extern ci_off_t CLAMAV_MAXFILESIZE;
extern char *CLAMAV_TMP;
extern int USE_CLAMD;
extern char *CLAMD_SOCKET_PATH;


#if defined(HAVE_LIBCLAMAV_09X) || defined(HAVE_LIBCLAMAV_095)
#define CL_ENGINE struct cl_engine
#else
#define CL_ENGINE struct cl_node
#endif

struct virus_db {
     CL_ENGINE *db;
     int refcount;
};

#ifndef HAVE_LIBCLAMAV_095
struct cl_limits limits;
#endif

struct virus_db *virusdb = NULL;
struct virus_db *old_virusdb = NULL;
ci_thread_mutex_t db_mutex;

int clamd_init();
int clamd_get_versions(unsigned int *level, unsigned int *version, char *str_version, size_t str_version_len);
int clamd_scan(int fd, char **virus);

int clamav_init()
{
    int ret;

#ifdef HAVE_FD_PASSING
    if (USE_CLAMD)
        return clamd_init();
#endif

    /*Else proceed loading the clamav virus database*/
    ret = clamav_init_virusdb();
     if (!ret)
         return 0;

#ifndef HAVE_LIBCLAMAV_095
     memset(&limits, 0, sizeof(struct cl_limits));
     limits.maxfiles = CLAMAV_MAX_FILES;
     limits.maxfilesize = CLAMAV_MAXFILESIZE;
     limits.maxreclevel = CLAMAV_MAXRECLEVEL;

#ifdef HAVE_LIBCLAMAV_LIMITS_MAXRATIO
     limits.maxratio = 200;     /* maximal compression ratio */
#endif

     limits.archivememlim = 0;  /* disable memory limit for bzip2 scanner */
#else
     if(!virusdb) /* ??????? */
	 return 0;
     
     ret = cl_engine_set_num(virusdb->db, CL_ENGINE_MAX_FILES, CLAMAV_MAX_FILES); 
     if(ret != CL_SUCCESS)
	 ci_debug_printf(1, "srvclamav_post_init_service: WARNING! cannot set CL_ENGINE_MAX_FILES\n");
     ret = cl_engine_set_num(virusdb->db, CL_ENGINE_MAX_FILESIZE, CLAMAV_MAXFILESIZE); 
     if(ret != CL_SUCCESS)
	 ci_debug_printf(1, "srvclamav_post_init_service: WARNING! cannot set CL_ENGINE_MAXFILESIZE\n");
     ret = cl_engine_set_num(virusdb->db, CL_ENGINE_MAX_RECURSION, CLAMAV_MAXRECLEVEL); 
     if(ret != CL_SUCCESS)
	 ci_debug_printf(1, "srvclamav_post_init_service: WARNING! cannot set CL_ENGINE_MAX_RECURSION\n");
#endif
     return 1;
}

int clamav_init_virusdb()
{
     int ret;
     unsigned int no = 0;
     virusdb = malloc(sizeof(struct virus_db));
     memset(virusdb, 0, sizeof(struct virus_db));
     if (!virusdb)
          return 0;
#ifdef HAVE_LIBCLAMAV_095
     if((ret = cl_init(CL_INIT_DEFAULT))) {
        ci_debug_printf(1, "!Can't initialize libclamav: %s\n", cl_strerror(ret));
        return 0;
    }

     if(!(virusdb->db = cl_engine_new())) {
	 ci_debug_printf(1, "Clamav DB load: Cannot create new clamav engine\n");
	 return 0;
     }

     if ((ret = cl_load(cl_retdbdir(), virusdb->db, &no, CL_DB_STDOPT))) {
          ci_debug_printf(1, "Clamav DB load: cl_load failed: %s\n",
                          cl_strerror(ret));
#elif defined(HAVE_LIBCLAMAV_09X)
     if ((ret = cl_load(cl_retdbdir(), &(virusdb->db), &no, CL_DB_STDOPT))) {
          ci_debug_printf(1, "Clamav DB load: cl_load failed: %s\n",
                          cl_strerror(ret));
#else
     if ((ret = cl_loaddbdir(cl_retdbdir(), &(virusdb->db), &no))) {
          ci_debug_printf(1, "cl_loaddbdir: %s\n", cl_perror(ret));
#endif
          return 0;
     }
#ifdef HAVE_LIBCLAMAV_095
     if ((ret = cl_engine_compile(virusdb->db))) {
#else
     if ((ret = cl_build(virusdb->db))) {
#endif
          ci_debug_printf(1, "Database initialization error: %s\n",
                          cl_strerror(ret));
#ifdef HAVE_LIBCLAMAV_095
	  cl_engine_free(virusdb->db);
#else
          cl_free(virusdb->db);
#endif
          free(virusdb);
          virusdb = NULL;
          return 0;
     }

     if (CLAMAV_TMP) {
#ifdef HAVE_LIBCLAMAV_095
         if(virusdb)
             cl_engine_set_str(virusdb->db, CL_ENGINE_TMPDIR, CLAMAV_TMP); 
#else
         cl_settempdir(CLAMAV_TMP, 0);
#endif
     }

     ci_thread_mutex_init(&db_mutex);
     virusdb->refcount = 1;
     old_virusdb = NULL;
     return 1;
}

/*
  Instead of using struct virus_db and refcount's someone can use the cl_dup function
  of clamav library, but it is  undocumented so I did not use it.
  The following implementation we are starting to reload clamav db while threads are 
  scanning for virus but we are not allow any child to start a new scan until we are 
  loading DB.
*/
/*#define DB_NO_FULL_LOCK 1*/
#undef DB_NO_FULL_LOCK
int clamav_reload_virusdb()
{
     struct virus_db *vdb = NULL;
     int ret;
     unsigned int no = 0;

#ifdef HAVE_FD_PASSING
     if (USE_CLAMD)
         return 1; /*Do nothing*/
#endif

     ci_thread_mutex_lock(&db_mutex);
     if (old_virusdb) {
          ci_debug_printf(1, "Clamav DB reload pending, cancelling.\n");
          ci_thread_mutex_unlock(&db_mutex);
          return 0;
     }
#ifdef DB_NO_FULL_LOCK
     ci_thread_mutex_unlock(&db_mutex);
#endif
     vdb = malloc(sizeof(struct virus_db));
     if (!vdb)
          return 0;
     memset(vdb, 0, sizeof(struct virus_db));
     ci_debug_printf(2, "db_reload command, going to load db\n");
#ifdef HAVE_LIBCLAMAV_095
     if(!(vdb->db = cl_engine_new())) {
	 ci_debug_printf(1, "Clamav DB load: Cannot create new clamav engine\n");
	 return 0;
     }
     if ((ret = cl_load(cl_retdbdir(), vdb->db, &no, CL_DB_STDOPT))) {
          ci_debug_printf(1, "Clamav DB reload: cl_load failed: %s\n",
                          cl_strerror(ret));
#elif defined(HAVE_LIBCLAMAV_09X)
     if ((ret = cl_load(cl_retdbdir(), &(vdb->db), &no, CL_DB_STDOPT))) {
          ci_debug_printf(1, "Clamav DB reload: cl_load failed: %s\n",
                          cl_strerror(ret));
#else
     if ((ret = cl_loaddbdir(cl_retdbdir(), &(vdb->db), &no))) {
          ci_debug_printf(1, "Clamav DB reload: cl_loaddbdir failed: %s\n",
                          cl_perror(ret));
#endif
          return 0;
     }
     ci_debug_printf(2, "Clamav DB loaded. Going to build\n");
#ifdef HAVE_LIBCLAMAV_095
     if ((ret = cl_engine_compile(vdb->db))) {
#else
     if ((ret = cl_build(vdb->db))) {
#endif
          ci_debug_printf(1,
                          "Clamav DB reload: Database initialization error: %s\n",
                          cl_strerror(ret));
#ifdef HAVE_LIBCLAMAV_095
	  cl_engine_free(vdb->db);
#else
          cl_free(vdb->db);
#endif
          free(vdb);
          vdb = NULL;
#ifdef DB_NO_FULL_LOCK
          /*no lock needed */
#else
          ci_thread_mutex_unlock(&db_mutex);
#endif
          return 0;
     }
     ci_debug_printf(2, "Loading Clamav DB done. Releasing old DB.....\n");
#ifdef DB_NO_FULL_LOCK
     ci_thread_mutex_lock(&db_mutex);
#endif
     old_virusdb = virusdb;
     old_virusdb->refcount--;
     ci_debug_printf(9, "Old VirusDB refcount:%d\n", old_virusdb->refcount);
     if (old_virusdb->refcount <= 0) {
#ifdef HAVE_LIBCLAMAV_095
	  cl_engine_free(old_virusdb->db);
#else
          cl_free(old_virusdb->db);
#endif
          free(old_virusdb);
          old_virusdb = NULL;
     }
     virusdb = vdb;
     virusdb->refcount = 1;
     ci_thread_mutex_unlock(&db_mutex);
     return 1;
}

CL_ENGINE *get_virusdb()
{
     struct virus_db *vdb;
     ci_thread_mutex_lock(&db_mutex);
     vdb = virusdb;
     vdb->refcount++;
     ci_thread_mutex_unlock(&db_mutex);
     return vdb->db;
}

void release_virusdb(CL_ENGINE * db)
{
     ci_thread_mutex_lock(&db_mutex);
     if (virusdb && db == virusdb->db)
          virusdb->refcount--;
     else if (old_virusdb && (db == old_virusdb->db)) {
          old_virusdb->refcount--;
          ci_debug_printf(3, "Old VirusDB refcount: %d\n",
                          old_virusdb->refcount);
          if (old_virusdb->refcount <= 0) {
#ifdef HAVE_LIBCLAMAV_095
	      cl_engine_free(old_virusdb->db);
#else
               cl_free(old_virusdb->db);
#endif
               free(old_virusdb);
               old_virusdb = NULL;
          }
     }
     else {
          ci_debug_printf(1,
                          "BUG in srv_clamav service! please contact the author\n");
     }
     ci_thread_mutex_unlock(&db_mutex);
}

void clamav_destroy_virusdb()
{
     if (virusdb) {
#ifdef HAVE_LIBCLAMAV_095
	  cl_engine_free(virusdb->db);
#else
          cl_free(virusdb->db);
#endif
          free(virusdb);
          virusdb = NULL;
     }
     if (old_virusdb) {
#ifdef HAVE_LIBCLAMAV_095
	  cl_engine_free(old_virusdb->db);
#else
          cl_free(old_virusdb->db);
#endif
          free(old_virusdb);
          old_virusdb = NULL;
     }
}

int clamav_scan(int fd, char **virus)
{
    CL_ENGINE *vdb;
    const char *virname;
    int ret, status;
    unsigned long scanned_data;

#ifdef HAVE_FD_PASSING
    if (USE_CLAMD)
        return clamd_scan(fd, virus); 
#endif

    *virus = NULL;
     vdb = get_virusdb();
#ifndef HAVE_LIBCLAMAV_095
     ret =
         cl_scandesc(fd, &virname, &scanned_data, vdb, &limits,
                     CL_SCAN_STDOPT);
#else
     ret =
         cl_scandesc(fd, &virname, &scanned_data, vdb,
                     CL_SCAN_STDOPT);
#endif

     status = 1;
     if (ret == CL_VIRUS) {
         *virus = ci_buffer_alloc(strlen(virname)+1);
         if (!*virus) {
             ci_debug_printf(1, "clamav_scan: Error allocating buffer to write virus name %s!\n", virname);
             status = 0;
         }
         else
             strcpy(*virus, virname);
     }
     else if (ret != CL_CLEAN) {
         ci_debug_printf(1,
                         "srvClamAv module: An error occured while scanning the data\n");
         status = 0;
     }
     release_virusdb(vdb);
     return status;
}

int clamav_get_versions(unsigned int *level, unsigned int *version, char *str_version, size_t str_version_len)
{
     char *daily_path;
     char *s1, *s2;
     struct cl_cvd *d1;
     struct stat daily_stat;

#ifdef HAVE_FD_PASSING
     if (USE_CLAMD)
         return clamd_get_versions(level, version, str_version, str_version_len);
#endif

     /*instead of 128 should be strlen("/daily.inc/daily.info")+1*/
     daily_path = malloc(strlen(cl_retdbdir()) + 128);
     if (!daily_path) {           /*???????? */
          ci_debug_printf(1, "clamav_get_versions: Error allocating memory!\n");
          return 0;
     }
     sprintf(daily_path, "%s/daily.cvd", cl_retdbdir());
     
     if(stat(daily_path,&daily_stat) != 0){
	 /* if the clamav_lib_path/daily.cvd does not exists
	  */
	 sprintf(daily_path, "%s/daily.cld", cl_retdbdir());
     
	 if(stat(daily_path,&daily_stat) != 0){
	     /*
	       else try to use the clamav_lib_path/daily.inc/daly.info file instead" */
	     sprintf(daily_path, "%s/daily.inc/daily.info", cl_retdbdir());
	 }
     }

     if ((d1 = cl_cvdhead(daily_path))) {
          *version = d1->version;
          free(d1);
     }
     else
         *version = 0;
     free(daily_path);

     s1 = (char *) cl_retver();
     s2 = str_version;
     while (*s1 != '\0' && s2 - str_version < (str_version_len-1)) {
          if (*s1 != '.') {
               *s2 = *s1;
               s2++;
          }
          s1++;
     }
     *s2 = '\0';
     /*done with str_version*/

     *level = cl_retflevel();
     /*done*/
     return 1;
}

/**********************************/
/*    Clamd support                            */
#ifdef HAVE_FD_PASSING

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
    close(fd_to_send);

    if (ret<0)
        return 0;

    return 1;
}

int clamd_init()
{
    /* try connect to see if clamd running*/
    char buf[1024];
    int ret;
    int sockfd = clamd_connect();
    if (!sockfd) {
        ci_debug_printf(1, "clamd_init: Error while connecting to server\n");
        return 0;
    }

    if (clamd_command(sockfd, "zPING", 6) <= 0) {
        ci_debug_printf(1, "clamd_init: Error while sending command to clamd server\n");
        close(sockfd);
        return 0;
    }
    ret = clamd_response(sockfd, buf, 1024);

    if (ret <= 0 || strcmp(buf, "PONG") != 0) {
        ci_debug_printf(1, "clamd_init: Not valid response from server: %s\n", buf);
        close(sockfd);
        return 0;
    }

    close(sockfd);
    return 1;
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
        close(sockfd);
        return 0;
    }
    ret = clamd_response(sockfd, buf, 1024);
    if (ret <= 0) { //error
        ci_debug_printf(1, "clamd_get_versions: Error reading response from clamd server\n");
        close(sockfd);
        return 0;
    }

    ret = sscanf(buf, "ClamAV %d.%d.%d/%d/", &v1, &v2, &v3, version);
    if (ret != 4) {
        ci_debug_printf(1, "clamd_get_versions: parse error. Response string: %s\n", buf);
        close(sockfd);
        return 0;
    }
    snprintf(str_version, str_version_len, "%d%d%d", v1,v2,v3);
    str_version[str_version_len - 1] = '\0';
    *level = 0; /*We are not able to retrieve level*/

    close(sockfd);
    return 1;
}

int clamd_scan(int fd, char **virus)
{
    char resp[1024], *s, *f, *v;
    int sockfd, ret;

    *virus = NULL;

    sockfd = clamd_connect();
    if (sockfd < 0)
        return 0;

    ret = send_fd(sockfd, fd);
    ret = clamd_response(sockfd, resp, sizeof(resp));

    s = strchr(resp, ':');
    if (!s) {
        ci_debug_printf(1, "clamd_scan: parse error. Response string: %s", resp);
        close(sockfd);
        return 0;
    }
    s++; /*point after ':'*/
    while (*s == ' ')  s++;

    if ((f = strstr(s, "FOUND"))) {
        /* A virus found */
       #define VIRUS_NAME_SIZE 128
        *virus =  ci_buffer_alloc(VIRUS_NAME_SIZE);
        if (! *virus) {
            ci_debug_printf(1, "clamd_scan: Error allocating buffer to write virus name %s!\n", s);
            close(sockfd);
            return 0;
        }
        for ( v = *virus; s != f && (v - *virus)< VIRUS_NAME_SIZE; v++, s++)
            *v = *s;
        /*There is a space before "FOUND" and maybe v points after the end of string*/
        *(v - 1) = '\0';
    }

    close(sockfd);
    return 1;
}

#endif  /*HAVE_FD_PASSING*/

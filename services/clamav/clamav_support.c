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


#include "srv_clamav.h"
#include "ci_threads.h"
#include "mem.h"
#include "debug.h"
#include "../../common.h"
#include <clamav.h>

extern long int CLAMAV_MAXRECLEVEL;
extern long int CLAMAV_MAX_FILES;
extern ci_off_t CLAMAV_MAXFILESIZE;
extern char *CLAMAV_TMP;


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

int clamav_init()
{
    int ret;
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

char *clamav_scan(int fd, unsigned long *scanned_data)
{
    CL_ENGINE *vdb;
    const char *virname;
    char *return_virus_name = NULL;
    int ret;
     vdb = get_virusdb();
#ifndef HAVE_LIBCLAMAV_095
     ret =
         cl_scandesc(fd, &virname, scanned_data, vdb, &limits,
                     CL_SCAN_STDOPT);
#else
     ret =
         cl_scandesc(fd, &virname, scanned_data, vdb,
                     CL_SCAN_STDOPT);
#endif

     if (ret == CL_VIRUS) {
	 return_virus_name = ci_buffer_alloc(strlen(virname)+1);
	 strcpy(return_virus_name, virname);
     }
     else if (ret != CL_CLEAN) {
         ci_debug_printf(1,
                         "srvClamAv module: An error occured while scanning the data\n");
     }
     release_virusdb(vdb);
     return return_virus_name;
}

void clamav_get_versions(unsigned int *level, unsigned int *version, char *str_version, size_t str_version_len)
{
     char *daily_path;
     char *s1, *s2;
     struct cl_cvd *d1;
     struct stat daily_stat;

     /*instead of 128 should be strlen("/daily.inc/daily.info")+1*/
     daily_path = malloc(strlen(cl_retdbdir()) + 128);
     if (!daily_path)           /*???????? */
          return;
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
}

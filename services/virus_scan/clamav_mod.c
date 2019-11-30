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
#include "c_icap/ci_threads.h"
#include "c_icap/commands.h"
#include "c_icap/mem.h"
#include "c_icap/module.h"
#include "c_icap/debug.h"
#include "../../common.h"
#include <clamav.h>

#include <assert.h>

static char *CLAMAV_TMP = NULL;
static long int CLAMAV_MAXRECLEVEL = 5;
static long int CLAMAV_MAX_FILES = 0;
static ci_off_t CLAMAV_MAXFILESIZE = 100 * 1048576; /* maximal archived file size == 100 Mb */
static ci_off_t CLAMAV_MAXSCANSIZE = 200 * 1048576;
static int CLAMAV_DETECT_PUA = 0;
static int CLAMAV_OFFICIAL_DB_ONLY = 0;
static char *CLAMAV_EXCLUDE_PUA = NULL;
static char *CLAMAV_INCLUDE_PUA = NULL;
static int CLAMAV_BLOCKENCRYPTED = 0;
static int CLAMAV_BLOCKBROKEN = 0;
static int CLAMAV_HEURISTIC_PRECEDENCE = 0;
static int CLAMAV_BLOCKMACROS = 0;
static int CLAMAV_PHISHING_BLOCKSSL = 0;
static int CLAMAV_PHISHING_BLOCKCLOAK = 0;

int cfg_virus_scan_TmpDir(const char *directive, const char **argv, void *setdata);
int cfg_set_pua_list(const char *directive, const char **argv, void *setdata);
static struct ci_conf_entry clamav_conf_variables[] = {
     {"ClamAvMaxRecLevel", &CLAMAV_MAXRECLEVEL, ci_cfg_size_long, NULL},
     {"MaxRecLevel", &CLAMAV_MAXRECLEVEL, ci_cfg_size_long, NULL},
     {"ClamAvMaxFilesInArchive", &CLAMAV_MAX_FILES, ci_cfg_size_long, NULL},
     {"MaxFilesInArchive", &CLAMAV_MAX_FILES, ci_cfg_size_long, NULL},
/*     {"ClamAvBzipMemLimit",NULL,setBoolean,NULL},*/
     {"ClamAvMaxFileSizeInArchive", &CLAMAV_MAXFILESIZE, ci_cfg_size_off,
      NULL},
     {"MaxFileSizeInArchive", &CLAMAV_MAXFILESIZE, ci_cfg_size_off,
      NULL},
     {"ClamAvMaxScanSize", &CLAMAV_MAXSCANSIZE, ci_cfg_size_off, NULL},
     {"MaxScanSize", &CLAMAV_MAXSCANSIZE, ci_cfg_size_off, NULL},
     {"ClamAvTmpDir", NULL, cfg_virus_scan_TmpDir, NULL},
     {"TmpDir", NULL, cfg_virus_scan_TmpDir, NULL},
     {"DetectPUA", &CLAMAV_DETECT_PUA, ci_cfg_onoff, NULL},
     {"ExcludePUA", &CLAMAV_EXCLUDE_PUA, cfg_set_pua_list, NULL},
     {"IncludePUA", &CLAMAV_INCLUDE_PUA, cfg_set_pua_list, NULL},
     {"OfficialDatabaseOnly", &CLAMAV_OFFICIAL_DB_ONLY, ci_cfg_onoff, NULL},
     {"ArchiveBlockEncrypted", &CLAMAV_BLOCKENCRYPTED, ci_cfg_onoff, NULL},
     {"DetectBrokenExecutables", &CLAMAV_BLOCKBROKEN, ci_cfg_onoff, NULL},
     {"HeuristicScanPrecedence", &CLAMAV_HEURISTIC_PRECEDENCE, ci_cfg_onoff, NULL},
     {"OLE2BlockMacros", &CLAMAV_BLOCKMACROS, ci_cfg_onoff, NULL},
     {"PhishingAlwaysBlockSSLMismatch", &CLAMAV_PHISHING_BLOCKSSL, ci_cfg_onoff, NULL},
     {"PhishingAlwaysBlockCloak", &CLAMAV_PHISHING_BLOCKCLOAK, ci_cfg_onoff, NULL},
     {NULL, NULL, NULL, NULL}
};

int clamav_init(struct ci_server_conf *server_conf);
int clamav_post_init(struct ci_server_conf *server_conf);
void clamav_release();

CI_DECLARE_MOD_DATA common_module_t module = {
    "clamav_mod",
    clamav_init,
    clamav_post_init,
    clamav_release,
    clamav_conf_variables,
};

int clamav_scan_simple_file(ci_simple_file_t *body,  av_virus_info_t *vinfo);
const char *clamav_version();
const char *clamav_signature();

av_engine_t  clamav_engine = {
    "clamav",
    0x0,
    NULL,
    clamav_scan_simple_file,
    clamav_signature,
    clamav_version
};

extern long int CLAMAV_MAXRECLEVEL;
extern long int CLAMAV_MAX_FILES;
extern ci_off_t CLAMAV_MAXFILESIZE;
extern ci_off_t CLAMAV_MAXSCANSIZE;
extern char *CLAMAV_TMP;

#define CLAMAVLIB_VERSION_SIZE 64
static char CLAMAVLIB_VERSION[CLAMAVLIB_VERSION_SIZE];
#define CLAMAV_SIGNATURE_SIZE SERVICE_ISTAG_SIZE + 1
static char CLAMAV_SIGNATURE[CLAMAV_SIGNATURE_SIZE];

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

#ifdef HAVE_CL_SCAN_OPTIONS
struct cl_scan_options CLAMSCAN_OPTIONS;
#else
unsigned int CLAMSCAN_OPTIONS = CL_SCAN_STDOPT;
#endif

struct virus_db *virusdb = NULL;
struct virus_db *old_virusdb = NULL;
ci_thread_mutex_t db_mutex;

void clamav_set_versions();
int clamav_init_virusdb();
int clamav_reload_virusdb();
void clamav_destroy_virusdb();

void clamav_dbreload_command(const char *name, int type, const char **argv);
int clamav_init(struct ci_server_conf *server_conf)
{
    register_command("clamav:dbreload", MONITOR_PROC_CMD | CHILDS_PROC_CMD,
                     clamav_dbreload_command);
    return CI_OK;
}

int clamav_post_init(struct ci_server_conf *server_conf)
{
    int ret;

    if (CLAMAV_EXCLUDE_PUA && CLAMAV_INCLUDE_PUA) {
        ci_debug_printf(1, "Error: you can define only one of the ExcludePUA and IncludePUA options");
        return CI_ERROR;
    }

    /*Else proceed loading the clamav virus database*/
    ret = clamav_init_virusdb();
     if (!ret)
         return CI_ERROR;

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
	 return CI_ERROR;

     ret = cl_engine_set_num(virusdb->db, CL_ENGINE_MAX_FILES, CLAMAV_MAX_FILES);
     if(ret != CL_SUCCESS)
	 ci_debug_printf(1, "srvclamav_post_init_service: WARNING! cannot set CL_ENGINE_MAX_FILES\n");
     ret = cl_engine_set_num(virusdb->db, CL_ENGINE_MAX_FILESIZE, CLAMAV_MAXFILESIZE);
     if(ret != CL_SUCCESS)
	 ci_debug_printf(1, "srvclamav_post_init_service: WARNING! cannot set CL_ENGINE_MAXFILESIZE\n");
     ret = cl_engine_set_num(virusdb->db, CL_ENGINE_MAX_SCANSIZE, CLAMAV_MAXSCANSIZE);
     if(ret != CL_SUCCESS)
	 ci_debug_printf(1, "srvclamav_post_init_service: WARNING! cannot set CL_ENGINE_MAXSCANSIZE\n");
     ret = cl_engine_set_num(virusdb->db, CL_ENGINE_MAX_RECURSION, CLAMAV_MAXRECLEVEL);
     if(ret != CL_SUCCESS)
	 ci_debug_printf(1, "srvclamav_post_init_service: WARNING! cannot set CL_ENGINE_MAX_RECURSION\n");
#endif

     /*Build scan options*/
#ifdef HAVE_CL_SCAN_OPTIONS
     memset(&CLAMSCAN_OPTIONS, 1, sizeof(CLAMSCAN_OPTIONS));
     CLAMSCAN_OPTIONS.parse = ~0;

#if defined(CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE)
     if (CLAMAV_BLOCKENCRYPTED) {
         CLAMSCAN_OPTIONS.general |= CL_SCAN_GENERAL_HEURISTICS;
         CLAMSCAN_OPTIONS.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE;
         CLAMSCAN_OPTIONS.heuristic |= CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
     }
#endif

#if defined(CL_SCAN_HEURISTIC_BROKEN)
     if (CLAMAV_BLOCKBROKEN) {
         CLAMSCAN_OPTIONS.general |= CL_SCAN_GENERAL_HEURISTICS;
         CLAMSCAN_OPTIONS.heuristic |= CL_SCAN_HEURISTIC_BROKEN;
     }
#endif

#if defined(CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE)
     if (CLAMAV_HEURISTIC_PRECEDENCE) {
         CLAMSCAN_OPTIONS.general |= CL_SCAN_GENERAL_HEURISTICS;
         CLAMSCAN_OPTIONS.heuristic |= CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE;
     }
#endif

#if defined(CL_SCAN_HEURISTIC_MACROS)
     if (CLAMAV_BLOCKMACROS) {
         CLAMSCAN_OPTIONS.general |= CL_SCAN_GENERAL_HEURISTICS;
         CLAMSCAN_OPTIONS.heuristic |= CL_SCAN_HEURISTIC_MACROS;
     }
#endif

#if defined(CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH)
     if (CLAMAV_PHISHING_BLOCKSSL) {
         CLAMSCAN_OPTIONS.general |= CL_SCAN_GENERAL_HEURISTICS;
         CLAMSCAN_OPTIONS.heuristic |= CL_SCAN_HEURISTIC_PHISHING_SSL_MISMATCH;
     }
#endif

#if defined(CL_SCAN_HEURISTIC_PHISHING_CLOAK)
     if (CLAMAV_PHISHING_BLOCKCLOAK) {
         CLAMSCAN_OPTIONS.general |= CL_SCAN_GENERAL_HEURISTICS;
         CLAMSCAN_OPTIONS.heuristic |= CL_SCAN_HEURISTIC_PHISHING_CLOAK;
     }
#endif

#else /*!HAVE_CL_SCAN_OPTIONS*/

#if defined(CL_SCAN_BLOCKENCRYPTED)
     if (CLAMAV_BLOCKENCRYPTED)
         CLAMSCAN_OPTIONS |= CL_SCAN_BLOCKENCRYPTED;
#endif
#if defined(CL_SCAN_BLOCKBROKEN)
     if (CLAMAV_BLOCKBROKEN)
         CLAMSCAN_OPTIONS |= CL_SCAN_BLOCKBROKEN;
#endif
#if defined(CL_SCAN_HEURISTIC_PRECEDENCE)
     if (CLAMAV_HEURISTIC_PRECEDENCE)
         CLAMSCAN_OPTIONS |= CL_SCAN_HEURISTIC_PRECEDENCE;
#endif
#if defined(CL_SCAN_BLOCKMACROS)
     if (CLAMAV_BLOCKMACROS)
         CLAMSCAN_OPTIONS |= CL_SCAN_BLOCKMACROS;
#endif
#if defined(CL_SCAN_PHISHING_BLOCKSSL)
     if (CLAMAV_PHISHING_BLOCKSSL)
         CLAMSCAN_OPTIONS |= CL_SCAN_PHISHING_BLOCKSSL;
#endif
#if defined(CL_SCAN_PHISHING_BLOCKCLOAK)
     if (CLAMAV_PHISHING_BLOCKCLOAK)
         CLAMSCAN_OPTIONS |= CL_SCAN_PHISHING_BLOCKCLOAK;
#endif

#endif /*HAVE_CL_SCAN_OPTIONS*/

     clamav_set_versions();
     av_register_engine(&clamav_engine);
     av_reload_istag();
     return CI_OK;
}

void clamav_release()
{
    clamav_destroy_virusdb();
    if (CLAMAV_TMP)
        free(CLAMAV_TMP);
}

int clamav_init_virusdb()
{
     int ret;
     unsigned int no = 0;
     unsigned int options = CL_DB_STDOPT;
#if defined(CL_DB_PUA_EXCLUDE) || defined(CL_DB_PUA_INCLUDE)
     char *pua_str = NULL;
#endif
     virusdb = malloc(sizeof(struct virus_db));
     memset(virusdb, 0, sizeof(struct virus_db));
     if (!virusdb)
          return 0;

#if defined(CL_DB_PUA)
     if (CLAMAV_DETECT_PUA)
         options |= CL_DB_PUA;
#endif
#if defined(CL_DB_PUA_INCLUDE)
     if (CLAMAV_INCLUDE_PUA) {
         options |= CL_DB_PUA_INCLUDE;
         pua_str = CLAMAV_INCLUDE_PUA;
     }
#endif
#if defined(CL_DB_PUA_EXCLUDE)
     if (CLAMAV_EXCLUDE_PUA) {
         options |= CL_DB_PUA_EXCLUDE;
         pua_str = CLAMAV_EXCLUDE_PUA;
     }
#endif
#if defined(CL_DB_OFFICIAL_ONLY)
     if (CLAMAV_OFFICIAL_DB_ONLY)
         options |= CL_DB_OFFICIAL_ONLY;
#endif

#ifdef HAVE_LIBCLAMAV_095
     if((ret = cl_init(CL_INIT_DEFAULT))) {
        ci_debug_printf(1, "!Can't initialize libclamav: %s\n", cl_strerror(ret));
        return 0;
    }

     if(!(virusdb->db = cl_engine_new())) {
	 ci_debug_printf(1, "Clamav DB load: Cannot create new clamav engine\n");
	 return 0;
     }

#if defined(CL_DB_PUA_EXCLUDE) || defined(CL_DB_PUA_INCLUDE)
     if (pua_str)
         cl_engine_set_str(virusdb->db, CL_ENGINE_PUA_CATEGORIES, pua_str);
#endif

     if ((ret = cl_load(cl_retdbdir(), virusdb->db, &no, options))) {
          ci_debug_printf(1, "Clamav DB load: cl_load failed: %s\n",
                          cl_strerror(ret));
#elif defined(HAVE_LIBCLAMAV_09X)
     if ((ret = cl_load(cl_retdbdir(), &(virusdb->db), &no, options))) {
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

int clamav_scan_simple_file(ci_simple_file_t *body, av_virus_info_t *vinfo)
{
    CL_ENGINE *vdb;
    const char *virname;
    int ret, status;
    unsigned long scanned_data;
    av_virus_t a_virus;
    int fd = body->fd;

    vinfo->virus_name[0] = '\0';
    vinfo->virus_found = 0;
     vdb = get_virusdb();
     lseek(fd, 0, SEEK_SET);
#if defined(HAVE_CL_SCAN_OPTIONS)
     ret =
         cl_scandesc(fd, NULL, &virname, &scanned_data, vdb,
                     &CLAMSCAN_OPTIONS);
#elif !defined(HAVE_LIBCLAMAV_095)
     ret =
         cl_scandesc(fd, &virname, &scanned_data, vdb, &limits,
                     CLAMSCAN_OPTIONS);
#else
     ret =
         cl_scandesc(fd, &virname, &scanned_data, vdb,
                     CLAMSCAN_OPTIONS);
#endif

     status = 1;
     if (ret == CL_VIRUS) {
         strncpy(vinfo->virus_name, virname, AV_NAME_SIZE);
         vinfo->virus_name[AV_NAME_SIZE - 1] = '\0';
         vinfo->virus_found = 1;
         ci_debug_printf(3, "clamav_mod: Virus '%s' detected\n", vinfo->virus_name);
         vinfo->viruses = ci_vector_create(512);
         strcpy(a_virus.virus, vinfo->virus_name); // Both of ize AV_NAME_SIZE
         a_virus.type[0]= '\0';
         a_virus.problemID = 0;
         a_virus.action = AV_NONE;
         ci_vector_add(vinfo->viruses, &a_virus, sizeof(av_virus_t));
     }
     else if (ret != CL_CLEAN) {
         ci_debug_printf(1,
                         "clamav_mod: An error occured while scanning the data\n");
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

void clamav_set_versions()
{
    char str_version[64];
    int cfg_version = 0;
    unsigned int version = 0, level = 0;

    clamav_get_versions(&level, &version, str_version, sizeof(str_version));

    /*Set clamav signature*/
    snprintf(CLAMAV_SIGNATURE, CLAMAV_SIGNATURE_SIZE - 1, "-%.3d-%s-%u%u",
             cfg_version, str_version, level, version);
    CLAMAV_SIGNATURE[CLAMAV_SIGNATURE_SIZE - 1] = '\0';

     /*set the clamav version*/
     snprintf(CLAMAVLIB_VERSION, CLAMAVLIB_VERSION_SIZE - 1, "%s/%d", str_version, version);
     CLAMAVLIB_VERSION[CLAMAVLIB_VERSION_SIZE - 1] = '\0';
}

const char *clamav_version()
{
    return CLAMAVLIB_VERSION;
}

const char *clamav_signature()
{
    return CLAMAV_SIGNATURE;
}

int cfg_virus_scan_TmpDir(const char *directive, const char **argv, void *setdata)
{
     struct stat stat_buf;
     if (argv == NULL || argv[0] == NULL) {
          ci_debug_printf(1, "Missing arguments in directive: %s\n", directive);
          return 0;
     }
     if (stat(argv[0], &stat_buf) != 0 || !S_ISDIR(stat_buf.st_mode)) {
          ci_debug_printf(1,
                          "The directory %s (%s=%s) does not exist or is not a directory !!!\n",
                          argv[0], directive, argv[0]);
          return 0;
     }

     /*TODO:Try to write to the directory to see if it is writable ........

      */
     CLAMAV_TMP = strdup(argv[0]);
     ci_debug_printf(2, "Setting parameter: %s=%s\n", directive, argv[0]);
     return 1;
}

int cfg_set_pua_list(const char *directive, const char **argv, void *setdata)
{
    int i, len, pos;
    char *pua_list = *(char **)setdata;
    if (pua_list)
        pos = strlen(pua_list);
    else
        pos = 0;
    len = pos;

    for (i = 0; argv[i] != NULL; ++i) {
        len += strlen(argv[i]) + 1;
    }

    pua_list = (char *)realloc(pua_list, len + 1);
    for (i = 0; argv[i] != NULL; ++i) {
        snprintf(pua_list + pos, len + 1 - pos, ".%s", argv[i]);
        pos += strlen(argv[i]) + 1;
    }
    pua_list[len] = '\0';
    ci_debug_printf(2, "%s set to %s\n", directive, pua_list);
    *(char **)setdata = pua_list;
    return 1;
}

void clamav_dbreload_command(const char *name, int type, const char **argv)
{
     ci_debug_printf(1, "Clamav virus database reload command received\n");
     if (!clamav_reload_virusdb()) {
          ci_debug_printf(1, "Clamav virus database reload command failed!\n");
     } else
         av_reload_istag();
}

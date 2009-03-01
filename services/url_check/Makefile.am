
pkglib_LTLIBRARIES=srv_url_check.la
INCLUDES = -I$(top_srcdir)

srv_url_check_la_LIBADD = @MODULES_LIBADD@
srv_url_check_la_CFLAGS=  -I../../include/
srv_url_check_la_LDFLAGS=  -module -avoid-version
srv_url_check_la_SOURCES = srv_url_check.c

if USEBDB
 srv_url_check_la_LIBADD += @BDB_ADD_LDFLAG@ -ldb
 srv_url_check_la_CFLAGS += @BDB_ADD_FLAG@
 srv_url_check_la_SOURCES += sguardDB.c
endif


EXTRA_DIST= makefile.w32 srv_url_check.def

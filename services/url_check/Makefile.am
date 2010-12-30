
INCLUDES = -I$(top_srcdir)
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=srv_url_check.la

srv_url_check_la_LIBADD = @MODULES_LIBADD@
srv_url_check_la_CFLAGS=  -I../../include/
srv_url_check_la_LDFLAGS=  -module -avoid-version
srv_url_check_la_SOURCES = srv_url_check.c url_check_body.c

TMPLS = templates/en/DENY

if USEBDB
 srv_url_check_la_LIBADD += @BDB_ADD_LDFLAG@ -ldb
 srv_url_check_la_CFLAGS += @BDB_ADD_FLAG@
 srv_url_check_la_SOURCES += sguardDB.c
endif

install-data-local:
	$(INSTALL) srv_url_check.conf $(DESTDIR)$(CONFIGDIR)/srv_url_check.conf
	$(INSTALL) $(TMPLS) $(DESTDIR)$(cicapdatadir)/templates/srv_url_check/en/


EXTRA_DIST= sguardDB.h url_check_body.h makefile.w32 srv_url_check.def srv_url_check.conf $(TMPLS)


INCLUDES = -I$(top_srcdir)
CONFIGDIR = @CONFDIR@

cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=srv_clamav.la

srv_clamav_la_LIBADD = @MODULES_LIBADD@ @clamavlib@ -lclamav
srv_clamav_la_CFLAGS=  -I../../include/ @clamavinc@
srv_clamav_la_LDFLAGS=  -module -avoid-version
srv_clamav_la_SOURCES = srv_clamav.c srv_clamav_vir.c

install-data-local:
	$(INSTALL) srv_clamav.conf $(DESTDIR)$(CONFIGDIR)/srv_clamav.conf

EXTRA_DIST = srv_clamav.h srv_clamav.conf

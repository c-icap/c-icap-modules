
INCLUDES = -I$(top_srcdir)
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=srv_clamav.la

srv_clamav_la_LIBADD = @MODULES_LIBADD@ @clamavlib@ -lclamav
srv_clamav_la_CFLAGS=  -I../../include/ @clamavinc@
srv_clamav_la_LDFLAGS=  -module -avoid-version
srv_clamav_la_SOURCES = srv_clamav.c srv_clamav_vir.c clamav_support.c

TMPLS = templates/en/VIR_MODE_HEAD templates/en/VIR_MODE_PROGRESS templates/en/VIR_MODE_TAIL templates/en/VIR_MODE_VIRUS_FOUND templates/en/VIRUS_FOUND

install-data-local:
	$(INSTALL) srv_clamav.conf $(DESTDIR)$(CONFIGDIR)/srv_clamav.conf
	$(INSTALL) $(TMPLS) $(DESTDIR)$(cicapdatadir)/templates/srv_clamav/en/

EXTRA_DIST = srv_clamav.h srv_clamav.conf $(TMPLS)

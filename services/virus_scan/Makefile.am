
INCLUDES = -I$(top_srcdir)
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=virus_scan.la

virus_scan_la_LIBADD = @MODULES_LIBADD@ @clamavlib@ -lclamav
virus_scan_la_CFLAGS=  -I../../include/ @clamavinc@
virus_scan_la_LDFLAGS=  -module -avoid-version
virus_scan_la_SOURCES = virus_scan.c virus_scan_vir.c clamav_support.c profiles.c

TMPLS = templates/en/VIR_MODE_HEAD templates/en/VIR_MODE_PROGRESS templates/en/VIR_MODE_TAIL templates/en/VIR_MODE_VIRUS_FOUND templates/en/VIRUS_FOUND

install-data-local:
	$(INSTALL) virus_scan.conf $(DESTDIR)$(CONFIGDIR)/virus_scan.conf.default
	if test ! -f $(DESTDIR)$(CONFIGDIR)/virus_scan.conf; then $(INSTALL) virus_scan.conf $(DESTDIR)$(CONFIGDIR)/virus_scan.conf; fi
	$(mkinstalldirs) $(DESTDIR)$(cicapdatadir)/templates/virus_scan/en/
	for f in $(TMPLS); do $(INSTALL) $$f $(DESTDIR)$(cicapdatadir)/templates/virus_scan/en/; done

EXTRA_DIST = virus_scan.h virus_scan.conf $(TMPLS)
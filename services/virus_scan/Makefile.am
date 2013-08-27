
INCLUDES = -I$(top_srcdir)
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=virus_scan.la clamd_mod.la

CONFS = virus_scan.conf clamd_mod.conf

virus_scan_la_LIBADD = @MODULES_LIBADD@ @ZLIB_ADD_LDADD@
virus_scan_la_LDFLAGS =  -module -avoid-version
virus_scan_la_CFLAGS = -I../../include/ @ZLIB_ADD_FLAG@
virus_scan_la_SOURCES = virus_scan.c virus_scan_vir.c av_body.c decode.c

clamd_mod_la_LIBADD = @MODULES_LIBADD@ 
clamd_mod_la_LDFLAGS =  -module -avoid-version
clamd_mod_la_CFLAGS = -I../../include/
clamd_mod_la_SOURCES = clamd_mod.c

if USECLAMAV
cicapmodule_LTLIBRARIES += clamav_mod.la
clamav_mod_la_LIBADD = @MODULES_LIBADD@ @clamavlib@ -lclamav
clamav_mod_la_LDFLAGS = -module -avoid-version
clamav_mod_la_CFLAGS = -I../../include/ @clamavinc@
clamav_mod_la_SOURCES = clamav_mod.c
CONFS += clamav_mod.conf
endif

if USE_VSCAN_PROFILES
  virus_scan_la_SOURCES += profiles.c
endif

TMPLS = templates/en/VIR_MODE_HEAD templates/en/VIR_MODE_PROGRESS templates/en/VIR_MODE_TAIL templates/en/VIR_MODE_VIRUS_FOUND templates/en/VIRUS_FOUND

install-data-local:
	for f in $(CONFS); do \
		$(INSTALL) $$f $(DESTDIR)$(CONFIGDIR)/$$f.default; \
		if test ! -f $(DESTDIR)$(CONFIGDIR)/$$f; then $(INSTALL) $$f $(DESTDIR)$(CONFIGDIR)/$$f; fi \
	done
	$(mkinstalldirs) $(DESTDIR)$(cicapdatadir)/templates/virus_scan/en/
	for f in $(TMPLS); do $(INSTALL) $$f $(DESTDIR)$(cicapdatadir)/templates/virus_scan/en/; done

EXTRA_DIST = virus_scan.h av_body.h virus_scan.conf clamd_mod.conf clamav_mod.conf $(TMPLS)

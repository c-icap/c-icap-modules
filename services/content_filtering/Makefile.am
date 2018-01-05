AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@

CFHEADERS = srv_body.h filters.h

TMPLS = templates/en/BLOCK

cicapmodule_LTLIBRARIES=srv_content_filtering.la

srv_content_filtering_la_LIBADD = @MODULES_LIBADD@
srv_content_filtering_la_CFLAGS=
srv_content_filtering_la_LDFLAGS=  -module -avoid-version
srv_content_filtering_la_SOURCES = srv_content_filtering.c srv_body.c filters.c profiles.c

install-data-local:
	$(INSTALL) -m 0644 $(srcdir)/srv_content_filtering.conf.default $(DESTDIR)$(CONFIGDIR)/srv_content_filtering.conf.default
	if test ! -f $(DESTDIR)$(CONFIGDIR)/srv_content_filtering.conf.default; then $(INSTALL) -m 0644 $(srcdir)/srv_content_filtering.conf.default $(DESTDIR)$(CONFIGDIR)/srv_content_filtering.conf; fi
	$(mkinstalldirs) $(DESTDIR)$(cicapdatadir)/templates/srv_content_filtering/en
	for f in $(TMPLS); do $(INSTALL) -m 0644 $(srcdir)/$$f $(DESTDIR)$(cicapdatadir)/templates/srv_content_filtering/en/; done


EXTRA_DIST = $(CFHEADERS) srv_content_filtering.conf.default $(TMPLS)

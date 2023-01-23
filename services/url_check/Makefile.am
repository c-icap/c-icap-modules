
AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@
cicapmodule_LTLIBRARIES=srv_url_check.la

do_subst=sed -e 's%[@]SYSCONFDIR[@]%$(CONFIGDIR)%g' \
             -e 's%[@]PACKAGE_STRING[@]%$(PACKAGE_STRING)%g'

srv_url_check_la_LIBADD = @MODULES_LIBADD@
srv_url_check_la_CFLAGS= 
srv_url_check_la_LDFLAGS=  -module -avoid-version @MODS_LDFLAGS@
srv_url_check_la_SOURCES = srv_url_check.c url_check_body.c request_filter.c sguardDB.c

manpages = c-icap-mods-sguardDB.8
manpages_src = $(manpages:.8=.8.in)

CLEANFILES = $(manpages)

SUFFIXES = .8.in .8

.8.in.8:
	$(do_subst) < $< > $@

man_MANS = $(manpages)

TMPLS = templates/en/DENY

bin_PROGRAMS = c-icap-mods-sguardDB
c_icap_mods_sguardDB_SOURCES =  sguardDB.c
c_icap_mods_sguardDB_LDADD = @UTILITIES_LIBADD@
c_icap_mods_sguardDB_CFLAGS = -DBUILD_SGUARD_TOOL


if USEBDB
 srv_url_check_la_LIBADD += @BDB_ADD_LDADD@
 srv_url_check_la_CFLAGS += @BDB_ADD_FLAG@
 srv_url_check_la_SOURCES += sguard_bdb.c

 c_icap_mods_sguardDB_SOURCES +=  sguard_bdb.c
 c_icap_mods_sguardDB_LDADD += @BDB_ADD_LDADD@
 c_icap_mods_sguardDB_CFLAGS += @BDB_ADD_FLAG@
endif

if USELMDB
  srv_url_check_la_LIBADD += @LMDB_ADD_LDADD@
  srv_url_check_la_CFLAGS += @LMDB_ADD_FLAG@
  srv_url_check_la_SOURCES += sguard_lmdb.c

  c_icap_mods_sguardDB_SOURCES +=  sguard_lmdb.c
  c_icap_mods_sguardDB_LDADD += @LMDB_ADD_LDADD@
  c_icap_mods_sguardDB_CFLAGS += @LMDB_ADD_FLAG@
endif

install-data-local:
	$(mkinstalldirs) $(DESTDIR)$(CONFIGDIR)
	$(INSTALL) $(srcdir)/srv_url_check.conf $(DESTDIR)$(CONFIGDIR)/srv_url_check.conf.default
	if test ! -f $(DESTDIR)$(CONFIGDIR)/srv_url_check.conf; then $(INSTALL) srv_url_check.conf $(DESTDIR)$(CONFIGDIR)/srv_url_check.conf; fi
	$(mkinstalldirs) $(DESTDIR)$(cicapdatadir)/templates/srv_url_check/en
	for f in $(TMPLS); do  $(INSTALL) $(srcdir)/$$f $(DESTDIR)$(cicapdatadir)/templates/srv_url_check/en/; done


EXTRA_DIST= sguardDB.h url_check_body.h request_filter.h makefile.w32 srv_url_check.def srv_url_check.conf $(TMPLS) $(manpages_src)

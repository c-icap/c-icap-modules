AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/include
CONFIGDIR = @CONFDIR@
cicapdatadir=@DATADIR@
cicapmoduledir=@MODSDIR@

bin_PROGRAMS =
pkglib_LTLIBRARIES=

if USETOKYOCABINET
pkglib_LTLIBRARIES += tc_tables.la
bin_PROGRAMS += c-icap-mktcdb
endif

if USETOKYOCABINET
tc_tables_la_LIBADD = @MODULES_LIBADD@
tc_tables_la_CFLAGS = @TOKYOCABINET_ADD_FLAG@
tc_tables_la_LDFLAGS= -module -avoid-version @MODS_LDFLAGS@ @TOKYOCABINET_ADD_LDADD@
tc_tables_la_SOURCES = tc_tables.c

c_icap_mktcdb_SOURCES = c-icap-mktcdb.c
c_icap_mktcdb_CFLAGS = @TOKYOCABINET_ADD_FLAG@
c_icap_mktcdb_LDADD = @UTILITIES_LIBADD@ @TOKYOCABINET_ADD_LDADD@
endif

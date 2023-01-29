
do_subst=sed -e 's%[@]PACKAGE_STRING[@]%$(PACKAGE_STRING)%g'


manpages = c-icap-mktcb.8
manpages_src = $(manpages:.8=.8.in)

CLEANFILES = $(manpages)

SUFFIXES =  .8.in .8

.8.in.8:
	$(do_subst) < $< > $@

man_MANS = $(manpages)

EXTRA_DIST = $(manpages_src)

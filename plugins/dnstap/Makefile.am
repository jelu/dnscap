MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

AM_CFLAGS = -I$(srcdir) \
    -I$(top_srcdir)/src \
    -I$(top_srcdir)/isc \
    $(SECCOMPFLAGS)

pkglib_LTLIBRARIES = dnstap.la
dnstap_la_SOURCES = dnstap.c dnstap.pb-c.c
dnstap_la_LDFLAGS = -module -avoid-version

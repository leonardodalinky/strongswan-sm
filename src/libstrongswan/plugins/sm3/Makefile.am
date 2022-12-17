AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

AM_LDFLAGS = -lgmssl

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-sm3.la
else
plugin_LTLIBRARIES = libstrongswan-sm3.la
endif

libstrongswan_sm3_la_SOURCES = \
	sm3_plugin.h sm3_plugin.c sm3_hasher.c sm3_hasher.h

libstrongswan_sm3_la_LDFLAGS = -module -avoid-version

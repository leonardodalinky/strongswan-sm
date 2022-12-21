AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

AM_LDFLAGS = -lgmssl

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-sm2.la
else
plugin_LTLIBRARIES = libstrongswan-sm2.la
endif

libstrongswan_sm2_la_SOURCES = \
	sm2_plugin.h sm2_plugin.c sm2_private_key.c sm2_private_key.h sm2_public_key.c sm2_public_key.h sm2_dh.c sm2_dh.h

libstrongswan_sm2_la_LDFLAGS = -module -avoid-version

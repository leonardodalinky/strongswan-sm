AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

AM_LDFLAGS = -lgmssl

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-sm4.la
else
plugin_LTLIBRARIES = libstrongswan-sm4.la
endif

libstrongswan_des_la_SOURCES = \
	sm4_plugin.h sm4_plugin.c sm4_crypter.c sm4_crypter.h

libstrongswan_des_la_LDFLAGS = -module -avoid-version
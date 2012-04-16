AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing -I$(top_builddir)/libmissing @LIBREQUIEM_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

debug_la_SOURCES = debug.c
debug_la_LDFLAGS = -module -avoid-version
debugdir = $(libdir)/requiem-logeater
debug_LTLIBRARIES = debug.la

-include $(top_srcdir)/git.mk

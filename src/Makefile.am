SUBDIRS = include

AM_CPPFLAGS = -I$(srcdir)/include/ -I$(top_srcdir)/libmissing -I$(top_builddir)/libmissing -I$(top_srcdir)/libev @LIBREQUIEM_CFLAGS@ @PCRE_CFLAGS@ @ICU_CPPFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

bin_PROGRAMS = requiem-logeater
requiem_logeater_LDADD = @LIBREQUIEM_LIBS@ @PCRE_LIBS@ @ICU_LIBS@ $(top_builddir)/libev/libev.la $(top_builddir)/libmissing/libmissing.la $(GETADDRINFO_LIB) $(HOSTENT_LIB) $(INET_NTOP_LIB) $(LIBSOCKET) $(LTLIBICONV) $(LTLIBINTL) $(SERVENT_LIB)
requiem_logeater_LDFLAGS = @LIBREQUIEM_LDFLAGS@ -export-dynamic \
        "-dlopen" $(top_builddir)/plugins/debug/debug.la \
        "-dlopen" $(top_builddir)/plugins/pcre/pcre.la

requiem_logeater_SOURCES = 	\
        requiem-logeater.c 	\
        udp-server.c 	\
        regex.c 	\
        log-entry.c 	\
	log-source.c	\
        log-plugins.c 	\
        logeater-options.c 	\
        file-server.c 	\
        logeater-alert.c	\
	logeater-charset.c


-include $(top_srcdir)/git.mk

DISTCHECK_CONFIGURE_FLAGS = --enable-unsupported-rulesets

ACLOCAL_AMFLAGS = -I m4 -I libmissing/m4
SUBDIRS = libev libmissing m4 plugins src tests

requiemconfdir = $(configdir)
EXTRA_DIST = plugins.rules requiem-logeater.conf config.h \
             AUTHORS COPYING HACKING.README INSTALL NEWS README 

MAINTAINERCLEANFILES = \
        $(srcdir)/INSTALL \
        $(srcdir)/aclocal.m4 \
        $(srcdir)/autoscan.log \
        $(srcdir)/compile \
        $(srcdir)/config.guess \
        $(srcdir)/config.h.in \
        $(srcdir)/config.sub \
        $(srcdir)/configure.scan \
        $(srcdir)/depcomp \
        $(srcdir)/install-sh \
        $(srcdir)/ltmain.sh \
        $(srcdir)/missing \
        $(srcdir)/mkinstalldirs \
        $(srcdir)/omf.make \
        $(srcdir)/xmldocs.make \
        $(srcdir)/gtk-doc.make \
        $(srcdir)/ChangeLog \
        `find "$(srcdir)" -type f -name Makefile.in -print`

install-data-local:
	$(INSTALL) -m 700 -d $(DESTDIR)$(metadata_dir)
	@if test -f $(DESTDIR)$(configdir)/requiem-logeater.conf; then         					\
		echo "********************************************************************************"; 	\
                echo;                                                                                    	\
                echo "$(DESTDIR)$(configdir)/requiem-logeater.conf already exist...";				\
                echo "Installing default configuration in $(DESTDIR)$(configdir)/requiem-logeater.conf-dist";        \
                echo;                                                                                    	\
                echo "********************************************************************************"; 	\
		$(INSTALL) -m 600 $(top_srcdir)/requiem-logeater.conf $(DESTDIR)$(configdir)/requiem-logeater.conf-dist;  \
        else                                                                                             	\
                $(INSTALL) -m 600 $(top_srcdir)/requiem-logeater.conf $(DESTDIR)$(configdir)/;                       \
        fi
	@if test -f $(DESTDIR)$(configdir)/plugins.rules; then         					\
		echo "********************************************************************************"; 	\
                echo;                                                                                    	\
                echo "$(DESTDIR)$(configdir)/plugins.rules already exist...";					\
                echo "Installing default configuration in $(DESTDIR)$(configdir)/plugins.rules-dist";	        \
                echo;                                                                                    	\
                echo "********************************************************************************"; 	\
		$(INSTALL) -m 600 $(top_srcdir)/plugins.rules $(DESTDIR)$(configdir)/plugins.rules-dist;	\
        else                                                                                             	\
		$(INSTALL) -m 600 $(top_srcdir)/plugins.rules $(DESTDIR)$(configdir)/;				\
        fi


uninstall-local:
	rm -f $(DESTDIR)$(configdir)/requiem-logeater.conf;	\
	rm -f $(DESTDIR)$(configdir)/plugin.rules;

dist-hook:
	@if test -d "$(srcdir)/.git"; then      \
		echo Creating ChangeLog && \
		( cd "$(top_srcdir)" && \
		  echo '# Generated by Makefile. Do not edit.'; echo; \
		  $(top_srcdir)/missing --run git log --stat ) > ChangeLog.tmp \
		&& mv -f ChangeLog.tmp $(top_distdir)/ChangeLog \
		|| ( rm -f ChangeLog.tmp ; \
		echo Failed to generate ChangeLog >&2 ); \
	else \
		echo A git clone is required to generate a ChangeLog >&2; \
	fi

-include $(top_srcdir)/git.mk

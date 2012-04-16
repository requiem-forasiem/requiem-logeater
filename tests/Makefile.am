EXTRA_DIST = loggrep.py requiem-logeater.conf ignored

$(top_srcdir)/requiem-logeater:
	cd $(top_srcdir)/requiem-logeater && make

check-am:
	$(srcdir)/loggrep.py $(top_srcdir)/plugins/pcre/ruleset/*.rules | $(top_srcdir)/src/requiem-logeater --quiet --dry-run --metadata=nowrite,head --batch-mode --no-resolve --pcre --dump-unmatched --config $(srcdir)/requiem-logeater.conf 2>&1 | $(GREP) -Fvf $(srcdir)/ignored

-include $(top_srcdir)/git.mk

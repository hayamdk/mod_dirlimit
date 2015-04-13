mod_dirlimit.la: mod_dirlimit.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_dirlimit.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_dirlimit.la

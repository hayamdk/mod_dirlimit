##
##  Makefile -- Build procedure for sample dirlimit Apache module
##  Autogenerated via ``apxs -n dirlimit -g''.
##

builddir=.
top_srcdir=/usr/share/apache2
top_builddir=/usr/share/apache2
include /usr/share/apache2/build/special.mk

#   the used tools
APXS=apxs
APACHECTL=apachectl

#   additional defines, includes and libraries
DEFS=-Wall
#INCLUDES=-Imy/include/dir
#LIBS=-Lmy/lib/dir -lmylib

#   the default target
all: local-shared-build

#   install the shared object file into Apache 
install: install-modules-yes

#   cleanup
clean:
	-rm -f mod_dirlimit.o mod_dirlimit.lo mod_dirlimit.slo mod_dirlimit.la 

#   simple test
test: reload
	lynx -mime_header http://localhost/dirlimit

#   install and activate shared object by reloading Apache to
#   force a reload of the shared object file
reload: install restart

#   the general Apache start/restart/stop
#   procedures
start:
	$(APACHECTL) start
restart:
	$(APACHECTL) restart
stop:
	$(APACHECTL) stop


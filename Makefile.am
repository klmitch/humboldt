## Copyright (C) 2017 by Kevin L. Mitchell <klmitch@mit.edu>
##
## Licensed under the Apache License, Version 2.0 (the "License"); you
## may not use this file except in compliance with the License. You
## may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
## implied. See the License for the specific language governing
## permissions and limitations under the License.

AUTOMAKE_OPTIONS = subdir-objects foreign

EXTRA_DIST = autogen.sh docs lib LICENSE README.rst tools
dist-hook:
	rm -rf `find $(distdir)/tools -name build -print -prune`
	rm -rf `find $(distdir)/tools -name .cache -print -prune`
	rm -rf `find $(distdir)/tools -name .coverage -print`
	rm -rf `find $(distdir)/tools -name cov_html -print -prune`
	rm -rf `find $(distdir)/tools -name dist -print -prune`
	rm -rf `find $(distdir)/tools -name .tox -print -prune`
	rm -rf `find $(distdir)/tools -name __pycache__ -print -prune`
	rm -rf `find $(distdir)/tools -name \*.egg-info -print -prune`
	rm -rf `find $(distdir)/tools -name \*.pyc -print`

AM_CPPFLAGS = \
	-DLOCALSTATEDIR='"$(localstatedir)"' \
	-DSYSCONFDIR='"$(sysconfdir)"'

bin_PROGRAMS = humboldt

humboldt_SOURCES = \
	include/alloc.h \
	include/common.h \
	include/configuration.h \
	include/connection.h \
	include/db.h \
	include/endpoint.h \
	include/log.h \
	include/protocol.h \
	include/runtime.h \
	include/yaml_util.h \
	src/alloc.c \
	src/configuration.c \
	src/connection.c \
	src/endpoint.c \
	src/log.c \
	src/main.c \
	src/protocol.c \
	src/runtime.c \
	src/yaml_util.c

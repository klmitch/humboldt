dnl Copyright (C) 2017 by Kevin L. Mitchell <klmitch@mit.edu>
dnl
dnl Licensed under the Apache License, Version 2.0 (the "License"); you
dnl may not use this file except in compliance with the License. You
dnl may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
dnl implied. See the License for the specific language governing
dnl permissions and limitations under the License.

AC_INIT([Humboldt Overlay Network Daemon], 0.0.1, [klmitch@mit.edu],
	[humboldt])
AC_PREREQ(2.69)

AC_COPYRIGHT([Copyright (C) 2017 by Kevin L. Mitchell <klmitch@mit.edu>

Licensed under the Apache License, Version 2.0 (the "License"); you
may not use this file except in compliance with the License. You may
obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing
permissions and limitations under the License.
])

AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_LIBOBJ_DIR([lib])
AM_INIT_AUTOMAKE

dnl Checks for programs
AC_PROG_CC_C99
PKG_PROG_PKG_CONFIG

dnl Checks for libraries
AX_LIB_SOCKET_NSL
HUMBOLDT_PC_LIBRARY([YAML], [yaml-0.1])

dnl Checks for header files

dnl Checks for types

dnl Checks for structures

dnl Checks for compiler characteristics

dnl Checks for library functions
AX_FUNC_GETOPT_LONG
AC_CHECK_FUNCS([vsyslog])

dnl Checks for system services

dnl Set up outputs
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])

AC_OUTPUT

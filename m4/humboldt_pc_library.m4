# -*- Autoconf -*-
#
# Copyright (C) 2017 by Kevin L. Mitchell <klmitch@mit.edu>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you
# may not use this file except in compliance with the License. You may
# obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing
# permissions and limitations under the License.

# HUMBOLDT_PC_LIBRARY(VARIABLE-PREFIX, MODULES)
AC_DEFUN([HUMBOLDT_PC_LIBRARY],
[PKG_CHECK_MODULES([$1], [$2], [], [
  AC_ERROR([$2 not found])
])
CPPFLAGS="${$1[]_CFLAGS} ${CPPFLAGS}"
LIBS="${$1[]_LIBS} ${LIBS}"
])# HUMBOLDT_PC_LIBRARY

#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([nsca_handler], [1.0], [pierre@reactos.org])
AC_CONFIG_SRCDIR([nsca_handler.c])
AC_CONFIG_HEADERS([nsca_handler.h])
AM_INIT_AUTOMAKE



# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([limits.h stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([memset])

AC_DEFINE(_BSD_SOURCE, 1, Enable BSD functions)
AC_DEFINE(_POSIX_C_SOURCE, 1, Enable POSIX functions)

AC_CONFIG_FILES([makefile])
AC_OUTPUT

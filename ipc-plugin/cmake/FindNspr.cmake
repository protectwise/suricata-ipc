# - Try to find Nspr
# Once done this will define
#  LIBNSPR_FOUND - System has LibNspr
#  LIBNSPR_INCLUDE_DIRS - The LibNspr include directories
#  LIBNSPR_LIBRARIES - The libraries needed to use LibNspr
#  LIBNSPR_DEFINITIONS - Compiler switches required for using LibNspr

find_package(PkgConfig)
pkg_check_modules(PC_LIBNSPR QUIET jansson)
set(LIBNSPR_DEFINITIONS ${PC_LIBNSPR_CFLAGS_OTHER})

find_path(LIBNSPR_INCLUDE_DIR nspr.h
        HINTS ${PC_LIBNSPR_INCLUDEDIR} ${PC_LIBNSPR_INCLUDE_DIRS}
        PATH_SUFFIXES nspr )

find_library(LIBNSPR_LIBRARY NAMES nss3
        HINTS ${PC_LIBNSPR_LIBDIR} ${PC_LIBNSPR_LIBRARY_DIRS} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBNSPR_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Nspr  DEFAULT_MSG
        LIBNSPR_LIBRARY LIBNSPR_INCLUDE_DIR)

mark_as_advanced(LIBNSPR_INCLUDE_DIR LIBNSPR_LIBRARY )

set(LIBNSPR_LIBRARIES ${LIBNSPR_LIBRARY} )
set(LIBNSPR_INCLUDE_DIRS ${LIBNSPR_INCLUDE_DIR} )

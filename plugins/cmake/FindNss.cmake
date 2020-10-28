# - Try to find Nss
# Once done this will define
#  LIBNSS_FOUND - System has LibNss
#  LIBNSS_INCLUDE_DIRS - The LibNss include directories
#  LIBNSS_LIBRARIES - The libraries needed to use LibNss
#  LIBNSS_DEFINITIONS - Compiler switches required for using LibNss

find_package(PkgConfig)
pkg_check_modules(PC_LIBNSS QUIET jansson)
set(LIBNSS_DEFINITIONS ${PC_LIBNSS_CFLAGS_OTHER})

find_path(LIBNSS_INCLUDE_DIR nss.h
        HINTS ${PC_LIBNSS_INCLUDEDIR} ${PC_LIBNSS_INCLUDE_DIRS}
        PATH_SUFFIXES nss )

find_library(LIBNSS_LIBRARY NAMES nss3
        HINTS ${PC_LIBNSS_LIBDIR} ${PC_LIBNSS_LIBRARY_DIRS} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBNSS_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(Nss  DEFAULT_MSG
        LIBNSS_LIBRARY LIBNSS_INCLUDE_DIR)

mark_as_advanced(LIBNSS_INCLUDE_DIR LIBNSS_LIBRARY )

set(LIBNSS_LIBRARIES ${LIBNSS_LIBRARY} )
set(LIBNSS_INCLUDE_DIRS ${LIBNSS_INCLUDE_DIR} )
